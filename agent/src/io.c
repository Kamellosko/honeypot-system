#define _GNU_SOURCE
#include "io.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int hp_open_beneath(int root, const char *path, int flags, mode_t mode) {
  struct open_how how = { .flags = (uint64_t)(flags | O_CLOEXEC | O_NOFOLLOW), .mode = mode,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS };
  return (int)syscall(SYS_openat2, root, path, &how, sizeof(how));
}

int hp_open_absolute(const char *path, int flags) {
  if (!path || *path != '/') { errno = EINVAL; return -1; }
  int root = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (root < 0) return -1;
  int fd = hp_open_beneath(root, path[1] ? path + 1 : ".", flags, 0);
  int error = errno;
  close(root); errno = error;
  return fd;
}

int hp_private_file(int root, const char *path, int flags, mode_t mode) {
  int fd = hp_open_beneath(root, path, flags | O_NONBLOCK, mode);
  if (fd < 0) return -1;
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_nlink != 1) { close(fd); errno = EACCES; return -1; }
  return fd;
}

int hp_private_directory(int root, const char *name) {
  if (mkdirat(root, name, 0700) && errno != EEXIST) return -1;
  int fd = hp_open_beneath(root, name, O_RDONLY | O_DIRECTORY, 0);
  if (fd < 0) return -1;
  struct stat st;
  if (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 077)) {
    close(fd); errno = EACCES; return -1;
  }
  return fd;
}

int hp_write_all(int fd, const void *data, size_t size) {
  const unsigned char *p = data;
  while (size) {
    ssize_t n = write(fd, p, size);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { if (!n) errno = EIO; return -1; }
    p += n; size -= (size_t)n;
  }
  return 0;
}

int hp_sync(int fd) {
  int result;
  do { result = fsync(fd); } while (result && errno == EINTR);
  return result;
}

int hp_read_file(const char *path, size_t limit, char **data, size_t *size) {
  *data = NULL; *size = 0;
  int fd = hp_open_absolute(path, O_RDONLY | O_NONBLOCK);
  if (fd < 0) return -1;
  struct stat before, after;
  int result = -1;
  char *buffer = NULL;
  size_t used = 0;
  if (fstat(fd, &before)) goto done;
  if (!S_ISREG(before.st_mode) || before.st_size < 0 || (uintmax_t)before.st_size > limit ||
      (uintmax_t)before.st_size >= SIZE_MAX) { errno = EFBIG; goto done; }
  buffer = calloc((size_t)before.st_size + 1, 1);
  if (!buffer) goto done;
  while (used < (size_t)before.st_size) {
    ssize_t n = read(fd, buffer + used, (size_t)before.st_size - used);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) { if (!n) errno = EIO; goto done; }
    used += (size_t)n;
  }
  if (fstat(fd, &after) || before.st_size != after.st_size ||
      before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
      before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) { errno = EAGAIN; goto done; }
  *data = buffer; *size = used; buffer = NULL; result = 0;
done:
  if (buffer) { explicit_bzero(buffer, used); free(buffer); }
  if (close(fd)) { if (*data) { explicit_bzero(*data, *size); free(*data); *data = NULL; *size = 0; } return -1; }
  return result;
}
