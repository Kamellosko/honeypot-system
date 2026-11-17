#define _GNU_SOURCE
#include "io.h"
#include "snapshot.h"
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
  char directory[] = "/tmp/hp-safe-io-XXXXXX";
  assert(mkdtemp(directory));
  int root = hp_open_absolute(directory, O_RDONLY | O_DIRECTORY);
  assert(root >= 0);
  int fd = hp_private_file(root, "file", O_CREAT | O_EXCL | O_WRONLY, 0600);
  assert(fd >= 0 && !hp_write_all(fd, "abc", 3) && !hp_sync(fd) && !close(fd));
  assert(!linkat(root, "file", root, "alias", 0));
  assert(hp_private_file(root, "file", O_RDONLY, 0) < 0);
  assert(!unlinkat(root, "alias", 0));
  assert(!fchmodat(root, "file", 0644, 0));
  assert(hp_private_file(root, "file", O_RDONLY, 0) < 0);
  assert(!fchmodat(root, "file", 0600, 0));
  assert(!symlinkat("file", root, "symlink"));
  assert(hp_private_file(root, "symlink", O_RDONLY, 0) < 0);
  assert(!mkfifoat(root, "fifo", 0600));
  alarm(3);
  assert(hp_private_file(root, "fifo", O_RDONLY, 0) < 0);
  alarm(0);
  assert(hp_open_beneath(root, "../", O_RDONLY | O_DIRECTORY, 0) < 0);
  char path[512];
  snprintf(path, sizeof(path), "%s/file", directory);
  char *bytes = NULL;
  size_t size = 0;
  assert(!hp_read_file(path, 3, &bytes, &size) && size == 3 && !memcmp(bytes, "abc", 3));
  explicit_bzero(bytes, size); free(bytes);
  assert(hp_read_file(path, 2, &bytes, &size) < 0 && !bytes && !size);
  assert(!unlinkat(root, "file", 0) && !unlinkat(root, "symlink", 0) && !unlinkat(root, "fifo", 0));
  assert(!close(root) && !rmdir(directory));
  return 0;
}
