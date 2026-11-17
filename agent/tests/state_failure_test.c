#define _GNU_SOURCE
#include "snapshot.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fail_commit;
int __real_renameat(int, const char *, int, const char *);
int __wrap_renameat(int olddir, const char *old, int newdir, const char *next) {
  if (fail_commit && old[0] == '.' && strlen(next) == 64) { errno = EIO; return -1; }
  return __real_renameat(olddir, old, newdir, next);
}

int main(void) {
  char dir[] = "/tmp/hp-state-fail-XXXXXX", state[256], path[256];
  assert(mkdtemp(dir));
  snprintf(state, sizeof(state), "%s/state", dir);
  snprintf(path, sizeof(path), "%s/data", dir);
  struct hp_store store;
  assert(!hp_store_init(&store, state, "agent"));
  int root = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  assert(root >= 0);
  FILE *f = fopen(path, "w");
  assert(f && fputs("old\n", f) >= 0 && !fclose(f));
  assert(!hp_snapshot_event(&store, root, dir, "data", "baseline"));
  int listing_fd = openat(store.snapshots_fd, ".", O_RDONLY | O_DIRECTORY);
  DIR *listing = fdopendir(listing_fd);
  assert(listing);
  char metadata[80] = {0}, content[65] = {0};
  struct dirent *entry;
  while ((entry = readdir(listing))) {
    if (strlen(entry->d_name) == 69 && strstr(entry->d_name, ".stat")) strcpy(metadata, entry->d_name);
    if (strlen(entry->d_name) == 64) strcpy(content, entry->d_name);
  }
  assert(!closedir(listing) && *metadata && *content);
  unsigned char before[512], after[512];
  int fd = openat(store.snapshots_fd, metadata, O_RDONLY);
  assert(fd >= 0);
  ssize_t n = read(fd, before, sizeof(before));
  assert(n > 0 && !close(fd));
  f = fopen(path, "w");
  assert(f && fputs("changed\n", f) >= 0 && !fclose(f));
  fail_commit = 1;
  assert(hp_snapshot_event(&store, root, dir, "data", "modify") == -1);
  assert(hp_store_pending_count(&store) == 1);
  fd = openat(store.snapshots_fd, metadata, O_RDONLY);
  assert(fd >= 0 && read(fd, after, sizeof(after)) == n && !memcmp(before, after, (size_t)n));
  assert(!close(fd));
  fd = openat(store.snapshots_fd, content, O_RDONLY);
  assert(fd >= 0 && read(fd, after, sizeof(after)) == 4 && !memcmp(after, "old\n", 4));
  assert(!close(fd));
  fail_commit = 0;
  assert(!hp_snapshot_event(&store, root, dir, "data", "modify"));
  assert(hp_store_pending_count(&store) == 2);
  hp_store_close(&store);
  assert(!close(root));
  return 0;
}
