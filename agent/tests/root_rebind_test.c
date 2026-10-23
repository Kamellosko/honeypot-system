#define _GNU_SOURCE
#include "monitor.h"
#include "snapshot.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
  char parent[] = "/tmp/hp-rebind-XXXXXX", state[256], share[256], gone[256], file[512];
  assert(mkdtemp(parent));
  snprintf(state, sizeof(state), "%s/state", parent);
  snprintf(share, sizeof(share), "%s/share", parent);
  snprintf(gone, sizeof(gone), "%s/old-share", parent);
  snprintf(file, sizeof(file), "%s/new.txt", share);
  assert(mkdir(share, 0700) == 0);
  struct hp_store store;
  struct hp_monitor monitor;
  assert(hp_store_init(&store, state, "agent") == 0);
  assert(hp_monitor_init(&monitor, &store) == 0);
  assert(hp_monitor_add_share(&monitor, "share", share) == 0);
  assert(rename(share, gone) == 0);
  assert(mkdir(share, 0700) == 0);
  FILE *out = fopen(file, "w");
  assert(out); fputs("new root\n", out); fclose(out);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  assert(hp_store_pending_count(&store) >= 1);
  struct stat bound, current;
  assert(fstat(monitor.roots[0].fd, &bound) == 0);
  assert(stat(share, &current) == 0);
  assert(bound.st_ino == current.st_ino && bound.st_dev == current.st_dev);
  hp_monitor_close(&monitor);
  hp_store_close(&store);
  return 0;
}
