#define _GNU_SOURCE
#include "monitor.h"
#include "snapshot.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int counting, reads;
ssize_t __real_read(int fd, void *buffer, size_t size);
ssize_t __wrap_read(int fd, void *buffer, size_t size) {
  if (counting) reads++;
  return __real_read(fd, buffer, size);
}

int main(void) {
  char dir[] = "/tmp/hp-log-XXXXXX", state[256], log[256], rotated[256];
  assert(mkdtemp(dir));
  snprintf(state, sizeof(state), "%s/state", dir);
  snprintf(log, sizeof(log), "%s/service.log", dir);
  snprintf(rotated, sizeof(rotated), "%s/service.log.1", dir);
  FILE *f = fopen(log, "w");
  assert(f); fputs("historical line\n", f); fclose(f);
  struct hp_store store;
  struct hp_monitor monitor;
  assert(hp_store_init(&store, state, "agent") == 0);
  assert(hp_monitor_init(&monitor, &store) == 0);
  assert(hp_monitor_add_log(&monitor, log) == 0);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  assert(hp_store_pending_count(&store) == 0);
  f = fopen(log, "a"); assert(f); fputs("Failed password for alice\n", f); fclose(f);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  assert(hp_store_pending_count(&store) == 1);
  char pending[512];
  snprintf(pending, sizeof(pending), "%s/pending", state);
  assert(chmod(pending, 0500) == 0);
  f = fopen(log, "a"); assert(f); fputs("retry line\n", f); fclose(f);
  assert(hp_monitor_poll(&monitor, 0) != 0);
  assert(chmod(pending, 0700) == 0);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  assert(hp_store_pending_count(&store) == 2);
  assert(rename(log, rotated) == 0);
  f = fopen(log, "w"); assert(f); fputs("new file line\n", f); fclose(f);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  assert(hp_store_pending_count(&store) >= 4);
  f = fopen(log, "w"); assert(f); fputs("x\n", f); fclose(f);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  assert(hp_store_pending_count(&store) >= 6);
  int before = hp_store_pending_count(&store);
  char *large = malloc(70001);
  assert(large);
  memset(large, 'x', 70000); large[70000] = '\n';
  f = fopen(log, "a");
  assert(f && fwrite(large, 1, 70001, f) == 70001 && !fclose(f));
  explicit_bzero(large, 70001); free(large);
  counting = 1;
  assert(hp_monitor_poll(&monitor, 0) == 0);
  counting = 0;
  assert(reads <= 8 && hp_store_pending_count(&store) == before + 2);
  hp_monitor_close(&monitor);
  hp_store_close(&store);
  return 0;
}
