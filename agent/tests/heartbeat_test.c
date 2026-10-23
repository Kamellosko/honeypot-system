#define _GNU_SOURCE
#include "config.h"
#include "heartbeat.h"
#include "snapshot.h"
#include "cJSON.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t random_value;
static int random_error, random_short, random_interrupted;

ssize_t __wrap_getrandom(void *buffer, size_t size, unsigned flags) {
  assert(size == sizeof(random_value) && flags == 0);
  if (random_interrupted) { random_interrupted = 0; errno = EINTR; return -1; }
  if (random_error) { errno = EIO; return -1; }
  memcpy(buffer, &random_value, size);
  return random_short ? 1 : (ssize_t)size;
}

int main(void) {
  char path[] = "/tmp/hp-heartbeat-XXXXXX";
  struct hp_store store;
  assert(mkdtemp(path));
  assert(!hp_store_init(&store, path, "test-agent"));
  double deadline = 0;
  assert(!hp_heartbeat_tick(&store, 100, &deadline));
  assert(deadline == 100 + HEARTBEAT_INTERVAL * .85);
  assert(hp_store_pending_count(&store) == 0);
  assert(!hp_heartbeat_tick(&store, deadline - .01, &deadline));
  assert(hp_store_pending_count(&store) == 0);
  double now = deadline;
  random_error = 1;
  assert(hp_heartbeat_tick(&store, now, &deadline) != 0);
  assert(deadline == now && hp_store_pending_count(&store) == 0);
  random_error = 0;
  random_short = 1;
  assert(hp_heartbeat_tick(&store, now, &deadline) != 0);
  assert(deadline == now && hp_store_pending_count(&store) == 0);
  random_short = 0;
  int fd = store.pending_fd;
  store.pending_fd = -1;
  assert(hp_heartbeat_tick(&store, now, &deadline) != 0);
  assert(deadline == now);
  store.pending_fd = fd;
  random_value = UINT32_MAX;
  random_interrupted = 1;
  assert(!hp_heartbeat_tick(&store, now, &deadline));
  assert(hp_store_pending_count(&store) == 1);
  assert(deadline == now + HEARTBEAT_INTERVAL * 1.15);
  char pending[512];
  snprintf(pending, sizeof(pending), "%s/pending", path);
  DIR *dir = opendir(pending);
  assert(dir);
  struct dirent *ent;
  while ((ent = readdir(dir))) {
    if (ent->d_name[0] == '.') continue;
    char name[1024], content[4096];
    snprintf(name, sizeof(name), "%s/%s", pending, ent->d_name);
    FILE *in = fopen(name, "r");
    assert(in);
    size_t n = fread(content, 1, sizeof(content) - 1, in);
    content[n] = 0;
    assert(!ferror(in) && !fclose(in));
    cJSON *json = cJSON_Parse(content);
    assert(json);
    assert(!strcmp(cJSON_GetObjectItem(json, "source")->valuestring, "system"));
    assert(!strcmp(cJSON_GetObjectItem(json, "operation")->valuestring, "heartbeat"));
    assert(!strcmp(cJSON_GetObjectItem(json, "agent_id")->valuestring, "test-agent"));
    assert(cJSON_GetObjectItem(json, "complete")->type == cJSON_True);
    cJSON_Delete(json);
    assert(!unlink(name));
  }
  closedir(dir);
  hp_store_close(&store);
  assert(!rmdir(pending));
  snprintf(pending, sizeof(pending), "%s/snapshots", path);
  assert(!rmdir(pending) && !rmdir(path));
  return 0;
}
