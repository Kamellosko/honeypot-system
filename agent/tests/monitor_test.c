#define _GNU_SOURCE
#include "monitor.h"
#include "snapshot.h"
#include "cJSON.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int has_complete_create(const char *state) {
  char dirpath[512];
  snprintf(dirpath, sizeof(dirpath), "%s/pending", state);
  DIR *dir = opendir(dirpath);
  assert(dir);
  struct dirent *ent;
  int found = 0;
  while ((ent = readdir(dir))) if (strstr(ent->d_name, ".json")) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name);
    FILE *in = fopen(path, "rb");
    assert(in);
    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    rewind(in);
    char *text = malloc((size_t)size + 1);
    assert(text && fread(text, 1, (size_t)size, in) == (size_t)size);
    text[size] = 0; fclose(in);
    cJSON *report = cJSON_Parse(text);
    free(text);
    assert(report);
    cJSON *op = cJSON_GetObjectItem(report, "operation");
    cJSON *complete = cJSON_GetObjectItem(report, "complete");
    cJSON *changes = cJSON_GetObjectItem(report, "content_changes");
    cJSON *diff = cJSON_GetObjectItem(changes, "diff");
    if (op && op->valuestring && !strcmp(op->valuestring, "create") &&
        complete && complete->type == cJSON_True && diff && diff->valuestring &&
        strstr(diff->valuestring, "+content")) found = 1;
    cJSON_Delete(report);
  }
  closedir(dir);
  return found;
}

int main(void) {
  char dir[] = "/tmp/hp-monitor-XXXXXX", state[256], sub[256], file[256];
  assert(mkdtemp(dir));
  snprintf(state, sizeof(state), "%s/state", dir);
  snprintf(sub, sizeof(sub), "%s/sub", dir);
  snprintf(file, sizeof(file), "%s/sub/data", dir);
  assert(mkdir(state, 0700) == 0);
  assert(mkdir(sub, 0700) == 0);
  struct hp_store store;
  struct hp_monitor monitor;
  char noncanonical[256];
  snprintf(noncanonical, sizeof(noncanonical), "%s/./", dir);
  assert(hp_store_init(&store, state, "agent") == 0);
  assert(hp_monitor_init(&monitor, &store) == 0);
  assert(hp_monitor_add_share(&monitor, "test", noncanonical) == 0);
  assert(monitor.watch_count == 2);
  FILE *f = fopen(file, "w");
  assert(f); fputs("content", f); fclose(f);
  assert(hp_monitor_poll(&monitor, 1000) == 0);
  assert(hp_store_pending_count(&store) >= 1);
  assert(has_complete_create(state));
  char moved[256], moved_file[256];
  snprintf(moved, sizeof(moved), "%s/moved", dir);
  snprintf(moved_file, sizeof(moved_file), "%s/moved/data", dir);
  assert(rename(sub, moved) == 0);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  int found_moved = 0;
  for (size_t i = 0; i < monitor.watch_count; i++)
    if (!strcmp(monitor.watches[i].relative, "moved")) found_moved = 1;
  assert(found_moved);
  f = fopen(moved_file, "a");
  assert(f); fputs(" after move", f); fclose(f);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  assert(rename(moved, sub) == 0);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  hp_monitor_close(&monitor);
  hp_store_close(&store);
  f = fopen(file, "w");
  assert(f); fputs("changed while stopped", f); fclose(f);
  assert(hp_store_init(&store, state, "agent") == 0);
  assert(hp_monitor_init(&monitor, &store) == 0);
  assert(hp_monitor_add_share(&monitor, "test", dir) == 0);
  assert(hp_store_pending_count(&store) >= 2);
  hp_monitor_close(&monitor);
  hp_store_close(&store);
  assert(unlink(file) == 0);
  assert(hp_store_init(&store, state, "agent") == 0);
  assert(hp_monitor_init(&monitor, &store) == 0);
  assert(hp_monitor_add_share(&monitor, "test", dir) == 0);
  assert(hp_store_pending_count(&store) >= 3);
  hp_monitor_close(&monitor);
  hp_store_close(&store);
  return 0;
}
