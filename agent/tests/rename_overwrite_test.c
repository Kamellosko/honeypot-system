#define _GNU_SOURCE
#include "monitor.h"
#include "snapshot.h"
#include "cJSON.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
  char parent[] = "/tmp/hp-overwrite-XXXXXX", share[256], state[256], a[512], b[512], pending[512];
  assert(mkdtemp(parent));
  snprintf(share, sizeof(share), "%s/share", parent);
  snprintf(state, sizeof(state), "%s/state", parent);
  snprintf(a, sizeof(a), "%s/a", share);
  snprintf(b, sizeof(b), "%s/b", share);
  snprintf(pending, sizeof(pending), "%s/pending", state);
  assert(mkdir(share, 0700) == 0);
  FILE *out = fopen(a, "w");
  assert(out); fputs("A unique old content\n", out); fclose(out);
  out = fopen(b, "w");
  assert(out); fputs("B overwritten unique content\n", out); fclose(out);
  struct hp_store store;
  struct hp_monitor monitor;
  assert(hp_store_init(&store, state, "agent") == 0);
  assert(hp_monitor_init(&monitor, &store) == 0);
  assert(hp_monitor_add_share(&monitor, "share", share) == 0);
  assert(rename(a, b) == 0);
  assert(hp_monitor_poll(&monitor, 0) == 0);
  DIR *dir = opendir(pending);
  assert(dir);
  int found_diff = 0, found_rename = 0;
  struct dirent *ent;
  while ((ent = readdir(dir))) if (strstr(ent->d_name, ".json")) {
    char file[1024];
    snprintf(file, sizeof(file), "%s/%s", pending, ent->d_name);
    FILE *in = fopen(file, "rb");
    assert(in);
    fseek(in, 0, SEEK_END);
    long n = ftell(in);
    rewind(in);
    char *text = malloc((size_t)n + 1);
    assert(text && fread(text, 1, (size_t)n, in) == (size_t)n);
    text[n] = 0; fclose(in);
    cJSON *report = cJSON_Parse(text);
    free(text);
    assert(report);
    cJSON *op = cJSON_GetObjectItem(report, "operation");
    if (op && op->valuestring && !strcmp(op->valuestring, "rename")) found_rename = 1;
    cJSON *changes = cJSON_GetObjectItem(report, "content_changes");
    cJSON *diff = cJSON_GetObjectItem(changes, "diff");
    if (diff && diff->valuestring &&
        strstr(diff->valuestring, "-B overwritten unique content") &&
        strstr(diff->valuestring, "+A unique old content")) found_diff = 1;
    cJSON_Delete(report);
  }
  closedir(dir);
  assert(found_rename && found_diff);
  hp_monitor_close(&monitor);
  hp_store_close(&store);
  return 0;
}
