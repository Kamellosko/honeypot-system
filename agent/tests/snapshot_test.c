#define _GNU_SOURCE
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

static cJSON *last_report(const char *state, const char *wanted) {
  char path[512];
  snprintf(path, sizeof(path), "%s/pending", state);
  DIR *dir = opendir(path);
  assert(dir);
  struct dirent *ent;
  cJSON *report = NULL;
  while ((ent = readdir(dir))) if (strstr(ent->d_name, ".json")) {
    char file[1024];
    snprintf(file, sizeof(file), "%s/%s", path, ent->d_name);
    FILE *in = fopen(file, "r");
    assert(in);
    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    rewind(in);
    char *text = malloc((size_t)size + 1);
    assert(text);
    assert(fread(text, 1, (size_t)size, in) == (size_t)size);
    text[size] = 0;
    fclose(in);
    cJSON *parsed = cJSON_Parse(text);
    free(text);
    assert(parsed);
    cJSON *operation = cJSON_GetObjectItem(parsed, "operation");
    if (operation && operation->type == cJSON_String && !strcmp(operation->valuestring, wanted)) {
      cJSON_Delete(report); report = parsed;
    } else cJSON_Delete(parsed);
  }
  closedir(dir);
  return report;
}

int main(void) {
  char dir[] = "/tmp/hp-snapshot-XXXXXX", state[256], file[256];
  assert(mkdtemp(dir));
  snprintf(state, sizeof(state), "%s/state", dir);
  snprintf(file, sizeof(file), "%s/data", dir);
  assert(mkdir(state, 0700) == 0);
  int root = open(dir, O_RDONLY | O_DIRECTORY);
  assert(root >= 0);
  struct hp_store store;
  assert(hp_store_init(&store, state, "agent") == 0);
  FILE *f = fopen(file, "w");
  assert(f);
  fputs("first\n", f); fclose(f);
  assert(chmod(file, 0600) == 0);
  assert(hp_snapshot_event(&store, root, dir, "data", "baseline") == 0);
  const unsigned char log[] = "smbd_audit: client=192.0.2.8|modify|data";
  hp_store_record_log(&store, "/var/log/samba/log.smbd", log, sizeof(log) - 1);
  f = fopen(file, "w");
  assert(f); fputs("second", f); fclose(f);
  assert(hp_snapshot_event(&store, root, dir, "data", "modify") == 0);
  assert(hp_store_pending_count(&store) == 1);
  cJSON *report = last_report(state, "modify");
  assert(report);
  cJSON *changes = cJSON_GetObjectItem(report, "content_changes");
  cJSON *diff = cJSON_GetObjectItem(changes, "diff");
  assert(diff && diff->type == cJSON_String && strstr(diff->valuestring, "-first\n") && strstr(diff->valuestring, "+second"));
  cJSON *evidence = cJSON_GetArrayItem(cJSON_GetObjectItem(report, "evidence"), 0);
  assert(evidence && cJSON_GetObjectItem(evidence, "context_only")->type == cJSON_True);
  cJSON *network = cJSON_GetObjectItem(evidence, "network_context");
  cJSON *endpoint = cJSON_GetArrayItem(cJSON_GetObjectItem(network, "endpoints"), 0);
  assert(endpoint && !strcmp(cJSON_GetObjectItem(endpoint, "ip")->valuestring, "192.0.2.8"));
  assert(cJSON_GetObjectItem(cJSON_GetObjectItem(report, "analysis"), "actor")->type == cJSON_NULL);
  cJSON_Delete(report);
  assert(hp_snapshot_event(&store, root, dir, "data", "baseline") == 0);
  assert(hp_store_pending_count(&store) == 1);
  assert(chmod(file, 0640) == 0);
  assert(hp_snapshot_event(&store, root, dir, "data", "metadata") == 0);
  report = last_report(state, "metadata");
  assert(report);
  cJSON *metadata = cJSON_GetObjectItem(report, "metadata");
  cJSON *old_mode = cJSON_GetObjectItem(metadata, "old_mode");
  cJSON *new_mode = cJSON_GetObjectItem(metadata, "new_mode");
  assert(old_mode && new_mode && old_mode->valueint == 0600 && new_mode->valueint == 0640);
  cJSON_Delete(report);
  assert(hp_store_pending_count(&store) == 2);
  assert(unlink(file) == 0);
  assert(hp_snapshot_event(&store, root, dir, "data", "delete") == 0);
  assert(hp_store_pending_count(&store) == 3);
  assert(symlink("/etc/passwd", file) == 0);
  assert(hp_snapshot_event(&store, root, dir, "data", "modify") != 0);
  hp_store_close(&store);
  close(root);
  return 0;
}
