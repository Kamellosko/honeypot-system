#define _GNU_SOURCE
#include "snapshot.h"
#include "cJSON.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __wrap_hp_write_text_diff(FILE *out, int old_fd, int new_fd) {
  (void)out; (void)old_fd; (void)new_fd;
  errno = ENOMEM;
  return -1;
}

int main(void) {
  char dir[] = "/tmp/hp-diff-fail-XXXXXX", state[256], path[256], pending[512], snapshots[512];
  assert(mkdtemp(dir));
  snprintf(state, sizeof(state), "%s/state", dir);
  snprintf(path, sizeof(path), "%s/data", dir);
  snprintf(pending, sizeof(pending), "%s/pending", state);
  snprintf(snapshots, sizeof(snapshots), "%s/snapshots", state);
  struct hp_store store;
  assert(hp_store_init(&store, state, "agent") == 0);
  int root = open(dir, O_RDONLY | O_DIRECTORY);
  assert(root >= 0);
  FILE *f = fopen(path, "w");
  assert(f); fputs("old\n", f); fclose(f);
  assert(hp_snapshot_event(&store, root, dir, "data", "baseline") == 0);
  f = fopen(path, "w");
  assert(f); fputs("new\n", f); fclose(f);
  assert(hp_snapshot_event(&store, root, dir, "data", "modify") != 0);
  assert(hp_store_pending_count(&store) == 1);
  DIR *listing = opendir(pending);
  assert(listing);
  struct dirent *ent;
  int valid = 0;
  while ((ent = readdir(listing))) if (strstr(ent->d_name, ".json")) {
    char file[1024];
    snprintf(file, sizeof(file), "%s/%s", pending, ent->d_name);
    f = fopen(file, "rb");
    assert(f);
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *text = malloc((size_t)n + 1);
    assert(text && fread(text, 1, (size_t)n, f) == (size_t)n);
    text[n] = 0; fclose(f);
    cJSON *report = cJSON_Parse(text);
    free(text);
    assert(report);
    cJSON *error = cJSON_GetObjectItem(report, "error");
    assert(error && error->valuestring && !strcmp(error->valuestring, "diff_failed"));
    cJSON_Delete(report);
    valid++;
  }
  closedir(listing);
  assert(valid == 1);
  listing = opendir(snapshots);
  assert(listing);
  int old_kept = 0;
  while ((ent = readdir(listing))) if (strlen(ent->d_name) == 64) {
    char file[1024], content[8];
    snprintf(file, sizeof(file), "%s/%s", snapshots, ent->d_name);
    f = fopen(file, "rb");
    assert(f);
    size_t n = fread(content, 1, sizeof(content), f);
    fclose(f);
    if (n == 4 && !memcmp(content, "old\n", 4)) old_kept = 1;
  }
  closedir(listing);
  assert(old_kept);
  hp_store_close(&store);
  close(root);
  return 0;
}
