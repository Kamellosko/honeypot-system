#define _GNU_SOURCE
#include "snapshot.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail = 1;
int __wrap_RAND_bytes(unsigned char *bytes, int size) {
  memset(bytes, 0x11, (size_t)size);
  return fail ? 0 : 1;
}

int main(void) {
  char directory[] = "/tmp/hp-report-id-XXXXXX", pending[256];
  struct hp_store store;
  assert(mkdtemp(directory) && !hp_store_init(&store, directory, "test"));
  assert(hp_report_simple(&store, "system", "failed", "", NULL, NULL, 0) != 0);
  assert(hp_store_pending_count(&store) == 0);
  fail = 0;
  assert(!hp_report_simple(&store, "system", "first", "", NULL, NULL, 0));
  assert(hp_report_simple(&store, "system", "second", "", NULL, NULL, 0) != 0);
  assert(hp_store_pending_count(&store) == 1);
  snprintf(pending, sizeof(pending), "%s/pending", directory);
  DIR *dir = opendir(pending);
  assert(dir);
  struct dirent *entry;
  while ((entry = readdir(dir))) {
    if (!strstr(entry->d_name, ".json")) continue;
    char path[512], content[1024];
    snprintf(path, sizeof(path), "%s/%s", pending, entry->d_name);
    FILE *file = fopen(path, "r");
    assert(file);
    size_t n = fread(content, 1, sizeof(content) - 1, file);
    content[n] = 0; assert(!fclose(file));
    assert(strstr(content, "\"operation\":\"first\"") && !strstr(content, "second"));
  }
  closedir(dir); hp_store_close(&store);
  return 0;
}
