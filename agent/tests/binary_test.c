#define _GNU_SOURCE
#include "snapshot.h"
#include "cJSON.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static cJSON *find_report(const char *state, const char *needle) {
  char dirpath[512];
  snprintf(dirpath, sizeof(dirpath), "%s/pending", state);
  DIR *dir = opendir(dirpath);
  assert(dir);
  struct dirent *ent;
  cJSON *found = NULL;
  while ((ent = readdir(dir))) if (strstr(ent->d_name, ".json")) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dirpath, ent->d_name);
    FILE *in = fopen(path, "rb");
    assert(in);
    assert(fseek(in, 0, SEEK_END) == 0);
    long n = ftell(in);
    rewind(in);
    char *buf = malloc((size_t)n + 1);
    assert(buf && fread(buf, 1, (size_t)n, in) == (size_t)n);
    buf[n] = 0;
    fclose(in);
    cJSON *report = cJSON_Parse(buf);
    free(buf);
    assert(report);
    cJSON *p = cJSON_GetObjectItem(report, "path");
    if (p && p->valuestring && strstr(p->valuestring, needle)) {
      cJSON_Delete(found);
      found = report;
    } else cJSON_Delete(report);
  }
  closedir(dir);
  return found;
}

static size_t decode(const char *s, unsigned char *out) {
  size_t n = strlen(s);
  assert(n % 4 == 0);
  int m = EVP_DecodeBlock(out, (const unsigned char *)s, (int)n);
  assert(m >= 0);
  return (size_t)m - (n && s[n - 1] == '=') - (n > 1 && s[n - 2] == '=');
}

int main(void) {
  char dir[] = "/tmp/hp-binary-XXXXXX", state[256], path[256];
  assert(mkdtemp(dir));
  snprintf(state, sizeof(state), "%s/state", dir);
  snprintf(path, sizeof(path), "%s/blob", dir);
  struct hp_store store;
  assert(hp_store_init(&store, state, "agent") == 0);
  int root = open(dir, O_RDONLY | O_DIRECTORY);
  assert(root >= 0);
  unsigned char old[131072], now[131072], reconstructed[131072];
  for (size_t i = 0; i < sizeof(old); i++) old[i] = (unsigned char)(i % 251);
  memcpy(now, old, sizeof(now));
  now[123] = 0; now[90000] ^= 0x7f;
  FILE *out = fopen(path, "wb");
  assert(out && fwrite(old, 1, sizeof(old), out) == sizeof(old));
  fclose(out);
  assert(hp_snapshot_event(&store, root, dir, "blob", "baseline") == 0);
  out = fopen(path, "wb");
  assert(out && fwrite(now, 1, sizeof(now), out) == sizeof(now));
  fclose(out);
  assert(hp_snapshot_event(&store, root, dir, "blob", "modify") == 0);
  cJSON *report = find_report(state, "blob");
  assert(report);
  cJSON *changes = cJSON_GetObjectItem(report, "content_changes");
  cJSON *blocks = cJSON_GetObjectItem(changes, "blocks");
  assert(blocks && cJSON_GetArraySize(blocks) == 2);
  memcpy(reconstructed, old, sizeof(old));
  for (int i = 0; i < cJSON_GetArraySize(blocks); i++) {
    cJSON *block = cJSON_GetArrayItem(blocks, i);
    cJSON *offset = cJSON_GetObjectItem(block, "offset");
    cJSON *old_b64 = cJSON_GetObjectItem(block, "old_base64");
    cJSON *new_b64 = cJSON_GetObjectItem(block, "new_base64");
    assert(offset && old_b64 && new_b64);
    size_t position = (size_t)offset->valuedouble;
    unsigned char decoded[65540];
    size_t old_n = decode(old_b64->valuestring, decoded);
    assert(old_n == 65536 && !memcmp(decoded, old + position, old_n));
    size_t new_n = decode(new_b64->valuestring, decoded);
    assert(new_n == 65536);
    memcpy(reconstructed + position, decoded, new_n);
  }
  assert(!memcmp(reconstructed, now, sizeof(now)));
  cJSON_Delete(report);
  char name[] = { 'x', (char)0xff, 0 };
  int fd = openat(root, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
  assert(fd >= 0 && write(fd, "z", 1) == 1);
  close(fd);
  assert(hp_snapshot_event(&store, root, dir, name, "create") == 0);
  assert(hp_store_pending_count(&store) == 2);
  char pending[512];
  snprintf(pending, sizeof(pending), "%s/pending", state);
  DIR *listing = opendir(pending);
  assert(listing);
  int found_path = 0;
  struct dirent *ent;
  while ((ent = readdir(listing))) if (strstr(ent->d_name, ".json")) {
    char report_path[1024];
    snprintf(report_path, sizeof(report_path), "%s/%s", pending, ent->d_name);
    FILE *in = fopen(report_path, "rb");
    assert(in);
    fseek(in, 0, SEEK_END);
    long n = ftell(in);
    rewind(in);
    char *buf = malloc((size_t)n + 1);
    assert(buf && fread(buf, 1, (size_t)n, in) == (size_t)n);
    buf[n] = 0;
    fclose(in);
    cJSON *parsed = cJSON_Parse(buf);
    free(buf);
    assert(parsed);
    cJSON *encoded = cJSON_GetObjectItem(parsed, "path_base64");
    if (encoded && encoded->valuestring) {
      unsigned char raw[1024];
      size_t len = decode(encoded->valuestring, raw);
      char expected[512];
      snprintf(expected, sizeof(expected), "%s/%s", dir, name);
      assert(len == strlen(expected) && !memcmp(raw, expected, len));
      found_path = 1;
    }
    cJSON_Delete(parsed);
  }
  closedir(listing);
  assert(found_path);
  hp_store_close(&store);
  close(root);
  return 0;
}
