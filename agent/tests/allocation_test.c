#define _GNU_SOURCE
#include "config.h"
#include "diff.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t failure, calls;
static int rejected(void) {
  if (failure && ++calls == failure) { errno = ENOMEM; return 1; }
  return 0;
}
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
char *__real_strdup(const char *);
char *__real_strndup(const char *, size_t);
void *__wrap_malloc(size_t n) { return rejected() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t s) { return rejected() ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t n) { return rejected() ? NULL : __real_realloc(p, n); }
char *__wrap_strdup(const char *s) { return rejected() ? NULL : __real_strdup(s); }
char *__wrap_strndup(const char *s, size_t n) { return rejected() ? NULL : __real_strndup(s, n); }

int main(void) {
  char dir[] = "/tmp/hp-alloc-XXXXXX", config[256], old[256], next[256];
  assert(mkdtemp(dir));
  snprintf(config, sizeof(config), "%s/smb.conf", dir);
  snprintf(old, sizeof(old), "%s/old", dir);
  snprintf(next, sizeof(next), "%s/new", dir);
  FILE *f = fopen(config, "w");
  assert(f && fprintf(f, "[global]\n[docs]\npath=%s\n", dir) > 0 && !fclose(f));
  f = fopen(old, "w"); assert(f && fputs("a\nb\nc\n", f) >= 0 && !fclose(f));
  f = fopen(next, "w"); assert(f && fputs("a\nx\nc\n", f) >= 0 && !fclose(f));
  int a = open(old, O_RDONLY), b = open(next, O_RDONLY);
  assert(a >= 0 && b >= 0);
  for (size_t i = 1; i <= 64; i++) {
    struct hp_sources sources = {0};
    calls = 0; failure = i;
    int result = hp_discover_config(config, &sources);
    failure = 0;
    assert(result == 0 || result == -1);
    hp_sources_free(&sources);
    f = tmpfile(); assert(f);
    calls = 0; failure = i;
    result = hp_write_text_diff(f, a, b);
    failure = 0;
    assert(result == 0 || result == -1);
    assert(!fclose(f));
  }
  assert(!close(a) && !close(b));
  assert(!unlink(config) && !unlink(old) && !unlink(next) && !rmdir(dir));
  return 0;
}
