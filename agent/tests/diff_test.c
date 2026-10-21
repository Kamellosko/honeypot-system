#define _GNU_SOURCE
#include "diff.h"
#include "cJSON.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void check(const char *old, const char *next, const char *wanted) {
  FILE *a = tmpfile(), *b = tmpfile();
  assert(a && b);
  assert(fwrite(old, 1, strlen(old), a) == strlen(old) && !fflush(a));
  assert(fwrite(next, 1, strlen(next), b) == strlen(next) && !fflush(b));
  char *json = NULL;
  size_t size = 0;
  FILE *out = open_memstream(&json, &size);
  assert(out && fputs("{\"test\":0", out) >= 0 && !hp_write_text_diff(out, fileno(a), fileno(b)));
  assert(fputc('}', out) != EOF && !fclose(out));
  cJSON *value = cJSON_Parse(json);
  assert(value && strstr(cJSON_GetObjectItem(value, "diff")->valuestring, wanted));
  cJSON_Delete(value); free(json); fclose(a); fclose(b);
}

int main(int argc, char **argv) {
  if (argc == 3) {
    FILE *old = fopen(argv[1], "r"), *next = fopen(argv[2], "r");
    assert(old && next && fputs("{\"test\":0", stdout) >= 0);
    int result = hp_write_text_diff(stdout, fileno(old), fileno(next));
    assert(!result && fputs("}", stdout) >= 0 && !fclose(old) && !fclose(next));
    return 0;
  }
  check("a\nb\nc\n", "a\nx\nc\n", "-b\n+x\n");
  check("", "new\n", "@@ -0,0 +1,1 @@\n+new\n");
  check("old\n", "", "@@ -1,1 +0,0 @@\n-old\n");
  check("old", "new", "\\ No newline at end of file\n");
  check("\"a\"\n", "\\b\n", "-\"a\"\n+\\b\n");
  check("same\n", "same\n", "");
  FILE *binary = tmpfile();
  assert(binary && fputc(0, binary) == 0 && !fflush(binary));
  FILE *out = tmpfile();
  assert(out && hp_write_text_diff(out, -1, fileno(binary)) == 1);
  assert(ftell(out) == 0);
  fclose(out); fclose(binary);
  return 0;
}
