#define _GNU_SOURCE
#include "protocol.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  char *text = NULL;
  size_t len = 0;
  FILE *out = open_memstream(&text, &len);
  assert(out);
  hp_json_string(out, (const unsigned char *)"a\n\"b", 4);
  fclose(out);
  assert(strcmp(text, "\"a\\u000a\\\"b\"") == 0);
  free(text);
  assert(hp_valid_utf8((const unsigned char *)"ą", strlen("ą")));
  const unsigned char invalid[] = {0xff, 0};
  assert(!hp_valid_utf8(invalid, 1));
  char id[65], utc[32];
  hp_report_id(id); hp_utc_time(utc);
  assert(strlen(id) == 64 && strlen(utc) == 20);
  return 0;
}
