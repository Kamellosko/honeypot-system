#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  char expected[64] = "";
  FILE *f = fopen("../VERSION", "r");
  assert(f && fgets(expected, sizeof(expected), f));
  fclose(f);
  expected[strcspn(expected, "\n")] = 0;
  assert(sizeof(HP_VERSION) > 1);
  assert(!strcmp(HP_VERSION, expected));
  return 0;
}
