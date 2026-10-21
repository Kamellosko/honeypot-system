#define _GNU_SOURCE
#include "port.h"
#include "snapshot.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(void) {
  char dir[] = "/tmp/hp-transport-XXXXXX";
  assert(mkdtemp(dir));
  struct hp_store store;
  assert(hp_store_init(&store, dir, "agent") == 0);
  assert(hp_report_simple(&store, "status", "unavailable", "/tmp/missing", "missing", NULL, 0) == 0);
  assert(hp_send_pending(&store, "127.0.0.1", 1) == 0);
  assert(hp_store_pending_count(&store) == 1);
  hp_store_close(&store);
  return 0;
}
