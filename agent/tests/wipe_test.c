#define _GNU_SOURCE
#include "monitor.h"
#include "snapshot.h"
#include "diff.h"
#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void *watched;
static size_t watched_size;
static int erased;
static size_t diff_size, diff_allocation;
static int diff_erased;
void __real_free(void *pointer);

static void assert_zero(const unsigned char *pointer, size_t size) {
  for (size_t i = 0; i < size; i++) assert(pointer[i] == 0);
}

void __wrap_free(void *pointer) {
  if (pointer && pointer == watched) {
    assert_zero(pointer, watched_size);
    erased++;
    watched = NULL;
  }
  if (pointer && diff_allocation && malloc_usable_size(pointer) == diff_allocation) {
    assert_zero(pointer, diff_size);
    diff_erased++;
  }
  __real_free(pointer);
}

int main(void) {
  char state[] = "/tmp/hp-wipe-XXXXXX", log[] = "/tmp/hp-wipe-log-XXXXXX";
  struct hp_store store;
  struct hp_monitor monitor;
  assert(mkdtemp(state));
  assert(!hp_store_init(&store, state, "test"));
  const unsigned char secret[] = "sensitive log content\n";
  hp_store_record_log(&store, "test-log", secret, sizeof(secret) - 1);
  watched = store.recent[0].content;
  watched_size = store.recent[0].size;
  assert(watched && !memcmp(watched, secret, watched_size));
  for (int i = 0; i < 32; i++) hp_store_record_log(&store, "test-log", secret, sizeof(secret) - 1);
  assert(erased == 1);
  int fd = mkstemp(log);
  assert(fd >= 0 && !close(fd));
  assert(!hp_monitor_init(&monitor, &store));
  assert(!hp_monitor_add_log(&monitor, log));
  assert(!hp_monitor_poll(&monitor, 0));
  FILE *out = fopen(log, "a");
  assert(out && fwrite(secret, 1, sizeof(secret) - 1, out) == sizeof(secret) - 1 && !fclose(out));
  assert(!hp_monitor_poll(&monitor, 0));
  assert_zero(monitor.logs[0].partial, sizeof(secret) - 1);
  assert_zero((const unsigned char *)store.report_buffer, sizeof(store.report_buffer));
  out = fopen(log, "a");
  assert(out && fputs("unfinished", out) >= 0 && !fclose(out));
  assert(!hp_monitor_poll(&monitor, 0));
  assert(monitor.logs[0].partial_size == 10 && !memcmp(monitor.logs[0].partial, "unfinished", 10));
  watched = monitor.logs[0].partial;
  watched_size = 65536;
  hp_monitor_close(&monitor);
  assert(erased == 2);
  watched = store.recent[0].content;
  watched_size = store.recent[0].size;
  hp_store_close(&store);
  assert(erased == 3);
  assert_zero((const unsigned char *)store.report_buffer, sizeof(store.report_buffer));
  assert(!unlink(log));

  /* Identify the diff's unique large text allocation without changing production code. */
  unsigned char diff_text[32749];
  memset(diff_text, 'S', sizeof(diff_text));
  void *probe = malloc(sizeof(diff_text));
  assert(probe);
  size_t allocation = malloc_usable_size(probe);
  free(probe);
  FILE *input = tmpfile(), *output = tmpfile();
  assert(input && output);
  assert(fwrite(diff_text, 1, sizeof(diff_text), input) == sizeof(diff_text));
  assert(!fflush(input));
  diff_size = sizeof(diff_text);
  diff_allocation = allocation;
  assert(!hp_write_text_diff(output, fileno(input), -1));
  diff_allocation = 0;
  assert(diff_erased == 1);
  assert(!fclose(input) && !fclose(output));
  return 0;
}
