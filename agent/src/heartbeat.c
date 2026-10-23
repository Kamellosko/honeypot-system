#define _GNU_SOURCE
#include "heartbeat.h"
#include "config.h"
#include "snapshot.h"
#include <errno.h>
#include <stdint.h>
#include <sys/random.h>

int hp_heartbeat_tick(struct hp_store *store, double now, double *deadline) {
  if (*deadline && now < *deadline) return 0;
  uint32_t random;
  ssize_t n;
  do { n = getrandom(&random, sizeof(random), 0); } while (n < 0 && errno == EINTR);
  if (n != sizeof(random)) return -1;
  if (*deadline && hp_report_simple(store, "system", "heartbeat", "", NULL, NULL, 0))
    return -1;
  *deadline = now + HEARTBEAT_INTERVAL * (.85 + .30 * (random / (double)UINT32_MAX));
  return 0;
}
