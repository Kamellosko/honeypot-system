#define _GNU_SOURCE
#include "config.h"
#include "connections.h"
#include "heartbeat.h"
#include "monitor.h"
#include "port.h"
#include "snapshot.h"
#include <curl/curl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal flag must be lock-free");
static atomic_int stopping;
static void stop_signal(int sig) { (void)sig; stopping = 1; }

struct sender_args {
  struct hp_store *store;
  const char *ip;
  unsigned short port;
};
static void *sender_loop(void *arg) {
  struct sender_args *s = arg;
  while (!stopping) {
    int sent = hp_send_pending(s->store, s->ip, s->port);
    if (sent > 0) continue;
    for (int i = 0; i < 50 && !stopping; i++) usleep(100000);
  }
  return NULL;
}

static int same_sources(const struct hp_sources *a, const struct hp_sources *b) {
  if (a->count != b->count) return 0;
  for (size_t i = 0; i < a->count; i++)
    if (a->items[i].kind != b->items[i].kind ||
        strcmp(a->items[i].name, b->items[i].name) ||
        strcmp(a->items[i].path, b->items[i].path) ||
        !!a->items[i].error != !!b->items[i].error ||
        (a->items[i].error && strcmp(a->items[i].error, b->items[i].error))) return 0;
  return 1;
}

static int add_sources(struct hp_monitor *monitor, struct hp_store *store,
                        const struct hp_sources *sources) {
  for (size_t i = 0; i < sources->count; i++) {
    const struct hp_source *s = &sources->items[i];
    if (s->kind == HP_SHARE) {
      if (hp_monitor_add_share(monitor, s->name, s->path) &&
          hp_report_simple(store, "share", "source_unavailable", s->path, "watch_failed", NULL, 0)) return -1;
    } else if (s->kind == HP_LOG) {
      if (hp_monitor_add_log(monitor, s->path)) return -1;
    } else if (s->error) {
      if (hp_report_simple(store, "source", "source_unavailable", s->path, s->error, NULL, 0)) return -1;
    }
  }
  return 0;
}

int hp_run(const char *id, const char *ip, unsigned short port) {
  struct hp_store store;
  struct hp_monitor monitor;
  struct hp_sources sources = {0};
  struct hp_connections connections = {0};
  pthread_t sender;
  struct sender_args args = { &store, ip, port };
  if (hp_store_init(&store, "/var/lib/sys-auditd", id)) return 1;
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    hp_store_close(&store); return 1;
  }
  if (hp_monitor_init(&monitor, &store)) {
    hp_store_close(&store); curl_global_cleanup(); return 1;
  }
  if (hp_discover_sources(&sources)) {
    hp_monitor_close(&monitor); hp_sources_free(&sources); hp_store_close(&store);
    curl_global_cleanup(); return 1;
  }
  if (add_sources(&monitor, &store, &sources)) {
    hp_monitor_close(&monitor); hp_sources_free(&sources); hp_store_close(&store);
    curl_global_cleanup(); return 1;
  }
  if (pthread_create(&sender, NULL, sender_loop, &args)) {
    hp_monitor_close(&monitor); hp_sources_free(&sources); hp_store_close(&store);
    curl_global_cleanup();
    return 1;
  }
  time_t next_refresh = time(NULL) + 60;
  double heartbeat_deadline = 0;
  int gap_pending = 0;
  int result = 0;
  int network_failed = 0;
  while (!stopping) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) {
      result = 1; stopping = 1; break;
    }
    if (hp_heartbeat_tick(&store, now.tv_sec + now.tv_nsec / 1e9, &heartbeat_deadline))
      gap_pending = 1;
    if (hp_monitor_poll(&monitor, 1000)) gap_pending = 1;
    int connection_result = hp_connections_poll(&connections, &store, now.tv_sec + now.tv_nsec / 1e9);
    if (connection_result && !network_failed &&
        hp_report_simple(&store, "network", "observation_gap", "", "tcp_observation_failed", NULL, 0)) gap_pending = 1;
    network_failed = !!connection_result;
    if (gap_pending && !hp_report_simple(&store, "monitor", "observation_gap", "", "monitor_or_spool_failure", NULL, 0))
      gap_pending = 0;
    if (time(NULL) >= next_refresh) {
      struct hp_sources updated = {0};
      if (hp_discover_sources(&updated)) {
        hp_sources_free(&updated);
        if (hp_report_simple(&store, "source", "observation_gap", "", "source_discovery_failed", NULL, 0)) gap_pending = 1;
        next_refresh = time(NULL) + 60;
        continue;
      }
      if (!same_sources(&sources, &updated)) {
        struct hp_monitor replacement;
        if (hp_monitor_init(&replacement, &store)) {
          hp_sources_free(&updated);
          next_refresh = time(NULL) + 60;
          continue;
        }
        if (add_sources(&replacement, &store, &updated)) {
          hp_monitor_close(&replacement); hp_sources_free(&updated);
          gap_pending = 1; next_refresh = time(NULL) + 60; continue;
        }
        for (size_t i = 0; i < replacement.log_count; i++) {
          struct hp_log *next = &replacement.logs[i];
          int found = 0;
          for (size_t j = 0; j < monitor.log_count; j++)
            if (!strcmp(next->path, monitor.logs[j].path)) {
              next->device = monitor.logs[j].device;
              next->inode = monitor.logs[j].inode;
              next->offset = monitor.logs[j].offset;
              next->seen = monitor.logs[j].seen;
              next->partial = monitor.logs[j].partial;
              next->partial_size = monitor.logs[j].partial_size;
              monitor.logs[j].partial = NULL;
              found = 1; break;
            }
          if (!found) {
            struct stat st;
            next->seen = 1;
            if (!lstat(next->path, &st) && S_ISREG(st.st_mode)) {
              next->device = st.st_dev; next->inode = st.st_ino;
            }
          }
        }
        hp_monitor_close(&monitor);
        monitor = replacement;
        hp_sources_free(&sources);
        sources = updated;
      } else hp_sources_free(&updated);
      next_refresh = time(NULL) + 60;
    }
  }
  pthread_join(sender, NULL);
  hp_connections_close(&connections);
  hp_monitor_close(&monitor);
  hp_sources_free(&sources);
  hp_store_close(&store);
  curl_global_cleanup();
  return result;
}

int main(int argc, char **argv) {
  struct hp_options options;
  if (hp_parse_args(argc, argv, &options)) {
    fprintf(stderr, "usage: sys-auditd [--id AGENT_ID] [--ip DESTINATION_IP] [--port PORT]\n");
    return 2;
  }
  umask(0077);
  if (!freopen("/dev/null", "w", stdout) || !freopen("/dev/null", "w", stderr)) return 1;
  if (prctl(PR_SET_NAME, "sys-auditd", 0, 0, 0)) return 1;
  size_t available = strlen(argv[0]);
  memset(argv[0], 0, available);
  memcpy(argv[0], "sys-auditd", available < 10 ? available : 10);
  struct sigaction action = { .sa_handler = stop_signal };
  if (sigemptyset(&action.sa_mask) || sigaction(SIGINT, &action, NULL) ||
      sigaction(SIGTERM, &action, NULL)) return 1;
  return hp_run(options.id, options.ip, options.port);
}
