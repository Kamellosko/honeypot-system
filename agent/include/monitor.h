#pragma once
#include "snapshot.h"
#include <stddef.h>
#include <sys/types.h>

struct hp_watch {
  int wd;
  size_t root;
  char *relative;
};
struct hp_root {
  char *name;
  char *path;
  int fd;
  int unavailable_reported;
  int incomplete;
  time_t retry_after;
};
struct hp_log {
  char *path;
  dev_t device;
  ino_t inode;
  off_t offset;
  int seen;
  unsigned char *partial;
  size_t partial_size;
  /* Last bytes consumed before offset; detects a rewrite that does not shrink the file. */
  unsigned char fingerprint[64];
  size_t fingerprint_size;
};
struct hp_move {
  unsigned cookie;
  size_t root;
  char *relative;
  int is_dir;
  time_t when;
};
struct hp_created {
  size_t root;
  char *relative;
  time_t when;
};
struct hp_monitor {
  int inotify_fd;
  struct hp_store *store;
  struct hp_watch *watches;
  size_t watch_count;
  struct hp_root *roots;
  size_t root_count;
  struct hp_log *logs;
  size_t log_count;
  struct hp_move moves[128];
  struct hp_created created[128];
};
int hp_monitor_init(struct hp_monitor *monitor, struct hp_store *store);
int hp_monitor_add_share(struct hp_monitor *monitor, const char *name, const char *path);
int hp_monitor_add_log(struct hp_monitor *monitor, const char *path);
int hp_monitor_poll(struct hp_monitor *monitor, int timeout_ms);
void hp_monitor_close(struct hp_monitor *monitor);
