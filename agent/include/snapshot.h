#pragma once
#include <stddef.h>
#include <stdio.h>
#include <time.h>

struct hp_evidence {
  char *source;
  unsigned char *content;
  size_t size;
  time_t captured_at;
};

struct hp_store {
  char *path;
  char *id;
  int snapshots_fd;
  int pending_fd;
  struct hp_evidence recent[32];
  size_t recent_next;
  /* Queue length estimate for report_begin only (-1 unknown); refreshed by a scan at most once per second. */
  int pending_estimate;
  double pending_scanned_at;
  /* One report writer owns this buffer until fclose; the sender only reads files. */
  char report_buffer[BUFSIZ];
};
int hp_store_init(struct hp_store *store, const char *path, const char *id);
void hp_store_close(struct hp_store *store);
int hp_store_pending_count(const struct hp_store *store);
int hp_snapshot_root_seen(struct hp_store *store, const char *root_path);
int hp_snapshot_mark_root(struct hp_store *store, const char *root_path);
int hp_snapshot_reconcile_deleted(struct hp_store *store, int root_fd, const char *root_path);
int hp_snapshot_rename(struct hp_store *store, const char *old_path, const char *new_path);
int hp_snapshot_has(struct hp_store *store, const char *root_path, const char *relative);
int hp_store_record_log(struct hp_store *store, const char *source,
                         const unsigned char *content, size_t size);
int hp_snapshot_event(struct hp_store *store, int root_fd, const char *root_path,
                      const char *relative, const char *operation);
int hp_report_simple(struct hp_store *store, const char *source, const char *operation,
                     const char *path, const char *error, const unsigned char *content,
                     size_t content_size);
int hp_report_connection(struct hp_store *store, const char *local_ip, unsigned short local_port,
                          const char *peer_ip, unsigned short peer_port);
