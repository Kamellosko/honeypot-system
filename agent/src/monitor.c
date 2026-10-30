#define _GNU_SOURCE
#include "monitor.h"
#include "io.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <dirent.h>

#define WATCH_MASK (IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF)

static int rooted_dir(int root, const char *rel) {
  struct open_how how = {
    .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
  };
  return (int)syscall(SYS_openat2, root, *rel ? rel : ".", &how, sizeof(how));
}

static int open_share_root(const char *path) {
  int slash = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (slash < 0) return -1;
  struct open_how how = {
    .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
  };
  const char *relative = path[0] == '/' ? path + 1 : path;
  int fd = (int)syscall(SYS_openat2, slash, *relative ? relative : ".", &how, sizeof(how));
  close(slash);
  return fd;
}

static int ignored(struct hp_monitor *m, const char *root, const char *rel) {
  char full[8192];
  if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full)) return 1;
  size_t n = strlen(m->store->path);
  return !strncmp(full, m->store->path, n) && (full[n] == '/' || !full[n]);
}

static int watch_tree(struct hp_monitor *m, size_t root_index, const char *rel, int baseline) {
  struct hp_root *root = &m->roots[root_index];
  if (ignored(m, root->path, rel)) return 0;
  int dirfd = rooted_dir(root->fd, rel);
  if (dirfd < 0) return -1;
  char proc[64];
  snprintf(proc, sizeof(proc), "/proc/self/fd/%d", dirfd);
  int wd = inotify_add_watch(m->inotify_fd, proc, WATCH_MASK | IN_ONLYDIR);
  if (wd < 0) { close(dirfd); return -1; }
  int known = 0;
  for (size_t i = 0; i < m->watch_count; i++) if (m->watches[i].wd == wd) { known = 1; break; }
  if (!known) {
    if (m->watch_count == SIZE_MAX / sizeof(*m->watches)) { close(dirfd); return -1; }
    char *relative = strdup(rel);
    if (!relative) { inotify_rm_watch(m->inotify_fd, wd); close(dirfd); return -1; }
    struct hp_watch *new_watches = realloc(m->watches, (m->watch_count + 1) * sizeof(*new_watches));
    if (!new_watches) { free(relative); inotify_rm_watch(m->inotify_fd, wd); close(dirfd); return -1; }
    m->watches = new_watches;
    m->watches[m->watch_count++] = (struct hp_watch){ wd, root_index, relative };
  }
  DIR *dir = fdopendir(dirfd);
  if (!dir) { close(dirfd); return -1; }
  int result = 0;
  struct dirent *ent;
  for (;;) {
    errno = 0;
    ent = readdir(dir);
    if (!ent) { if (errno) result = -1; break; }
    if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
    char child[8192];
    if (snprintf(child, sizeof(child), "%s%s%s", rel, *rel ? "/" : "", ent->d_name) >= (int)sizeof(child)) { result = -1; continue; }
    if (ignored(m, root->path, child)) continue;
    struct stat st;
    if (fstatat(dirfd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW)) { result = -1; continue; }
    if (S_ISDIR(st.st_mode)) {
      if (watch_tree(m, root_index, child, baseline)) result = -1;
    }
    else if (S_ISREG(st.st_mode))
      if (hp_snapshot_event(m->store, root->fd, root->path, child,
                            baseline == 1 ? "baseline" : baseline == 2 ? "reconcile" : "create")) result = -1;
  }
  if (closedir(dir)) result = -1;
  return result;
}

int hp_monitor_init(struct hp_monitor *m, struct hp_store *store) {
  memset(m, 0, sizeof(*m));
  m->store = store;
  m->inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
  return m->inotify_fd < 0 ? -1 : 0;
}

int hp_monitor_add_share(struct hp_monitor *m, const char *name, const char *path) {
  char *canonical = realpath(path, NULL);
  if (!canonical) return -1;
  int fd = open_share_root(canonical);
  if (fd < 0) { free(canonical); return -1; }
  char *root_name = strdup(name);
  if (!root_name || m->root_count == SIZE_MAX / sizeof(*m->roots)) { free(root_name); close(fd); free(canonical); return -1; }
  struct hp_root *roots = realloc(m->roots, (m->root_count + 1) * sizeof(*roots));
  if (!roots) { free(root_name); close(fd); free(canonical); return -1; }
  m->roots = roots;
  size_t index = m->root_count++;
  m->roots[index] = (struct hp_root){ .name = root_name, .path = canonical, .fd = fd };
  int seen = hp_snapshot_root_seen(m->store, canonical);
  int result = watch_tree(m, index, "", seen ? 2 : 1);
  if (seen && hp_snapshot_reconcile_deleted(m->store, fd, canonical)) result = -1;
  if (!result) result = hp_snapshot_mark_root(m->store, canonical);
  m->roots[index].incomplete = !!result;
  m->roots[index].retry_after = time(NULL) + 60;
  return result;
}

int hp_monitor_add_log(struct hp_monitor *m, const char *path) {
  if (m->log_count == SIZE_MAX / sizeof(*m->logs)) return -1;
  struct hp_log *logs = realloc(m->logs, (m->log_count + 1) * sizeof(*logs));
  if (!logs) return -1;
  m->logs = logs;
  m->logs[m->log_count] = (struct hp_log){ .path = strdup(path) };
  if (!m->logs[m->log_count].path) return -1;
  m->log_count++;
  return 0;
}

static int poll_logs(struct hp_monitor *m) {
  int failed = 0;
  for (size_t i = 0; i < m->log_count; i++) {
    struct hp_log *log = &m->logs[i];
    int fd = hp_open_absolute(log->path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
      if (!log->seen) {
        if (hp_report_simple(m->store, "log", "source_unavailable", log->path, "missing_or_inaccessible_log", NULL, 0))
          failed = 1;
        else log->seen = 1;
      }
      continue;
    }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); failed = 1; continue; }
    if (!log->seen) {
      log->offset = st.st_size;
      log->seen = 1;
    } else if (log->device != st.st_dev || log->inode != st.st_ino) {
      if (log->partial_size &&
          hp_report_simple(m->store, "log", "append", log->path, "partial_record_at_rotation", log->partial, log->partial_size)) {
        close(fd); failed = 1; continue;
      }
      if (log->partial) explicit_bzero(log->partial, log->partial_size);
      log->partial_size = 0;
      if (hp_report_simple(m->store, "log", "rotation", log->path, "possible_log_gap", NULL, 0)) {
        close(fd); failed = 1; continue;
      }
      log->offset = 0;
    } else if (st.st_size < log->offset) {
      if (log->partial_size &&
          hp_report_simple(m->store, "log", "append", log->path, "partial_record_at_truncation", log->partial, log->partial_size)) {
        close(fd); failed = 1; continue;
      }
      if (log->partial) explicit_bzero(log->partial, log->partial_size);
      log->partial_size = 0;
      if (hp_report_simple(m->store, "log", "truncation", log->path, "possible_log_gap", NULL, 0)) {
        close(fd); failed = 1; continue;
      }
      log->offset = 0;
    }
    log->device = st.st_dev; log->inode = st.st_ino;
    if (lseek(fd, log->offset, SEEK_SET) < 0) { close(fd); failed = 1; continue; }
    if (!log->partial) log->partial = malloc(65536);
    if (!log->partial) { close(fd); failed = 1; continue; }
    unsigned char buffer[65536];
    int stop = 0;
    size_t budget = 1048576;
    while (!stop && budget && log->offset < st.st_size) {
      size_t count = st.st_size - log->offset > (off_t)sizeof(buffer) ? sizeof(buffer) : (size_t)(st.st_size - log->offset);
      if (count > budget) count = budget;
      ssize_t n = read(fd, buffer, count);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) { failed = 1; break; }
      budget -= (size_t)n;
      for (size_t pos = 0; pos < (size_t)n;) {
        size_t length = (size_t)n - pos, room = 65536 - log->partial_size;
        if (length > room) length = room;
        const unsigned char *newline = memchr(buffer + pos, '\n', length);
        if (newline) length = (size_t)(newline - buffer - pos) + 1;
        memcpy(log->partial + log->partial_size, buffer + pos, length);
        log->partial_size += length; log->offset += (off_t)length; pos += length;
        if (newline || log->partial_size == 65536) {
          if (hp_report_simple(m->store, "log", "append", log->path,
                               newline ? NULL : "long_record_segment", log->partial, log->partial_size)) {
            log->offset -= (off_t)log->partial_size;
            explicit_bzero(log->partial, log->partial_size); log->partial_size = 0;
            failed = 1; stop = 1; break;
          }
          if (hp_store_record_log(m->store, log->path, log->partial, log->partial_size)) failed = 1;
          explicit_bzero(log->partial, log->partial_size); log->partial_size = 0;
        }
      }
      explicit_bzero(buffer, sizeof(buffer));
    }
    explicit_bzero(buffer, sizeof(buffer));
    if (close(fd)) failed = 1;
  }
  return failed ? -1 : 0;
}

static int under(const char *path, const char *prefix) {
  size_t n = strlen(prefix);
  return !strncmp(path, prefix, n) && (!path[n] || path[n] == '/');
}

static void drop_watches(struct hp_monitor *m, size_t root, const char *relative) {
  for (size_t i = 0; i < m->watch_count;) {
    if (m->watches[i].root != root || !under(m->watches[i].relative, relative)) { i++; continue; }
    inotify_rm_watch(m->inotify_fd, m->watches[i].wd);
    free(m->watches[i].relative);
    m->watches[i] = m->watches[--m->watch_count];
  }
}

static int refresh_roots(struct hp_monitor *m) {
  int failed = 0;
  for (size_t i = 0; i < m->root_count; i++) {
    struct hp_root *root = &m->roots[i];
    int current = open_share_root(root->path);
    struct stat previous_st, current_st;
    int same = root->fd >= 0 && current >= 0 &&
               !fstat(root->fd, &previous_st) && !fstat(current, &current_st) &&
               previous_st.st_dev == current_st.st_dev && previous_st.st_ino == current_st.st_ino;
    if (same) {
      close(current);
      if (root->incomplete && time(NULL) >= root->retry_after) {
        int result = watch_tree(m, i, "", 2);
        if (hp_snapshot_reconcile_deleted(m->store, root->fd, root->path)) result = -1;
        if (!result) result = hp_snapshot_mark_root(m->store, root->path);
        root->incomplete = !!result;
        root->retry_after = time(NULL) + 60;
        if (result) failed = -1;
      }
      continue;
    }
    if (root->fd >= 0) {
      if (hp_report_simple(m->store, "monitor", "observation_gap", root->path,
                           "share_root_replaced_or_removed", NULL, 0)) failed = -1;
      drop_watches(m, i, "");
      close(root->fd);
      root->fd = -1;
    }
    if (current < 0) {
      if (!root->unavailable_reported) {
        if (hp_report_simple(m->store, "share", "source_unavailable", root->path,
                             "share_root_missing_or_inaccessible", NULL, 0)) failed = -1;
        else root->unavailable_reported = 1;
      }
      continue;
    }
    root->fd = current;
    root->unavailable_reported = 0;
    int result = watch_tree(m, i, "", 2);
    if (hp_snapshot_reconcile_deleted(m->store, current, root->path)) result = -1;
    root->incomplete = !!result;
    root->retry_after = time(NULL) + 60;
    if (result) failed = -1;
  }
  return failed;
}

static int finish_move(struct hp_monitor *m, struct hp_move *move) {
  struct hp_root *root = &m->roots[move->root];
  int result;
  if (move->is_dir) {
    drop_watches(m, move->root, move->relative);
    result = hp_snapshot_reconcile_deleted(m->store, root->fd, root->path);
  } else result = hp_snapshot_event(m->store, root->fd, root->path, move->relative, "delete");
  if (result) { root->incomplete = 1; root->retry_after = 0; return -1; }
  free(move->relative);
  memset(move, 0, sizeof(*move));
  return 0;
}

static int remember_move(struct hp_monitor *m, unsigned cookie, size_t root,
                          const char *relative, int is_dir) {
  if (!cookie) {
    struct hp_move move = { .root = root, .relative = strdup(relative), .is_dir = is_dir };
    if (!move.relative) return -1;
    int result = finish_move(m, &move);
    free(move.relative);
    return result;
  }
  struct hp_move *slot = NULL;
  for (size_t i = 0; i < 128; i++) if (!m->moves[i].relative) { slot = &m->moves[i]; break; }
  if (!slot) {
    slot = &m->moves[0];
    for (size_t i = 1; i < 128; i++) if (m->moves[i].when < slot->when) slot = &m->moves[i];
    if (finish_move(m, slot)) return -1;
    hp_report_simple(m->store, "monitor", "observation_gap", relative, "rename_cookie_capacity", NULL, 0);
  }
  *slot = (struct hp_move){ .cookie = cookie, .root = root,
                            .relative = strdup(relative), .is_dir = is_dir, .when = time(NULL) };
  return slot->relative ? 0 : -1;
}

static int pair_move(struct hp_monitor *m, unsigned cookie, size_t new_root,
                     const char *new_relative, int is_dir) {
  if (!cookie) return 0;
  for (size_t i = 0; i < 128; i++) {
    struct hp_move *move = &m->moves[i];
    if (!move->relative || move->cookie != cookie) continue;
    struct hp_root *old_root = &m->roots[move->root], *target = &m->roots[new_root];
    int had_target = !is_dir && hp_snapshot_has(m->store, target->path, new_relative);
    if (had_target) {
      if (hp_snapshot_event(m->store, target->fd, target->path, new_relative, "rename_overwrite") ||
          hp_snapshot_event(m->store, old_root->fd, old_root->path, move->relative, "delete")) {
        hp_report_simple(m->store, "monitor", "observation_gap", new_relative,
                         "rename_overwrite_diff_failed", NULL, 0);
        free(move->relative);
        memset(move, 0, sizeof(*move));
        return 1;
      }
    }
    char old_full[8192], new_full[8192];
    if (snprintf(old_full, sizeof(old_full), "%s/%s", old_root->path, move->relative) < (int)sizeof(old_full) &&
        snprintf(new_full, sizeof(new_full), "%s/%s", target->path, new_relative) < (int)sizeof(new_full)) {
      if (hp_snapshot_rename(m->store, old_full, new_full))
        hp_report_simple(m->store, "monitor", "observation_gap", new_full, "rename_state_failed", NULL, 0);
    }
    if (is_dir && move->is_dir) {
      size_t old_len = strlen(move->relative);
      for (size_t j = 0; j < m->watch_count; j++) {
        struct hp_watch *watch = &m->watches[j];
        if (watch->root != move->root || !under(watch->relative, move->relative)) continue;
        char next[8192];
        if (snprintf(next, sizeof(next), "%s%s", new_relative, watch->relative + old_len) >= (int)sizeof(next)) continue;
        char *replacement = strdup(next);
        if (!replacement) {
          target->incomplete = 1; target->retry_after = 0;
          hp_report_simple(m->store, "monitor", "observation_gap", next, "rename_allocation_failed", NULL, 0);
          continue;
        }
        free(watch->relative);
        watch->relative = replacement;
        watch->root = new_root;
      }
      watch_tree(m, new_root, new_relative, 2);
    } else hp_snapshot_event(m->store, target->fd, target->path, new_relative, "reconcile");
    free(move->relative);
    memset(move, 0, sizeof(*move));
    return 1;
  }
  return 0;
}

static int created_match(struct hp_monitor *m, size_t root, const char *relative, int remove) {
  for (size_t i = 0; i < 128; i++)
    if (m->created[i].relative && m->created[i].root == root &&
        !strcmp(m->created[i].relative, relative)) {
      if (remove) { free(m->created[i].relative); memset(&m->created[i], 0, sizeof(m->created[i])); }
      return 1;
    }
  return 0;
}

static int remember_create(struct hp_monitor *m, size_t root, const char *relative) {
  if (created_match(m, root, relative, 0)) return 0;
  struct hp_created *slot = NULL;
  for (size_t i = 0; i < 128; i++) if (!m->created[i].relative) { slot = &m->created[i]; break; }
  if (!slot) {
    hp_report_simple(m->store, "monitor", "observation_gap", relative, "create_queue_capacity", NULL, 0);
    return hp_snapshot_event(m->store, m->roots[root].fd, m->roots[root].path, relative, "create");
  }
  *slot = (struct hp_created){ .root = root, .relative = strdup(relative), .when = time(NULL) };
  return slot->relative ? 0 : -1;
}

int hp_monitor_poll(struct hp_monitor *m, int timeout_ms) {
  int failed = refresh_roots(m);
  struct pollfd p = { .fd = m->inotify_fd, .events = POLLIN };
  int ready = poll(&p, 1, timeout_ms);
  if (ready < 0 && errno != EINTR) return -1;
  if (poll_logs(m)) failed = -1;
  if (ready > 0 && (p.revents & POLLIN)) {
    unsigned char buf[65536];
    ssize_t n;
    // One read per poll: a client that creates files faster than we process them
    // must not keep us here forever. Leftover events make poll() return at once.
    if ((n = read(m->inotify_fd, buf, sizeof(buf))) > 0) {
      for (size_t pos = 0; pos < (size_t)n;) {
        struct inotify_event *event = (struct inotify_event *)(buf + pos);
        pos += sizeof(*event) + event->len;
        if (event->mask & IN_Q_OVERFLOW) {
          if (hp_report_simple(m->store, "monitor", "observation_gap", "", "inotify_overflow", NULL, 0)) failed = -1;
          for (size_t i = 0; i < m->root_count; i++) {
            if (watch_tree(m, i, "", 2)) failed = -1;
            if (m->roots[i].fd >= 0 && hp_snapshot_reconcile_deleted(m->store, m->roots[i].fd, m->roots[i].path)) failed = -1;
          }
          continue;
        }
        struct hp_watch *watch = NULL;
        for (size_t i = 0; i < m->watch_count; i++) if (m->watches[i].wd == event->wd) { watch = &m->watches[i]; break; }
        if (!watch || !event->len) continue;
        char rel[8192];
        if (snprintf(rel, sizeof(rel), "%s%s%s", watch->relative, *watch->relative ? "/" : "", event->name) >= (int)sizeof(rel)) {
          if (hp_report_simple(m->store, "monitor", "observation_gap", "", "path_too_long", NULL, 0)) failed = -1;
          continue;
        }
        struct hp_root *root = &m->roots[watch->root];
        if (ignored(m, root->path, rel)) continue;
        if (event->mask & IN_MOVED_FROM) {
          created_match(m, watch->root, rel, 1);
          if (remember_move(m, event->cookie, watch->root, rel, !!(event->mask & IN_ISDIR))) failed = -1;
          continue;
        }
        if (event->mask & IN_MOVED_TO) {
          if (pair_move(m, event->cookie, watch->root, rel, !!(event->mask & IN_ISDIR))) continue;
        }
        if (event->mask & IN_ISDIR) {
          if ((event->mask & (IN_CREATE | IN_MOVED_TO)) && watch_tree(m, watch->root, rel, 0)) failed = -1;
          if (event->mask & IN_DELETE) drop_watches(m, watch->root, rel);
          continue;
        }
        if (event->mask & IN_CREATE) {
          if (remember_create(m, watch->root, rel)) failed = -1;
          continue;
        }
        if (event->mask & IN_DELETE) {
          if (created_match(m, watch->root, rel, 1))
            failed |= hp_report_simple(m->store, "share", "create_delete", rel, "contents_unavailable", NULL, 0);
          else failed |= hp_snapshot_event(m->store, root->fd, root->path, rel, "delete");
        } else if ((event->mask & IN_ATTRIB) && created_match(m, watch->root, rel, 0)) {
          continue;
        } else if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_ATTRIB)) {
          int created = created_match(m, watch->root, rel, 0);
          int result = hp_snapshot_event(m->store, root->fd, root->path, rel,
                                         event->mask & IN_MOVED_TO ? "create" :
                                         event->mask & IN_ATTRIB ? "metadata" :
                                         created ? "create" : "modify");
          if (result) failed = -1;
          else if (created) created_match(m, watch->root, rel, 1);
        }
      }
    }
    if (n < 0 && errno != EAGAIN) return -1;
  }
  for (size_t i = 0; i < 128; i++)
    if (m->moves[i].relative && time(NULL) - m->moves[i].when >= 1 && finish_move(m, &m->moves[i])) failed = -1;
  for (size_t i = 0; i < 128; i++)
    if (m->created[i].relative && time(NULL) - m->created[i].when >= 1) {
      struct hp_created *created = &m->created[i];
      struct hp_root *root = &m->roots[created->root];
      if (hp_snapshot_event(m->store, root->fd, root->path, created->relative, "create")) {
        failed = -1;
        created->when = time(NULL) + 4;
      }
      else { free(created->relative); memset(created, 0, sizeof(*created)); }
    }
  return failed ? -1 : 0;
}

void hp_monitor_close(struct hp_monitor *m) {
  if (m->inotify_fd >= 0) close(m->inotify_fd);
  for (size_t i = 0; i < m->watch_count; i++) free(m->watches[i].relative);
  free(m->watches);
  for (size_t i = 0; i < m->root_count; i++) {
    if (m->roots[i].fd >= 0) close(m->roots[i].fd);
    free(m->roots[i].name); free(m->roots[i].path);
  }
  free(m->roots);
  for (size_t i = 0; i < m->log_count; i++) {
    free(m->logs[i].path);
    if (m->logs[i].partial) explicit_bzero(m->logs[i].partial, 65536);
    free(m->logs[i].partial);
  }
  free(m->logs);
  for (size_t i = 0; i < 128; i++) free(m->moves[i].relative);
  for (size_t i = 0; i < 128; i++) free(m->created[i].relative);
  explicit_bzero(m, sizeof(*m));
}
