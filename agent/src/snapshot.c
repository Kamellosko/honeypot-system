#define _GNU_SOURCE
#include "snapshot.h"
#include "protocol.h"
#include "network.h"
#include "diff.h"
#include "io.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>

#define BLOCK 65536
#define TEXT_MAX 1048576
#define CAPTURE_MAX (64LL * 1024 * 1024)   /* largest file we copy into a snapshot */
#define BLOCKS_MAX (16LL * 1024 * 1024)    /* raw bytes of changed blocks in one report */
#define PENDING_MAX 10000                  /* queued reports; more are dropped (observation_gap) */

static void write_evidence(FILE *out, const struct hp_store *s, const char *path, const char *previous_path);

struct hp_observed {
  mode_t mode;
  uid_t uid;
  gid_t gid;
  time_t mtime_sec;
  long mtime_nsec;
  char sha[65];
};

static void hex_hash(const unsigned char *data, size_t n, char out[65]) {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  static const char hex[] = "0123456789abcdef";
  SHA256(data, n, digest);
  for (size_t i = 0; i < sizeof(digest); i++) {
    out[i * 2] = hex[digest[i] >> 4];
    out[i * 2 + 1] = hex[digest[i] & 15];
  }
  out[64] = 0;
  explicit_bzero(digest, sizeof(digest));
}

static int digest_fd(int fd, char out[65]) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned char buf[BLOCK], digest[EVP_MAX_MD_SIZE];
  unsigned len = 0;
  int result = -1;
  if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 || lseek(fd, 0, SEEK_SET) < 0) goto done;
  for (;;) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) { if (errno == EINTR) continue; goto done; }
    if (!n) break;
    if (EVP_DigestUpdate(ctx, buf, (size_t)n) != 1) goto done;
    explicit_bzero(buf, sizeof(buf));
  }
  if (EVP_DigestFinal_ex(ctx, digest, &len) != 1 || len != SHA256_DIGEST_LENGTH) goto done;
  static const char hex[] = "0123456789abcdef";
  for (unsigned i = 0; i < len; i++) { out[i * 2] = hex[digest[i] >> 4]; out[i * 2 + 1] = hex[digest[i] & 15]; }
  out[len * 2] = 0;
  result = 0;
done:
  explicit_bzero(buf, sizeof(buf));
  explicit_bzero(digest, sizeof(digest));
  EVP_MD_CTX_free(ctx);
  return result;
}

int hp_store_init(struct hp_store *s, const char *path, const char *id) {
  memset(s, 0, sizeof(*s));
  s->snapshots_fd = s->pending_fd = -1;
  int parent = -1, root = -1;
  char *copy = path && path[0] == '/' ? strdup(path) : NULL;
  if (!copy) return -1;
  size_t length = strlen(copy);
  while (length > 1 && copy[length - 1] == '/') copy[--length] = 0;
  char *name = strrchr(copy, '/');
  if (!name || !name[1]) goto error;
  *name++ = 0;
  parent = hp_open_absolute(*copy ? copy : "/", O_RDONLY | O_DIRECTORY);
  if (parent < 0) goto error;
  root = hp_private_directory(parent, name);
  if (root < 0 || hp_sync(parent)) goto error;
  char descriptor[64], canonical[4096];
  snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", root);
  ssize_t n = readlink(descriptor, canonical, sizeof(canonical) - 1);
  if (n < 0 || n == sizeof(canonical) - 1) goto error;
  canonical[n] = 0;
  s->path = strdup(canonical); s->id = strdup(id);
  if (!s->path || !s->id) goto error;
  s->snapshots_fd = hp_private_directory(root, "snapshots");
  s->pending_fd = hp_private_directory(root, "pending");
  if (s->snapshots_fd < 0 || s->pending_fd < 0 || hp_sync(root)) goto error;
  close(root); close(parent); free(copy);
  return 0;
error:
  if (root >= 0) close(root);
  if (parent >= 0) close(parent);
  free(copy); hp_store_close(s);
  return -1;
}

void hp_store_close(struct hp_store *s) {
  if (s->snapshots_fd >= 0) close(s->snapshots_fd);
  if (s->pending_fd >= 0) close(s->pending_fd);
  if (s->path) explicit_bzero(s->path, strlen(s->path));
  if (s->id) explicit_bzero(s->id, strlen(s->id));
  free(s->path); free(s->id);
  for (size_t i = 0; i < 32; i++) {
    if (s->recent[i].content) explicit_bzero(s->recent[i].content, s->recent[i].size);
    if (s->recent[i].source) explicit_bzero(s->recent[i].source, strlen(s->recent[i].source));
    free(s->recent[i].source); free(s->recent[i].content);
  }
  explicit_bzero(s, sizeof(*s));
  s->snapshots_fd = s->pending_fd = -1;
}

int hp_store_record_log(struct hp_store *s, const char *source,
                         const unsigned char *content, size_t size) {
  char *name = strdup(source);
  unsigned char *bytes = malloc(size ? size : 1);
  time_t captured_at = time(NULL);
  if (!name || !bytes || captured_at == (time_t)-1) {
    if (name) explicit_bzero(name, strlen(name));
    free(name); free(bytes); return -1;
  }
  if (size) memcpy(bytes, content, size);
  struct hp_evidence *e = &s->recent[s->recent_next++ % 32];
  if (e->content) explicit_bzero(e->content, e->size);
  if (e->source) explicit_bzero(e->source, strlen(e->source));
  free(e->source); free(e->content);
  *e = (struct hp_evidence){ .source = name, .content = bytes, .size = size, .captured_at = captured_at };
  return 0;
}

int hp_store_pending_count(const struct hp_store *s) {
  int fd = openat(s->pending_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC), count = 0;
  if (fd < 0) return -1;
  DIR *dir = fdopendir(fd);
  if (!dir) { close(fd); return -1; }
  struct dirent *ent;
  for (;;) {
    errno = 0;
    ent = readdir(dir);
    if (!ent) { if (errno) count = -1; break; }
    if (strstr(ent->d_name, ".json")) {
      if (count == INT_MAX) { count = -1; break; }
      count++;
    }
  }
  if (closedir(dir)) count = -1;
  return count;
}

static int open_rooted(int root, const char *relative) {
  return hp_open_beneath(root, relative, O_RDONLY | O_NONBLOCK, 0);
}

static void root_marker(const char *root_path, char name[80]) {
  char key[65];
  hex_hash((const unsigned char *)root_path, strlen(root_path), key);
  snprintf(name, 80, "root-%.64s", key);
}

int hp_snapshot_root_seen(struct hp_store *s, const char *root_path) {
  char name[80];
  root_marker(root_path, name);
  struct stat st;
  return fstatat(s->snapshots_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0;
}

int hp_snapshot_mark_root(struct hp_store *s, const char *root_path) {
  char name[80];
  root_marker(root_path, name);
  int fd = hp_private_file(s->snapshots_fd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    if (errno != EEXIST) return -1;
    fd = hp_private_file(s->snapshots_fd, name, O_RDONLY, 0);
    return fd < 0 ? -1 : close(fd);
  }
  int result = hp_sync(fd);
  close(fd);
  return result || hp_sync(s->snapshots_fd) ? -1 : 0;
}

static int store_path(struct hp_store *s, const char *key, const char *full) {
  char name[80];
  snprintf(name, sizeof(name), "%.64s.path", key);
  int fd = hp_private_file(s->snapshots_fd, name, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) {
    if (errno != EEXIST) return -1;
    fd = hp_private_file(s->snapshots_fd, name, O_RDONLY, 0);
    return fd < 0 ? -1 : close(fd);
  }
  size_t len = strlen(full);
  int result = hp_write_all(fd, full, len) || hp_sync(fd);
  if (close(fd)) result = 1;
  if (result) { unlinkat(s->snapshots_fd, name, 0); return -1; }
  return hp_sync(s->snapshots_fd);
}

int hp_snapshot_has(struct hp_store *s, const char *root_path, const char *relative) {
  char full[8192], key[65];
  if (snprintf(full, sizeof(full), "%s/%s", root_path, relative) >= (int)sizeof(full)) return 0;
  hex_hash((const unsigned char *)full, strlen(full), key);
  struct stat st;
  return !fstatat(s->snapshots_fd, key, &st, AT_SYMLINK_NOFOLLOW) && S_ISREG(st.st_mode);
}

static int load_observed(struct hp_store *s, const char *key, const char *sha,
                         struct hp_observed *observed) {
  char name[80];
  snprintf(name, sizeof(name), "%.64s.stat", key);
  int fd = hp_private_file(s->snapshots_fd, name, O_RDONLY, 0);
  if (fd < 0) return -1;
  ssize_t n = read(fd, observed, sizeof(*observed));
  close(fd);
  return n == sizeof(*observed) && !memcmp(observed->sha, sha, sizeof(observed->sha)) ? 0 : -1;
}

static int save_observed(struct hp_store *s, const char *key,
                         const struct hp_observed *observed, const char *nonce) {
  char name[80], tmp[80];
  snprintf(name, sizeof(name), "%.64s.stat", key);
  snprintf(tmp, sizeof(tmp), ".%.32s.%.16s.stat.tmp", key, nonce);
  int fd = hp_private_file(s->snapshots_fd, tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) return -1;
  int failed = hp_write_all(fd, observed, sizeof(*observed)) || hp_sync(fd);
  if (close(fd)) failed = 1;
  if (failed || renameat(s->snapshots_fd, tmp, s->snapshots_fd, name) || hp_sync(s->snapshots_fd)) {
    unlinkat(s->snapshots_fd, tmp, 0); return -1;
  }
  return 0;
}

int hp_snapshot_reconcile_deleted(struct hp_store *s, int root_fd, const char *root_path) {
  int fd = openat(s->snapshots_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return -1;
  DIR *dir = fdopendir(fd);
  if (!dir) { close(fd); return -1; }
  size_t prefix = strlen(root_path);
  int result = 0;
  struct dirent *ent;
  for (;;) {
    errno = 0;
    ent = readdir(dir);
    if (!ent) { if (errno) result = -1; break; }
    size_t n = strlen(ent->d_name);
    if (n != 69 || strcmp(ent->d_name + 64, ".path")) continue;
    int path_fd = hp_private_file(s->snapshots_fd, ent->d_name, O_RDONLY, 0);
    if (path_fd < 0) { result = -1; continue; }
    char full[8192];
    ssize_t bytes = read(path_fd, full, sizeof(full) - 1);
    close(path_fd);
    if (bytes < 0) { result = -1; continue; }
    if ((size_t)bytes <= prefix + 1) continue;
    full[bytes] = 0;
    if (strncmp(full, root_path, prefix) || full[prefix] != '/') continue;
    const char *relative = full + prefix + 1;
    int current = open_rooted(root_fd, relative);
    if (current >= 0) { close(current); continue; }
    if (errno == ENOENT || errno == ELOOP)
      result |= hp_snapshot_event(s, root_fd, root_path, relative, "delete_during_downtime");
    else result |= hp_report_simple(s, "share", "observation_gap", full, "reconcile_access_failed", NULL, 0);
  }
  if (closedir(dir)) result = -1;
  return result ? -1 : 0;
}

static int same_stat(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_size == b->st_size &&
         a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
         a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int capture(int root, const char *relative, int dst, struct stat *result) {
  unsigned char buf[BLOCK];
  for (int attempt = 0; attempt < 3; attempt++) {
    int src = open_rooted(root, relative);
    if (src < 0) return -1;
    struct stat before, after;
    if (fstat(src, &before) || !S_ISREG(before.st_mode) || ftruncate(dst, 0) || lseek(dst, 0, SEEK_SET) < 0) { close(src); return -1; }
    if (before.st_size > CAPTURE_MAX) { close(src); errno = EFBIG; return -1; }
    long long copied = 0;
    int okay = 1;
    for (;;) {
      ssize_t n = read(src, buf, sizeof(buf));
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) { okay = 0; break; }
      if (!n) break;
      copied += n;
      if (copied > CAPTURE_MAX) { okay = 0; errno = EFBIG; break; }   /* file grew while copying */
      if (hp_write_all(dst, buf, (size_t)n)) okay = 0;
      explicit_bzero(buf, sizeof(buf));
      if (!okay) break;
    }
    explicit_bzero(buf, sizeof(buf));
    if (fstat(src, &after)) okay = 0;
    close(src);
    if (!okay) return -1;
    int current = open_rooted(root, relative);
    struct stat at_path;
    if (current >= 0 && fstat(current, &at_path) == 0 &&
        same_stat(&before, &after) && same_stat(&after, &at_path)) {
      close(current); *result = after; return hp_sync(dst);
    }
    if (current >= 0) close(current);
  }
  errno = EAGAIN;
  return -1;
}

static void json_path(FILE *out, const char *path) {
  size_t n = strlen(path);
  if (hp_valid_utf8((const unsigned char *)path, n)) {
    fputs("\"path\":", out); hp_json_string(out, (const unsigned char *)path, n);
  } else {
    fputs("\"path\":null,\"path_base64\":", out);
    hp_json_base64(out, (const unsigned char *)path, n);
  }
}

static FILE *report_begin(struct hp_store *s, const char *source, const char *operation,
                          const char *path, char filename[80]) {
  char id[65], utc[32], tmp[80];
  if (hp_store_pending_count(s) > PENDING_MAX) return NULL;   /* server unreachable for a long time */
  if (hp_report_id(id) || hp_utc_time(utc)) return NULL;
  snprintf(filename, 80, "%s.json", id);
  snprintf(tmp, 80, ".%s.tmp", id);
  int fd = hp_private_file(s->pending_fd, tmp, O_CREAT | O_EXCL | O_WRONLY, 0600);
  if (fd < 0) return NULL;
  FILE *out = fdopen(fd, "w");
  if (!out) { close(fd); unlinkat(s->pending_fd, tmp, 0); return NULL; }
  if (setvbuf(out, s->report_buffer, _IOFBF, sizeof(s->report_buffer))) {
    fclose(out); unlinkat(s->pending_fd, tmp, 0); return NULL;
  }
  fprintf(out, "{\"schema_version\":1,\"report_id\":\"%s\",\"agent_id\":", id);
  hp_json_string(out, (const unsigned char *)s->id, strlen(s->id));
  fprintf(out, ",\"observed_at\":\"%s\",\"source\":", utc);
  hp_json_string(out, (const unsigned char *)source, strlen(source));
  fputs(",\"operation\":", out); hp_json_string(out, (const unsigned char *)operation, strlen(operation));
  fputc(',', out); json_path(out, path);
  return out;
}

static int report_end(struct hp_store *s, FILE *out, const char *filename) {
  char tmp[80];
  snprintf(tmp, sizeof(tmp), ".%.64s.tmp", filename);
  int fd = fileno(out);
  if (ferror(out) || fputc('}', out) == EOF || fflush(out) || hp_sync(fd)) {
    fclose(out); explicit_bzero(s->report_buffer, sizeof(s->report_buffer));
    unlinkat(s->pending_fd, tmp, 0); return -1;
  }
  int close_failed = fclose(out);
  explicit_bzero(s->report_buffer, sizeof(s->report_buffer));
  if (close_failed || renameat2(s->pending_fd, tmp, s->pending_fd, filename, RENAME_NOREPLACE) || hp_sync(s->pending_fd)) {
    unlinkat(s->pending_fd, tmp, 0); return -1;
  }
  return 0;
}

static void report_abort(struct hp_store *s, FILE *out, const char *filename) {
  char tmp[80];
  snprintf(tmp, sizeof(tmp), ".%.64s.tmp", filename);
  fclose(out);
  explicit_bzero(s->report_buffer, sizeof(s->report_buffer));
  unlinkat(s->pending_fd, tmp, 0);
}

int hp_report_simple(struct hp_store *s, const char *source, const char *operation,
                     const char *path, const char *error, const unsigned char *content,
                     size_t content_size) {
  char filename[80];
  FILE *out = report_begin(s, source, operation, path, filename);
  if (!out) return -1;
  const char *classification = "unknown";
  if (content && (memmem(content, content_size, "Failed password", 15) ||
                  memmem(content, content_size, "NT_STATUS_LOGON_FAILURE", 23)))
    classification = "authentication_failure";
  else if (content && memmem(content, content_size, "smbd_audit:", 11))
    classification = "samba_audit";
  fprintf(out, ",\"metadata\":{},\"analysis\":{\"classification\":\"%s\"}", classification);
  if (content) {
    fputs(",\"network_context\":", out);
    hp_write_network_context(out, content, content_size);
  }
  fputs(",\"evidence\":", out);
  if (strcmp(source, "log") && *path) write_evidence(out, s, path, NULL);
  else fputs("[]", out);
  fputs(",\"content_changes\":null,\"complete\":", out);
  fputs(error ? "false" : "true", out);
  fputs(",\"error\":", out);
  if (error) hp_json_string(out, (const unsigned char *)error, strlen(error)); else fputs("null", out);
  if (content) {
    fputs(",\"content\":", out);
    if (hp_valid_utf8(content, content_size)) hp_json_string(out, content, content_size);
    else { fputs("null,\"content_base64\":", out); hp_json_base64(out, content, content_size); }
  }
  return report_end(s, out, filename);
}

int hp_report_connection(struct hp_store *s, const char *local_ip, unsigned short local_port,
                          const char *peer_ip, unsigned short peer_port) {
  char filename[80];
  FILE *out = report_begin(s, "network", "tcp_connection_observed", "", filename);
  if (!out) return -1;
  fputs(",\"metadata\":{},\"analysis\":{\"classification\":\"tcp_connection\",\"actor\":null},"
        "\"evidence\":[],\"content_changes\":null,\"complete\":true,\"error\":null,\"connection\":{"
        "\"protocol\":\"tcp\",\"state\":\"ESTABLISHED\",\"direction\":\"inbound_listener_match\","
        "\"observation_method\":\"inet_diag_poll\",\"local_ip\":", out);
  hp_json_string(out, (const unsigned char *)local_ip, strlen(local_ip));
  fprintf(out, ",\"local_port\":%hu,\"peer_port\":%hu,\"peer\":", local_port, peer_port);
  hp_write_endpoint(out, peer_ip);
  fputc('}', out);
  return report_end(s, out, filename);
}

int hp_snapshot_rename(struct hp_store *s, const char *old_path, const char *new_path) {
  char filename[80];
  FILE *out = report_begin(s, "share", "rename", new_path, filename);
  if (!out) return -1;
  fputs(",\"previous_path\":", out);
  if (hp_valid_utf8((const unsigned char *)old_path, strlen(old_path)))
    hp_json_string(out, (const unsigned char *)old_path, strlen(old_path));
  else {
    fputs("null,\"previous_path_base64\":", out);
    hp_json_base64(out, (const unsigned char *)old_path, strlen(old_path));
  }
  fputs(",\"metadata\":{},\"analysis\":{\"classification\":\"rename\",\"actor\":null},\"evidence\":", out);
  write_evidence(out, s, new_path, old_path);
  fputs(",\"content_changes\":null,\"complete\":true,\"error\":null", out);
  if (report_end(s, out, filename)) return -1;
  int fd = openat(s->snapshots_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) return -1;
  DIR *dir = fdopendir(fd);
  if (!dir) { close(fd); return -1; }
  struct dirent *ent;
  size_t prefix = strlen(old_path);
  int result = 0;
  for (;;) {
    errno = 0;
    ent = readdir(dir);
    if (!ent) { if (errno) result = -1; break; }
    size_t n = strlen(ent->d_name);
    if (n != 69 || strcmp(ent->d_name + 64, ".path")) continue;
    int path_fd = hp_private_file(s->snapshots_fd, ent->d_name, O_RDONLY, 0);
    if (path_fd < 0) { result = -1; continue; }
    char full[8192], next[8192], old_key[65], new_key[65], old_stat[80], new_stat[80];
    ssize_t bytes = read(path_fd, full, sizeof(full) - 1);
    close(path_fd);
    if (bytes < 0) { result = -1; continue; }
    if ((size_t)bytes < prefix) continue;
    full[bytes] = 0;
    if (strncmp(full, old_path, prefix) || (full[prefix] && full[prefix] != '/')) continue;
    if (snprintf(next, sizeof(next), "%s%s", new_path, full + prefix) >= (int)sizeof(next)) { result = -1; continue; }
    hex_hash((const unsigned char *)full, strlen(full), old_key);
    hex_hash((const unsigned char *)next, strlen(next), new_key);
    if (store_path(s, new_key, next)) { result = -1; continue; }
    snprintf(old_stat, sizeof(old_stat), "%.64s.stat", old_key);
    snprintf(new_stat, sizeof(new_stat), "%.64s.stat", new_key);
    if (renameat(s->snapshots_fd, old_key, s->snapshots_fd, new_key) ||
        renameat(s->snapshots_fd, old_stat, s->snapshots_fd, new_stat)) {
      result = -1; continue;
    }
    if (unlinkat(s->snapshots_fd, ent->d_name, 0)) result = -1;
  }
  if (closedir(dir)) result = -1;
  if (hp_sync(s->snapshots_fd)) result = -1;
  return result;
}

static void write_evidence(FILE *out, const struct hp_store *s, const char *path, const char *previous_path) {
  const char *base = strrchr(path, '/');
  base = base ? base + 1 : path;
  size_t name_len = strlen(base);
  const char *previous = previous_path ? strrchr(previous_path, '/') : NULL;
  previous = previous ? previous + 1 : previous_path;
  size_t previous_len = previous ? strlen(previous) : 0;
  int first = 1;
  fputc('[', out);
  for (size_t i = 0; i < 32; i++) {
    const struct hp_evidence *e = &s->recent[i];
    if (!e->content || time(NULL) - e->captured_at > 60 ||
        ((!name_len || !memmem(e->content, e->size, base, name_len)) &&
         (!previous_len || !memmem(e->content, e->size, previous, previous_len)))) continue;
    if (!first) fputc(',', out);
    first = 0;
    fputs("{\"source\":", out);
    if (hp_valid_utf8((const unsigned char *)e->source, strlen(e->source)))
      hp_json_string(out, (const unsigned char *)e->source, strlen(e->source));
    else { fputs("null,\"source_base64\":", out); hp_json_base64(out, (const unsigned char *)e->source, strlen(e->source)); }
    fputs(",\"context_only\":true,\"content\":", out);
    if (hp_valid_utf8(e->content, e->size)) hp_json_string(out, e->content, e->size);
    else { fputs("null,\"content_base64\":", out); hp_json_base64(out, e->content, e->size); }
    fputs(",\"network_context\":", out);
    hp_write_network_context(out, e->content, e->size);
    fputc('}', out);
  }
  fputc(']', out);
}

static ssize_t read_block(int fd, unsigned char *buf) {
  if (fd < 0) return 0;
  size_t used = 0;
  while (used < BLOCK) {
    ssize_t n = read(fd, buf + used, BLOCK - used);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) return -1;
    if (!n) break;
    used += (size_t)n;
  }
  return (ssize_t)used;
}

static int write_blocks(FILE *out, int old_fd, int new_fd) {
  unsigned char a[BLOCK], b[BLOCK];
  off_t offset = 0;
  int first = 1;
  long long total = 0;
  if ((old_fd >= 0 && lseek(old_fd, 0, SEEK_SET) < 0) || (new_fd >= 0 && lseek(new_fd, 0, SEEK_SET) < 0)) return -1;
  fputc('[', out);
  for (;;) {
    ssize_t an = read_block(old_fd, a);
    ssize_t bn = read_block(new_fd, b);
    if (an < 0 || bn < 0) {
      explicit_bzero(a, sizeof(a)); explicit_bzero(b, sizeof(b)); return -1;
    }
    if (!an && !bn) break;
    if (an != bn || memcmp(a, b, (size_t)an)) {
      total += an + bn;
      if (total > BLOCKS_MAX) {   /* report would be too large for the server */
        explicit_bzero(a, sizeof(a)); explicit_bzero(b, sizeof(b)); return -1;
      }
      if (!first) fputc(',', out);
      first = 0;
      fprintf(out, "{\"offset\":%lld,\"old_base64\":", (long long)offset);
      hp_json_base64(out, a, (size_t)an);
      fputs(",\"new_base64\":", out);
      hp_json_base64(out, b, (size_t)bn);
      fputc('}', out);
    }
    explicit_bzero(a, sizeof(a));
    explicit_bzero(b, sizeof(b));
    offset += BLOCK;
  }
  fputc(']', out);
  return 0;
}

int hp_snapshot_event(struct hp_store *s, int root_fd, const char *root_path,
                      const char *relative, const char *operation) {
  char key_input[8192], key[65], tmp[80], report[80], full[8192];
  if (!relative || !*relative || relative[0] == '/' ||
      snprintf(key_input, sizeof(key_input), "%s/%s", root_path, relative) >= (int)sizeof(key_input)) return -1;
  snprintf(full, sizeof(full), "%s", key_input);
  size_t state_len = strlen(s->path);
  if (!strncmp(full, s->path, state_len) && (full[state_len] == '/' || !full[state_len])) return 0;
  hex_hash((const unsigned char *)key_input, strlen(key_input), key);
  int old_fd = hp_private_file(s->snapshots_fd, key, O_RDONLY, 0);
  if (old_fd < 0 && errno != ENOENT) return -1;
  int exists = strncmp(operation, "delete", 6) != 0;
  int new_fd = -1;
  struct stat new_st = {0}, old_st = {0};
  if (old_fd >= 0 && fstat(old_fd, &old_st)) { close(old_fd); return -1; }
  char nonce[65];
  if (hp_report_id(nonce)) goto fail;
  snprintf(tmp, sizeof(tmp), ".%.32s.%.16s.tmp", key, nonce);
  if (exists) {
    new_fd = hp_private_file(s->snapshots_fd, tmp, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (new_fd < 0) goto fail;
    if (capture(root_fd, relative, new_fd, &new_st)) {
      hp_report_simple(s, "share", operation, full, errno == EAGAIN ? "unstable_capture" : "capture_failed", NULL, 0);
      goto fail;
    }
  }
  char old_hash[65] = "", new_hash[65] = "";
  if ((old_fd >= 0 && digest_fd(old_fd, old_hash)) ||
      (new_fd >= 0 && digest_fd(new_fd, new_hash))) goto fail;
  struct hp_observed old_obs = {0}, new_obs = {0};
  int have_old_obs = old_fd >= 0 && !load_observed(s, key, old_hash, &old_obs);
  if (new_fd >= 0) {
    new_obs.mode = new_st.st_mode & 07777;
    new_obs.uid = new_st.st_uid;
    new_obs.gid = new_st.st_gid;
    new_obs.mtime_sec = new_st.st_mtim.tv_sec;
    new_obs.mtime_nsec = new_st.st_mtim.tv_nsec;
    snprintf(new_obs.sha, sizeof(new_obs.sha), "%s", new_hash);
  }
  if (!strcmp(operation, "baseline") && old_fd < 0) {
    if (new_fd >= 0 && !store_path(s, key, full) &&
        renameat(s->snapshots_fd, tmp, s->snapshots_fd, key) == 0 &&
        !hp_sync(s->snapshots_fd) && !save_observed(s, key, &new_obs, nonce)) {
      int failed = hp_sync(s->snapshots_fd);
      if (close(new_fd)) failed = 1;
      return failed ? -1 : 0;
    }
    goto fail;
  }
  int same_metadata = have_old_obs && new_fd >= 0 &&
    old_obs.mode == new_obs.mode && old_obs.uid == new_obs.uid &&
    old_obs.gid == new_obs.gid && old_obs.mtime_sec == new_obs.mtime_sec &&
    old_obs.mtime_nsec == new_obs.mtime_nsec;
  if (old_fd >= 0 && new_fd >= 0 && old_st.st_size == new_st.st_size &&
      !strcmp(old_hash, new_hash) && same_metadata && !strcmp(operation, "baseline")) {
    close(old_fd); close(new_fd); unlinkat(s->snapshots_fd, tmp, 0);
    return 0;
  }
  if (old_fd >= 0 && new_fd >= 0 && old_st.st_size == new_st.st_size &&
      !strcmp(old_hash, new_hash) && same_metadata) {
    close(old_fd); close(new_fd); unlinkat(s->snapshots_fd, tmp, 0);
    return 0;
  }
  const char *reported_operation = !strcmp(operation, "baseline") ? "downtime_change" : operation;
  FILE *out = report_begin(s, "share", reported_operation, full, report);
  if (!out) goto fail;
  fprintf(out, ",\"metadata\":{\"old_size\":%lld,\"new_size\":%lld,\"old_mode\":",
          (long long)old_st.st_size, (long long)new_st.st_size);
  if (have_old_obs) fprintf(out, "%u", (unsigned)old_obs.mode); else fputs("null", out);
  fprintf(out, ",\"new_mode\":%u,\"old_uid\":", (unsigned)new_obs.mode);
  if (have_old_obs) fprintf(out, "%u", (unsigned)old_obs.uid); else fputs("null", out);
  fprintf(out, ",\"new_uid\":%u,\"old_gid\":", (unsigned)new_obs.uid);
  if (have_old_obs) fprintf(out, "%u", (unsigned)old_obs.gid); else fputs("null", out);
  fprintf(out, ",\"new_gid\":%u,\"mtime_sec\":%lld},", (unsigned)new_obs.gid, (long long)new_obs.mtime_sec);
  fputs("\"analysis\":{\"classification\":\"file_change\",\"actor\":null},\"evidence\":", out);
  write_evidence(out, s, full, NULL);
  fputs(",\"content_changes\":{", out);
  fputs("\"old_sha256\":", out);
  if (old_fd >= 0) hp_json_string(out, (unsigned char *)old_hash, strlen(old_hash)); else fputs("null", out);
  fputs(",\"new_sha256\":", out);
  if (new_fd >= 0) hp_json_string(out, (unsigned char *)new_hash, strlen(new_hash)); else fputs("null", out);
  int okay = hp_write_text_diff(out, old_fd, new_fd);
  if (okay == 1) {
    fputs(",\"format\":\"blocks64k\",\"blocks\":", out);
    okay = write_blocks(out, old_fd, new_fd);
  }
  if (okay || ferror(out)) {
    report_abort(s, out, report);
    hp_report_simple(s, "share", operation, full, "diff_failed", NULL, 0);
    goto fail;
  }
  fputs("},\"complete\":", out);
  int complete = (old_fd >= 0 || !strcmp(operation, "create")) &&
                 (old_fd < 0 || have_old_obs);
  fputs(complete && !okay ? "true" : "false", out);
  fputs(",\"error\":", out);
  if (okay) fputs("\"diff_failed\"", out);
  else if (!complete) fputs(old_fd >= 0 ? "\"missing_metadata_baseline\"" : "\"missing_baseline\"", out);
  else fputs("null", out);
  if (report_end(s, out, report)) goto fail;
  if (new_fd >= 0) {
    if (store_path(s, key, full)) goto fail;
    if (renameat(s->snapshots_fd, tmp, s->snapshots_fd, key) || hp_sync(s->snapshots_fd)) goto fail;
    if (save_observed(s, key, &new_obs, nonce)) goto fail;
  } else if (old_fd >= 0) {
    char path_name[80];
    snprintf(path_name, sizeof(path_name), "%.64s.path", key);
    if (unlinkat(s->snapshots_fd, key, 0)) goto fail;
    if (unlinkat(s->snapshots_fd, path_name, 0) && errno != ENOENT) goto fail;
    snprintf(path_name, sizeof(path_name), "%.64s.stat", key);
    if ((unlinkat(s->snapshots_fd, path_name, 0) && errno != ENOENT) || hp_sync(s->snapshots_fd)) goto fail;
  }
  if (old_fd >= 0) close(old_fd);
  if (new_fd >= 0) close(new_fd);
  return 0;
fail:
  if (new_fd >= 0) { close(new_fd); unlinkat(s->snapshots_fd, tmp, 0); }
  if (old_fd >= 0) close(old_fd);
  return -1;
}
