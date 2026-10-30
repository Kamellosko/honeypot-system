#define _GNU_SOURCE
#include "config.h"
#include "io.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <pwd.h>
#include <stdint.h>
#include <strings.h>
#include <time.h>
#include <tdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int add_source(struct hp_sources *out, enum hp_source_kind kind,
                      const char *name, const char *path, const char *error) {
  if (kind == HP_LOG) for (size_t i = 0; i < out->count; i++)
    if (out->items[i].kind == HP_LOG && path && !strcmp(out->items[i].path, path)) return 0;
  if (out->count == SIZE_MAX / sizeof(*out->items)) return -1;
  struct hp_source *p = realloc(out->items, (out->count + 1) * sizeof(*p));
  if (!p) return -1;
  out->items = p;
  p = &out->items[out->count];
  p->kind = kind;
  p->name = strdup(name ? name : "");
  p->path = strdup(path ? path : "");
  p->error = error ? strdup(error) : NULL;
  if (!p->name || !p->path || (error && !p->error)) {
    free(p->name); free(p->path); free(p->error);
    return -1;
  }
  out->count++;
  return 0;
}

void hp_sources_free(struct hp_sources *out) {
  for (size_t i = 0; i < out->count; i++) {
    free(out->items[i].name); free(out->items[i].path); free(out->items[i].error);
  }
  free(out->items);
  memset(out, 0, sizeof(*out));
}

int hp_validate_args(const char *id, const char *ip, const char *port) {
  unsigned char addr[16];
  char *end;
  long n;
  if (!id || !*id || strlen(id) > 64 || !ip || !port || !*port) return -1;
  for (const unsigned char *p = (const unsigned char *)id; *p; p++)
    if (*p < 0x20 || *p > 0x7e) return -1;
  if (inet_pton(AF_INET, ip, addr) != 1 && inet_pton(AF_INET6, ip, addr) != 1) return -1;
  errno = 0;
  n = strtol(port, &end, 10);
  return errno || *end || n < 1 || n > 65535 ? -1 : 0;
}

int hp_parse_args(int argc, char *const argv[], struct hp_options *options) {
  const char *id = AGENT_ID, *ip = DEST_IP, *port;
  char default_port[32];
  unsigned seen = 0;
  snprintf(default_port, sizeof(default_port), "%lld", (long long)DEST_PORT);
  port = default_port;
  if (argc < 1 || !(argc & 1)) return -1;
  for (int i = 1; i < argc; i += 2) {
    unsigned flag;
    if (!strcmp(argv[i], "--id")) { flag = 1; id = argv[i + 1]; }
    else if (!strcmp(argv[i], "--ip")) { flag = 2; ip = argv[i + 1]; }
    else if (!strcmp(argv[i], "--port")) { flag = 4; port = argv[i + 1]; }
    else return -1;
    if (seen & flag) return -1;
    seen |= flag;
  }
  if (hp_validate_args(id, ip, port)) return -1;
  *options = (struct hp_options){ id, ip, (unsigned short)strtoul(port, NULL, 10) };
  return 0;
}

#define CONFIG_LIMIT 1048576
#define ACCOUNT_LIMIT 65536

struct share {
  char name[256], path[4096];
  int enabled, printer;
};
struct parser {
  struct share *shares;
  size_t count, current, bytes;
  struct share defaults;
  char backend[4096], private_dir[4096], password_file[4096], log_pattern[4096];
  const char *error;
};
struct users { char **names; size_t count, capacity; };
static int log_archive(const char *name);

static char *trim(char *s) {
  while (isspace((unsigned char)*s)) s++;
  size_t n = strlen(s);
  while (n && isspace((unsigned char)s[n - 1])) s[--n] = 0;
  return s;
}

static int copy_value(char *out, size_t size, const char *value) {
  size_t n = strlen(value);
  if (n >= size) return -1;
  memcpy(out, value, n + 1); return 0;
}

static int boolean(const char *value) {
  if (!strcasecmp(value, "yes") || !strcasecmp(value, "true") || !strcasecmp(value, "on") || !strcmp(value, "1")) return 1;
  if (!strcasecmp(value, "no") || !strcasecmp(value, "false") || !strcasecmp(value, "off") || !strcmp(value, "0")) return 0;
  return -1;
}

static int parse_file(struct parser *parser, const char *path, unsigned depth);

static int parse_line(struct parser *p, char *line, unsigned depth) {
  char *s = trim(line);
  if (!*s || *s == '#' || *s == ';') return 0;
  if (*s == '[') {
    char *end = strchr(s, ']');
    if (!end || *trim(end + 1)) { p->error = "malformed_section"; return 1; }
    *end = 0; s = trim(s + 1);
    if (!*s || strlen(s) >= sizeof(p->defaults.name)) { p->error = "invalid_section_name"; return 1; }
    if (!strcasecmp(s, "global")) { p->current = SIZE_MAX; return 0; }
    for (size_t i = 0; i < p->count; i++) if (!strcasecmp(p->shares[i].name, s)) { p->current = i; return 0; }
    if (p->count >= 4096) { p->error = "share_limit"; return 1; }
    struct share *next = realloc(p->shares, (p->count + 1) * sizeof(*next));
    if (!next) return -1;
    p->shares = next; p->current = p->count++;
    p->shares[p->current] = (struct share){ .enabled = -1, .printer = -1 };
    return copy_value(p->shares[p->current].name, sizeof(p->defaults.name), s);
  }
  char *eq = strchr(s, '=');
  if (!eq) { p->error = "malformed_option"; return 1; }
  *eq++ = 0; s = trim(s); eq = trim(eq);
  size_t n = strlen(eq);
  if (n && (*eq == '"' || *eq == '\'')) {
    if (n < 2 || eq[n - 1] != *eq) { p->error = "unterminated_quote"; return 1; }
    eq[n - 1] = 0; eq++;
  }
  if (!strcasecmp(s, "include")) {
    if (*eq != '/' || strpbrk(eq, "%${}")) { p->error = "unsupported_dynamic_or_registry_include"; return 1; }
    return parse_file(p, eq, depth + 1);
  }
  if (!strcasecmp(s, "copy") || !strcasecmp(s, "config file") ||
      (!strcasecmp(s, "usershare max shares") && strcmp(eq, "0")) ||
      (!strcasecmp(s, "config backend") && strcasecmp(eq, "file")) ||
      (!strcasecmp(s, "registry shares") && boolean(eq) != 0)) {
    p->error = "unsupported_registry_or_copy_configuration"; return 1;
  }
  struct share *share = p->current == SIZE_MAX ? &p->defaults : &p->shares[p->current];
  int result = 0;
  if (!strcasecmp(s, "path") || !strcasecmp(s, "directory")) result = copy_value(share->path, sizeof(share->path), eq);
  else if (!strcasecmp(s, "available") || !strcasecmp(s, "printable") || !strcasecmp(s, "print ok")) {
    int value = boolean(eq);
    if (value < 0) { p->error = "invalid_boolean"; return 1; }
    if (!strcasecmp(s, "available")) share->enabled = value; else share->printer = value;
  } else if (p->current == SIZE_MAX) {
    if (!strcasecmp(s, "passdb backend")) result = copy_value(p->backend, sizeof(p->backend), eq);
    else if (!strcasecmp(s, "private dir")) result = copy_value(p->private_dir, sizeof(p->private_dir), eq);
    else if (!strcasecmp(s, "smb passwd file")) result = copy_value(p->password_file, sizeof(p->password_file), eq);
    else if (!strcasecmp(s, "log file")) result = copy_value(p->log_pattern, sizeof(p->log_pattern), eq);
  }
  if (result) { p->error = "option_too_long"; return 1; }
  return 0;
}

static int parse_text(struct parser *p, char *text, size_t size, unsigned depth) {
  char logical[8192];
  size_t used = 0;
  int result = 0;
  if (memchr(text, 0, size)) { p->error = "nul_in_configuration"; return 1; }
  for (size_t pos = 0; pos < size;) {
    char *end = memchr(text + pos, '\n', size - pos);
    size_t count = end ? (size_t)(end - text - pos) : size - pos;
    if (count && text[pos + count - 1] == '\r') count--;
    if (count >= sizeof(logical) - used) { p->error = "config_line_limit"; result = 1; break; }
    memcpy(logical + used, text + pos, count); used += count;
    pos = end ? (size_t)(end - text) + 1 : size;
    if (used && logical[used - 1] == '\\') { used--; continue; }
    logical[used] = 0;
    result = parse_line(p, logical, depth); used = 0;
    if (result) break;
  }
  if (!result && used) { p->error = "unterminated_continuation"; result = 1; }
  explicit_bzero(logical, sizeof(logical));
  return result;
}

static int parse_file(struct parser *p, const char *path, unsigned depth) {
  if (depth > 16) { p->error = "include_depth_or_cycle"; return 1; }
  char *data;
  size_t size;
  if (hp_read_file(path, CONFIG_LIMIT, &data, &size)) { p->error = "config_read_failed"; return errno == ENOMEM ? -1 : 1; }
  if (size > 4 * CONFIG_LIMIT - p->bytes) { explicit_bzero(data, size); free(data); p->error = "config_size_limit"; return 1; }
  p->bytes += size;
  int result = parse_text(p, data, size, depth);
  explicit_bzero(data, size); free(data);
  return result;
}

static void users_free(struct users *users) {
  for (size_t i = 0; i < users->count; i++) { explicit_bzero(users->names[i], strlen(users->names[i])); free(users->names[i]); }
  free(users->names);
}

static int add_user(struct users *users, const char *name, size_t size) {
  if (!size || size > 255 || users->count == ACCOUNT_LIMIT) return -1;
  for (size_t i = 0; i < size; i++) if ((unsigned char)name[i] < 32 || name[i] == ':' || name[i] == '/' || !name[i]) return -1;
  if (users->count == users->capacity) {
    size_t capacity = users->capacity ? users->capacity * 2 : 32;
    char **next = realloc(users->names, capacity * sizeof(*next));
    if (!next) return -1;
    users->names = next; users->capacity = capacity;
  }
  char *copy = strndup(name, size);
  if (!copy) return -1;
  users->names[users->count++] = copy;
  return 0;
}

static int read_tdb(const char *path, struct users *users) {
  int fd = hp_open_absolute(path, O_RDONLY | O_NONBLOCK);
  if (fd < 0) return -1;
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > 256 * CONFIG_LIMIT) { close(fd); return -1; }
  struct flock lock = { .l_type = F_RDLCK, .l_whence = SEEK_SET };
  if (fcntl(fd, F_SETLK, &lock)) { close(fd); return -1; }
  char descriptor[64];
  snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
  /* This is an owned descriptor bridge, never an untrusted pathname. */
  struct tdb_context *db = tdb_open(descriptor, 0, TDB_NOMMAP, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
  if (!db) { close(fd); return -1; }
  int result = -1;
  /* libtdb's lock-all API rejects O_RDONLY; this descriptor holds the fcntl read lock. */
  if (tdb_get_flags(db) & TDB_MUTEX_LOCKING) goto done;
  TDB_DATA version_key = { (unsigned char *)"INFO/version", sizeof("INFO/version") };
  TDB_DATA version = tdb_fetch(db, version_key);
  int compatible = version.dptr && version.dsize == 4 && version.dptr[0] == 4 && !version.dptr[1] && !version.dptr[2] && !version.dptr[3];
  if (version.dptr) { explicit_bzero(version.dptr, version.dsize); free(version.dptr); }
  if (!compatible) goto done;
  result = 0;
  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start)) { result = -1; goto done; }
  size_t visited = 0;
  TDB_DATA key = tdb_firstkey(db);
  while (key.dptr) {
    struct timespec now;
    if (++visited > 2 * ACCOUNT_LIMIT + 32 || clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 2) result = -1;
    if (key.dsize > 5 && !memcmp(key.dptr, "USER_", 5)) {
      if (!result && (key.dptr[key.dsize - 1] || add_user(users, (char *)key.dptr + 5, key.dsize - 6))) result = -1;
    }
    TDB_DATA next = {0};
    if (!result) next = tdb_nextkey(db, key);
    explicit_bzero(key.dptr, key.dsize); free(key.dptr);
    key = next;
    if (result) break;
  }
  if (!result && tdb_error(db) != TDB_SUCCESS && tdb_error(db) != TDB_ERR_NOEXIST) result = -1;
done:
  if (tdb_close(db)) result = -1;
  if (close(fd)) result = -1;
  return result;
}

static int read_smbpasswd(const char *path, struct users *users) {
  char *data;
  size_t size;
  if (hp_read_file(path, 16 * CONFIG_LIMIT, &data, &size)) return -1;
  int result = 0;
  if (memchr(data, 0, size)) result = -1;
  char *save = NULL;
  for (char *line = result ? NULL : strtok_r(data, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
    if (*line == '#' || !*line) continue;
    char *colon = strchr(line, ':');
    size_t fields = 0;
    for (const char *c = line; *c; c++) if (*c == ':') fields++;
    if (!colon || fields < 5 || add_user(users, line, (size_t)(colon - line))) { result = -1; break; }
  }
  explicit_bzero(data, size); free(data);
  return result;
}

static int add_share(struct hp_sources *out, const char *name, const char *path) {
  if (!path || *path != '/' || strpbrk(path, "%${}")) return add_source(out, HP_SOURCE_STATUS, name, path, "unsupported_dynamic_path");
  int fd = hp_open_absolute(path, O_RDONLY | O_DIRECTORY);
  if (fd < 0) return add_source(out, HP_SOURCE_STATUS, name, path, "missing_or_inaccessible_share");
  close(fd);
  return add_source(out, HP_SHARE, name, path, NULL);
}

static int home_share(struct hp_sources *out, const char *name, const char *pattern) {
  struct passwd account, *found = NULL;
  char buffer[16384], path[4096];
  int result = getpwnam_r(name, &account, buffer, sizeof(buffer), &found);
  if (result || !found || !found->pw_dir) {
    result = add_source(out, HP_SOURCE_STATUS, name, "", "unresolved_home"); goto done;
  }
  size_t used = 0;
  if (!*pattern) pattern = "%H";
  for (size_t i = 0; pattern[i]; i++) {
    const char *piece = NULL;
    char literal[2] = { pattern[i], 0 };
    if (pattern[i] == '%') {
      i++;
      if (pattern[i] == 'H') piece = found->pw_dir;
      else if (pattern[i] == 'U' || pattern[i] == 'u' || pattern[i] == 'S') piece = name;
      else { result = add_source(out, HP_SOURCE_STATUS, name, pattern, "unsupported_home_substitution"); goto done; }
    } else piece = literal;
    size_t n = strlen(piece);
    if (n >= sizeof(path) - used) { result = add_source(out, HP_SOURCE_STATUS, name, pattern, "home_path_limit"); goto done; }
    memcpy(path + used, piece, n); used += n;
  }
  path[used] = 0;
  result = add_share(out, name, path);
done:
  explicit_bzero(buffer, sizeof(buffer)); explicit_bzero(path, sizeof(path));
  return result;
}

static int resolve_homes(struct parser *p, struct hp_sources *out, const char *pattern) {
  struct users users = {0};
  char path[4096], backend[4096];
  if (copy_value(backend, sizeof(backend), p->backend)) return -1;
  char *explicit_path = strchr(backend, ':');
  if (explicit_path) *explicit_path++ = 0;
  int result;
  if (!strcmp(backend, "tdbsam")) {
    if (snprintf(path, sizeof(path), "%s/passdb.tdb", p->private_dir) >= (int)sizeof(path)) return -1;
    result = read_tdb(explicit_path ? explicit_path : path, &users);
  } else if (!strcmp(backend, "smbpasswd")) {
    if (snprintf(path, sizeof(path), "%s/smbpasswd", p->private_dir) >= (int)sizeof(path)) return -1;
    result = read_smbpasswd(explicit_path ? explicit_path : *p->password_file ? p->password_file : path, &users);
  } else return add_source(out, HP_SOURCE_STATUS, "homes", p->backend, "unsupported_passdb_backend");
  if (result) result = add_source(out, HP_SOURCE_STATUS, "homes", explicit_path ? explicit_path : path, "account_database_unavailable_or_unsupported");
  else if (!users.count) result = add_source(out, HP_SOURCE_STATUS, "homes", "", "no_resolved_samba_accounts");
  else for (size_t i = 0; i < users.count; i++) if (home_share(out, users.names[i], pattern)) { result = -1; break; }
  users_free(&users);
  explicit_bzero(path, sizeof(path)); explicit_bzero(backend, sizeof(backend));
  return result;
}

static int resolve(struct parser *p, struct hp_sources *out) {
  for (size_t i = 0; i < p->count; i++) {
    struct share *s = &p->shares[i];
    if (!(s->enabled < 0 ? p->defaults.enabled : s->enabled) || (s->printer < 0 ? p->defaults.printer : s->printer)) continue;
    const char *path = *s->path ? s->path : p->defaults.path;
    int result = !strcasecmp(s->name, "homes") ? resolve_homes(p, out, path) : add_share(out, s->name, path);
    if (result) return -1;
  }
  return 0;
}

static int configured_logs(const char *pattern, struct hp_sources *out) {
  if (!*pattern) return 0;
  if (*pattern != '/' || strlen(pattern) >= 4096) return add_source(out, HP_SOURCE_STATUS, "samba_log", pattern, "unsupported_log_path");
  char directory[4096], glob[8192];
  strcpy(directory, pattern);
  char *name = strrchr(directory, '/');
  *name++ = 0;
  if (strpbrk(directory, "%${}")) return add_source(out, HP_SOURCE_STATUS, "samba_log", pattern, "unsupported_dynamic_log_directory");
  size_t used = 0;
  for (size_t i = 0; name[i]; i++) {
    if (name[i] == '%') {
      if (!name[i + 1]) return add_source(out, HP_SOURCE_STATUS, "samba_log", pattern, "invalid_log_substitution");
      glob[used++] = '*'; i++;
    } else {
      if (strchr("*?[]\\", name[i])) glob[used++] = '\\';
      glob[used++] = name[i];
    }
  }
  glob[used] = 0;
  int fd = hp_open_absolute(*directory ? directory : "/", O_RDONLY | O_DIRECTORY);
  DIR *dir = fd < 0 ? NULL : fdopendir(fd);
  if (!dir) { if (fd >= 0) close(fd); return add_source(out, HP_SOURCE_STATUS, "samba_log", pattern, "missing_log_directory"); }
  int result = 0, found = 0;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(dir))) {
    if (entry->d_name[0] == '.' || log_archive(entry->d_name) || fnmatch(glob, entry->d_name, 0)) continue;
    struct stat st;
    if (out->count >= 4096) break;   /* a client with thousands of names must not make discovery quadratic */
    if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      if (errno == ENOENT) { errno = 0; continue; }   /* rotated away between readdir and stat */
      result = -1; break;
    }
    if (S_ISREG(st.st_mode)) {
      char path[4096];
      if (snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) >= (int)sizeof(path) ||
          add_source(out, HP_LOG, "samba_log", path, NULL)) { result = -1; break; }
      found = 1;
    }
    errno = 0;
  }
  if (errno) result = -1;
  if (closedir(dir)) result = -1;
  if (!result && !found) result = add_source(out, HP_SOURCE_STATUS, "samba_log", pattern, "no_matching_log_files");
  return result;
}

int hp_discover_config(const char *path, struct hp_sources *out) {
  struct parser p = { .current = SIZE_MAX, .defaults = { .enabled = 1 },
    .backend = "tdbsam", .private_dir = "/var/lib/samba/private" };
  int result = parse_file(&p, path, 0);
  if (result > 0) result = add_source(out, HP_SOURCE_STATUS, "samba_config", path, p.error);
  else if (!result) {
    result = resolve(&p, out);
    if (!result) result = configured_logs(p.log_pattern, out);
  }
  if (p.shares) explicit_bzero(p.shares, p.count * sizeof(*p.shares));
  free(p.shares); explicit_bzero(&p, sizeof(p));
  return result;
}

static int log_archive(const char *name) {
  static const char *suffixes[] = { ".gz", ".xz", ".bz2", ".zst", ".zip" };
  size_t n = strlen(name);
  for (size_t i = 0; i < sizeof(suffixes) / sizeof(*suffixes); i++) {
    size_t len = strlen(suffixes[i]);
    if (n >= len && !strcmp(name + n - len, suffixes[i])) return 1;
  }
  return 0;
}

int hp_discover_sources(struct hp_sources *out) {
  if (hp_discover_config("/etc/samba/smb.conf", out)) return -1;
  static const char *logs[] = { "/var/log/messages", "/var/log/secure", "/var/log/cron", "/var/log/maillog", "/var/log/boot.log" };
  for (size_t i = 0; i < sizeof(logs) / sizeof(*logs); i++) {
    struct stat st;
    int missing = lstat(logs[i], &st) || !S_ISREG(st.st_mode);
    if (add_source(out, missing ? HP_SOURCE_STATUS : HP_LOG, "system_log", logs[i], missing ? "missing_log" : NULL)) return -1;
  }
  int fd = hp_open_absolute("/var/log/samba", O_RDONLY | O_DIRECTORY);
  DIR *dir = fd < 0 ? NULL : fdopendir(fd);
  if (!dir) { if (fd >= 0) close(fd); return add_source(out, HP_SOURCE_STATUS, "samba_logs", "/var/log/samba", "missing_log_directory"); }
  int result = 0;
  struct dirent *ent;
  errno = 0;
  while ((ent = readdir(dir))) {
    if (ent->d_name[0] == '.' || log_archive(ent->d_name)) continue;
    char path[4096];
    if (snprintf(path, sizeof(path), "/var/log/samba/%s", ent->d_name) >= (int)sizeof(path)) { result = -1; break; }
    struct stat st;
    if (out->count >= 4096) break;
    if (fstatat(fd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      if (errno == ENOENT) { errno = 0; continue; }
      result = -1; break;
    }
    if (S_ISREG(st.st_mode) && add_source(out, HP_LOG, "samba_log", path, NULL)) { result = -1; break; }
    errno = 0;
  }
  if (errno) result = -1;
  if (closedir(dir)) result = -1;
  return result;
}

