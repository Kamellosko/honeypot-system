#define _GNU_SOURCE
#include "event.h"
#include "network.h"
#include "protocol.h"
#include <stdlib.h>
#include <string.h>

#define USER_MAX 128

static int has(const unsigned char *c, size_t n, const char *needle) {
  return c && memmem(c, n, needle, strlen(needle)) != NULL;
}

static int is_failure(const unsigned char *c, size_t n) {
  return has(c, n, "Failed password") || has(c, n, "NT_STATUS_LOGON_FAILURE") ||
         has(c, n, "NT_STATUS_WRONG_PASSWORD") || has(c, n, "NT_STATUS_NO_SUCH_USER");
}

static int is_success(const unsigned char *c, size_t n) {
  return has(c, n, "status [NT_STATUS_OK]") || has(c, n, "Accepted password") ||
         has(c, n, "Accepted publickey");
}

const char *hp_classify(const char *operation, const unsigned char *content, size_t size) {
  if (is_failure(content, size)) return "authentication_failure";
  if (is_success(content, size)) return "authentication_success";
  if (has(content, size, "smbd_audit")) return "samba_audit";
  if (operation && !strcmp(operation, "heartbeat")) return "heartbeat";
  return "unknown";
}

/* Pierwsza linia, w ktorej zachodzi predykat; zwraca wskaznik i dlugosc bez '\n'. */
static const unsigned char *first_line(const unsigned char *c, size_t n, int (*pred)(const unsigned char *, size_t),
                                       size_t *len) {
  size_t i = 0;
  while (i < n) {
    const unsigned char *nl = memchr(c + i, '\n', n - i);
    size_t l = nl ? (size_t)(nl - (c + i)) : n - i;
    if (pred(c + i, l)) { *len = l; return c + i; }
    i += l + 1;
  }
  return NULL;
}

static int is_audit(const unsigned char *c, size_t n) { return has(c, n, "smbd_audit"); }

static void copy_user(struct hp_event *e, const unsigned char *s, size_t n) {
  if (n > USER_MAX) n = USER_MAX;
  memcpy(e->user, s, n);
  e->user[n] = 0;
}

/* sshd: "Failed password for [invalid user ]NAME from IP port N" */
static void parse_ssh(struct hp_event *e, const unsigned char *l, size_t n) {
  const unsigned char *p = memmem(l, n, " for ", 5);
  if (p) {
    p += 5;
    if ((size_t)(l + n - p) > 13 && !memcmp(p, "invalid user ", 13)) p += 13;
    const unsigned char *end = p;
    while (end < l + n && *end != ' ') end++;
    copy_user(e, p, (size_t)(end - p));
  }
  const unsigned char *port = memmem(l, n, " port ", 6);
  if (port) {
    int v = atoi((const char *)port + 6);
    if (v > 0 && v <= 65535) e->src_port = v;
  }
}

/* Samba auth: "user [DOMAIN]\[NAME]" albo "user [NAME]" */
static void parse_smb_auth(struct hp_event *e, const unsigned char *l, size_t n) {
  const unsigned char *p = memmem(l, n, "user [", 6);
  if (!p) return;
  p += 6;
  const unsigned char *end = memchr(p, ']', (size_t)(l + n - p));
  if (!end) return;
  if (end + 2 < l + n && end[1] == '\\' && end[2] == '[') {
    p = end + 3;
    end = memchr(p, ']', (size_t)(l + n - p));
    if (!end) return;
  }
  copy_user(e, p, (size_t)(end - p));
}

/* full_audit: "smbd_audit[PID]: USER|IP|machine|share|op|..." */
static void parse_smb_audit(struct hp_event *e, const unsigned char *l, size_t n) {
  const unsigned char *p = memmem(l, n, "smbd_audit", 10);
  p = memchr(p, ':', (size_t)(l + n - p));
  if (!p) return;
  p++;
  while (p < l + n && *p == ' ') p++;
  const unsigned char *end = memchr(p, '|', (size_t)(l + n - p));
  if (end) copy_user(e, p, (size_t)(end - p));
}

static void set(struct hp_event *e, const char *category, const char *type, const char *severity) {
  e->category = category; e->type = type; e->severity = severity;
}

void hp_event_from_log(struct hp_event *e, const char *source, const char *operation,
                       const unsigned char *content, size_t size) {
  memset(e, 0, sizeof(*e));
  e->src_port = e->dst_port = -1;
  e->outcome = "unknown";
  const char *cls = hp_classify(operation, content, size);
  const unsigned char *line = NULL;
  size_t len = 0;
  if (!strcmp(cls, "authentication_failure")) {
    set(e, "authentication", "auth.failure", "medium");
    e->outcome = "failure";
    line = first_line(content, size, is_failure, &len);
  } else if (!strcmp(cls, "authentication_success")) {
    set(e, "authentication", "auth.success", "high");
    e->outcome = "success";
    line = first_line(content, size, is_success, &len);
  } else if (!strcmp(cls, "samba_audit")) {
    set(e, "file", "samba.audit", "low");
    line = first_line(content, size, is_audit, &len);
    if (line) { e->service = "smb"; parse_smb_audit(e, line, len); }
  } else if (!strcmp(cls, "heartbeat")) {
    set(e, "system", "system.heartbeat", "info");
  } else if (!strcmp(operation, "observation_gap")) {
    set(e, "system", "system.observation_gap", "medium");
  } else if (!strcmp(operation, "source_unavailable")) {
    set(e, "system", "system.source_unavailable", "medium");
  } else if (!strcmp(source, "log")) {
    set(e, "system", "log.entry", "info");
  } else {
    set(e, "system", "system.unknown", "info");
  }
  if (!line) return;
  if (has(line, len, "NT_STATUS") || has(line, len, "smbd")) {
    e->service = "smb";
    if (strcmp(cls, "samba_audit")) parse_smb_auth(e, line, len);
  } else if (strcmp(cls, "samba_audit")) {
    e->service = "ssh";
    parse_ssh(e, line, len);
  }
  struct hp_network_context ctx;
  hp_extract_ips(line, len, &ctx);
  if (ctx.count) snprintf(e->src_ip, sizeof(e->src_ip), "%s", ctx.ips[0]);
}

static void str_or_null(FILE *out, const char *s) {
  if (s && *s) hp_json_string(out, (const unsigned char *)s, strlen(s)); else fputs("null", out);
}

static void endpoint(FILE *out, const char *ip, int port, int with_mac) {
  if (!*ip && port < 0) { fputs("null", out); return; }
  fputs("{\"ip\":", out); str_or_null(out, ip);
  if (port >= 0) fprintf(out, ",\"port\":%d", port); else fputs(",\"port\":null", out);
  if (with_mac) fputs(",\"mac\":null", out);
  fputc('}', out);
}

void hp_event_write(FILE *out, const struct hp_event *e) {
  fputs(",\"event\":{\"category\":", out); str_or_null(out, e->category);
  fputs(",\"type\":", out); str_or_null(out, e->type);
  fputs(",\"severity\":", out); str_or_null(out, e->severity);
  fputs(",\"outcome\":", out); str_or_null(out, e->outcome);
  fputs(",\"service\":", out); str_or_null(out, e->service);
  fputs(",\"action\":", out); str_or_null(out, e->action);
  fputs(",\"src\":", out); endpoint(out, e->src_ip, e->src_port, 1);
  fputs(",\"dst\":", out); endpoint(out, e->dst_ip, e->dst_port, 0);
  fputs(",\"user\":", out);
  if (*e->user) { fputs("{\"name\":", out); str_or_null(out, e->user); fputc('}', out); } else fputs("null", out);
  fputc('}', out);
}
