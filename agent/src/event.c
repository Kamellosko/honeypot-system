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

/* Samba odmowila dostepu (np. konto bez prawa do udzialu, gosc odrzucony); linie full_audit maja wlasny typ. */
static int is_denied(const unsigned char *c, size_t n) {
  return has(c, n, "NT_STATUS_ACCESS_DENIED") && !has(c, n, "smbd_audit");
}

/* sshd: "Invalid user NAME from IP port N" (sama proba nieistniejacego konta, bez hasla albo przed nim). */
static int is_invalid_user(const unsigned char *c, size_t n) {
  return has(c, n, "Invalid user ") && has(c, n, " from ");
}

/* sshd: polaczenie bez poprawnego banera SSH, typowy slad skanera wersji (nmap -sV) albo sondy portu. */
static int is_probe(const unsigned char *c, size_t n) {
  return has(c, n, "Did not receive identification string from") ||
         has(c, n, "banner exchange: Connection from") || has(c, n, "kex_exchange_identification:");
}

static void copy_user(struct hp_event *e, const unsigned char *s, size_t n);

/* Ostry dekoder base64 (alfabet standardowy, dlugosc % 4 == 0, '=' tylko na koncu); pusty napis to pusty wynik. */
static int b64_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  return c == '+' ? 62 : c == '/' ? 63 : -1;
}

static int b64_decode(const unsigned char *s, size_t n, unsigned char *out, size_t cap, size_t *outlen) {
  size_t o = 0;
  if (n % 4) return 0;
  for (size_t i = 0; i < n; i += 4) {
    int v[4], pad = 0;
    for (int k = 0; k < 4; k++) {
      unsigned char c = s[i + k];
      if (c == '=') {
        if (i + 4 != n || k < 2) return 0;
        v[k] = 0; pad++;
      } else {
        if (pad || (v[k] = b64_value(c)) < 0) return 0;
      }
    }
    unsigned val = (unsigned)v[0] << 18 | (unsigned)v[1] << 12 | (unsigned)v[2] << 6 | (unsigned)v[3];
    if (o + 3 - pad > cap) return 0;
    out[o++] = (unsigned char)(val >> 16);
    if (pad < 2) out[o++] = (unsigned char)(val >> 8);
    if (pad < 1) out[o++] = (unsigned char)val;
  }
  *outlen = o;
  return 1;
}

#define PAM_DECODE_MAX 3072
#define PASSWORD_MAX 256

/* Linia hook-a PAM: "Mon DD HH:MM:SS host hp-pam: u=<b64 uzytkownik> h=<rhost> p=<b64 haslo>".
   Znacznik programu musi byc 5. polem (atakujacy kontroluje nazwe uzytkownika w liniach sshd, ale nie ich znacznik).
   Zwraca 1 dla poprawnej linii; gdy e != NULL, wypelnia user, src_ip i haslo. */
static int parse_pam(const unsigned char *l, size_t n, struct hp_event *e) {
  const unsigned char *tok[8];
  size_t tlen[8];
  size_t i = 0;
  int count = 0;
  while (i < n && count < 8) {
    while (i < n && (l[i] == ' ' || l[i] == '\t' || l[i] == '\r' || l[i] == '\n')) i++;
    size_t start = i;
    while (i < n && l[i] != ' ' && l[i] != '\t' && l[i] != '\r' && l[i] != '\n') i++;
    if (i == start) break;
    tok[count] = l + start; tlen[count] = i - start; count++;
  }
  if (count != 8 || tlen[4] != 7 || memcmp(tok[4], "hp-pam:", 7)) return 0;
  if (tlen[5] < 3 || memcmp(tok[5], "u=", 2) || tlen[6] < 2 || memcmp(tok[6], "h=", 2) ||
      tlen[7] < 2 || memcmp(tok[7], "p=", 2)) return 0;
  unsigned char user[PAM_DECODE_MAX], pw[PAM_DECODE_MAX];
  size_t ulen = 0, plen = 0;
  if (!b64_decode(tok[5] + 2, tlen[5] - 2, user, sizeof(user), &ulen) || !ulen) return 0;
  if (!b64_decode(tok[7] + 2, tlen[7] - 2, pw, sizeof(pw), &plen)) return 0;
  if (e) {
    copy_user(e, user, ulen);
    char host[INET6_ADDRSTRLEN];
    size_t hl = tlen[6] - 2;
    unsigned char probe[sizeof(struct in6_addr)];
    if (hl > 0 && hl < sizeof(host)) {
      memcpy(host, tok[6] + 2, hl);
      host[hl] = 0;
      if (inet_pton(AF_INET, host, probe) == 1 || inet_pton(AF_INET6, host, probe) == 1)
        snprintf(e->src_ip, sizeof(e->src_ip), "%s", host);
    }
    e->has_password = 1;
    e->password_len = plen > PASSWORD_MAX ? PASSWORD_MAX : plen;
    memcpy(e->password, pw, e->password_len);
  }
  explicit_bzero(pw, sizeof(pw));
  return 1;
}

static int is_pam(const unsigned char *c, size_t n) { return parse_pam(c, n, NULL); }

static const unsigned char *first_line(const unsigned char *c, size_t n, int (*pred)(const unsigned char *, size_t),
                                       size_t *len);

const char *hp_classify(const char *operation, const unsigned char *content, size_t size) {
  size_t pam_len;
  if (first_line(content, size, is_pam, &pam_len)) return "authentication_attempt";
  if (is_failure(content, size)) return "authentication_failure";
  if (is_success(content, size)) return "authentication_success";
  if (is_denied(content, size)) return "access_denied";
  if (is_invalid_user(content, size)) return "invalid_user";
  if (is_probe(content, size)) return "service_probe";
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
  /* Nazwa moze pochodzic z base64 (hook PAM) albo byc ucieta w srodku znaku: JSON musi zostac poprawny,
     a raport nie moze byc odrzucony przez serwer, wiec bajty spoza UTF-8 zamieniamy na '?'. */
  if (!hp_valid_utf8((const unsigned char *)e->user, n))
    for (size_t i = 0; i < n; i++) if ((unsigned char)e->user[i] & 0x80) e->user[i] = '?';
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

/* Ostatnie " from " w linii sshd: tam sshd dopisuje adres klienta, wiec nazwa uzytkownika podana przez
   atakujacego (ktora moze zawierac " from ") nie podmieni adresu. Zwraca wskaznik na " from " albo NULL. */
static const unsigned char *last_from(const unsigned char *l, size_t n) {
  const unsigned char *found = NULL, *p = l;
  while ((p = memmem(p, (size_t)(l + n - p), " from ", 6))) { found = p; p += 6; }
  return found;
}

/* "... from IP port N...": adres i port klienta po ostatnim " from ". */
static void parse_from(struct hp_event *e, const unsigned char *l, size_t n) {
  const unsigned char *p = last_from(l, n);
  if (!p) return;
  p += 6;
  const unsigned char *end = p;
  while (end < l + n && *end != ' ' && *end != ':' && *end != '\r') end++;
  /* IPv6 zawiera ':', wiec gdy adres sie nie parsuje, bierzemy caly token do spacji. */
  char host[INET6_ADDRSTRLEN];
  unsigned char probe[sizeof(struct in6_addr)];
  for (int pass = 0; pass < 2; pass++) {
    size_t hl = (size_t)(end - p);
    if (hl > 0 && hl < sizeof(host)) {
      memcpy(host, p, hl);
      host[hl] = 0;
      if (inet_pton(AF_INET, host, probe) == 1 || inet_pton(AF_INET6, host, probe) == 1) {
        snprintf(e->src_ip, sizeof(e->src_ip), "%s", host);
        break;
      }
    }
    while (end < l + n && *end != ' ') end++;
  }
  const unsigned char *port = memmem(end, (size_t)(l + n - end), " port ", 6);
  if (port) {
    int v = atoi((const char *)port + 6);
    if (v > 0 && v <= 65535) e->src_port = v;
  }
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
  if (!strcmp(cls, "authentication_attempt")) {
    set(e, "authentication", "auth.attempt", "medium");
    e->outcome = "failure";
    e->service = "ssh";
    line = first_line(content, size, is_pam, &len);
    if (line) parse_pam(line, len, e);
    return;
  }
  if (!strcmp(cls, "invalid_user")) {
    set(e, "authentication", "auth.invalid_user", "low");
    e->outcome = "failure";
    e->service = "ssh";
    line = first_line(content, size, is_invalid_user, &len);
    if (line) {
      const unsigned char *p = memmem(line, len, "Invalid user ", 13) + 13;
      const unsigned char *from = last_from(line, len);
      if (from && from >= p) copy_user(e, p, (size_t)(from - p));
      parse_from(e, line, len);
    }
    return;
  }
  if (!strcmp(cls, "service_probe")) {
    set(e, "network", "net.probe", "medium");
    e->service = "ssh";
    line = first_line(content, size, is_probe, &len);
    if (line) parse_from(e, line, len);
    return;
  }
  if (!strcmp(cls, "access_denied")) {
    set(e, "authentication", "auth.denied", "medium");
    e->outcome = "failure";
    line = first_line(content, size, is_denied, &len);
  } else
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
  } else if (!strcmp(source, "share")) {
    hp_event_file(e, operation);
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
    /* Adres klienta sshd stoi po OSTATNIM " from ". Nazwe uzytkownika wpisuje atakujacy i moze wygladac jak IP
       (np. "127.0.0.1"), wiec ogolne szukanie pierwszego adresu w linii podmienialoby zrodlo. Gdy adresu nie ma,
       zostaje pusty zamiast zgadywania. */
    parse_from(e, line, len);
    return;
  }
  struct hp_network_context ctx;
  hp_extract_ips(line, len, &ctx);
  if (ctx.count) snprintf(e->src_ip, sizeof(e->src_ip), "%s", ctx.ips[0]);
}

void hp_event_scan(struct hp_event *e, const struct hp_scan_hit *hit) {
  memset(e, 0, sizeof(*e));
  e->src_port = e->dst_port = -1;
  e->outcome = "unknown";
  set(e, "network", "net.scan", "medium");
  snprintf(e->src_ip, sizeof(e->src_ip), "%s", hit->src_ip);
  snprintf(e->dst_ip, sizeof(e->dst_ip), "%s", hit->dst_ip);
  e->scan_ports = hit->ports;
  e->scan_kind = hit->kind;
  e->scan_window = hit->window_seconds;
}

void hp_event_file(struct hp_event *e, const char *action) {
  memset(e, 0, sizeof(*e));
  e->src_port = e->dst_port = -1;
  e->outcome = "unknown";
  set(e, "file", "file.change", "medium");
  e->action = action;
}

void hp_event_connection(struct hp_event *e, const char *local_ip, unsigned short local_port,
                         const char *peer_ip, unsigned short peer_port) {
  memset(e, 0, sizeof(*e));
  e->outcome = "unknown";
  set(e, "network", "net.connection", "low");
  snprintf(e->src_ip, sizeof(e->src_ip), "%s", peer_ip);
  snprintf(e->dst_ip, sizeof(e->dst_ip), "%s", local_ip);
  e->src_port = peer_port;
  e->dst_port = local_port;
  e->service = local_port == 22 ? "ssh" : (local_port == 139 || local_port == 445) ? "smb" : NULL;
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
  fputs(",\"credential\":", out);
  if (!e->has_password) fputs("null", out);
  else if (hp_valid_utf8(e->password, e->password_len)) {
    fputs("{\"password\":", out); hp_json_string(out, e->password, e->password_len); fputc('}', out);
  } else {
    fputs("{\"password\":null,\"password_base64\":", out);
    hp_json_base64(out, e->password, e->password_len);
    fputc('}', out);
  }
  fputs(",\"detail\":", out);
  if (e->scan_ports > 0) {
    fprintf(out, "{\"ports\":%d,\"scan\":", e->scan_ports);
    str_or_null(out, e->scan_kind);
    fprintf(out, ",\"window_seconds\":%d}", e->scan_window);
  } else fputs("null", out);
  fputc('}', out);
}
