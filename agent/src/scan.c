#define _GNU_SOURCE
#include "scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { F_SYN = 1, F_ACK = 2, F_FIN = 4, F_RST = 8, F_PSH = 16, F_URG = 32, F_OTHER = 64 };

struct entry {
  int used, muted, nports;
  time_t first;
  char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
  const char *kind;
  unsigned short ports[HP_SCAN_PORTS_MAX];
};

struct hp_scan_tracker {
  int threshold, window;
  struct entry e[HP_SCAN_SOURCES];
};

static int is_space(unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

/* Kopiuje wartosc tokenu "KEY=value" do out; 0 gdy za dluga lub pusta. */
static int copy_value(const unsigned char *v, size_t n, char *out, size_t cap) {
  if (!n || n >= cap) return 0;
  memcpy(out, v, n);
  out[n] = 0;
  return 1;
}

static int valid_ip(const char *s) {
  unsigned char buf[sizeof(struct in6_addr)];
  return inet_pton(AF_INET, s, buf) == 1 || inet_pton(AF_INET6, s, buf) == 1;
}

static const char *kind_of(int mask) {
  if (mask == F_SYN) return "syn";
  if (mask == 0) return "null";
  if (mask == F_FIN) return "fin";
  if (mask == (F_FIN | F_PSH | F_URG)) return "xmas";
  return "other";
}

static int flag_of(const unsigned char *t, size_t n) {
  if (n == 3 && !memcmp(t, "SYN", 3)) return F_SYN;
  if (n == 3 && !memcmp(t, "ACK", 3)) return F_ACK;
  if (n == 3 && !memcmp(t, "FIN", 3)) return F_FIN;
  if (n == 3 && !memcmp(t, "RST", 3)) return F_RST;
  if (n == 3 && !memcmp(t, "PSH", 3)) return F_PSH;
  if (n == 3 && !memcmp(t, "URG", 3)) return F_URG;
  return F_OTHER;
}

/* Rozbiera linie zapory. Zwraca 1 dla poprawnego pakietu TCP. *netfilter (opcjonalny) = 1, gdy to linia jadra z
   SRC=, DST= i PROTO= (dowolny protokol): taka linia jest konsumowana, ale tylko TCP liczy sie do skanu. */
static int parse_line(const unsigned char *line, size_t len, struct hp_scan_packet *p, int *netfilter) {
  int have_src = 0, have_dst = 0, have_tcp = 0, seen_src = 0, seen_dst = 0, seen_proto = 0;
  int port = 0, after_res = 0, mask = 0, field = 0;
  memset(p, 0, sizeof(*p));
  if (netfilter) *netfilter = 0;
  size_t i = 0;
  while (i < len) {
    while (i < len && is_space(line[i])) i++;
    size_t start = i;
    while (i < len && !is_space(line[i])) i++;
    size_t n = i - start;
    if (!n) break;
    const unsigned char *t = line + start;
    /* pola syslog: miesiac, dzien, czas, host, znacznik programu (musi byc "kernel:") */
    if (field < 5) {
      if (field == 4 && !(n == 7 && !memcmp(t, "kernel:", 7))) return 0;
      field++;
      continue;
    }
    if (n > 4 && !memcmp(t, "SRC=", 4)) {
      seen_src = 1;
      have_src = copy_value(t + 4, n - 4, p->src_ip, sizeof(p->src_ip)) && valid_ip(p->src_ip);
    } else if (n > 4 && !memcmp(t, "DST=", 4)) {
      seen_dst = 1;
      have_dst = copy_value(t + 4, n - 4, p->dst_ip, sizeof(p->dst_ip)) && valid_ip(p->dst_ip);
    } else if (n > 6 && !memcmp(t, "PROTO=", 6)) {
      seen_proto = 1;
      if (n == 9 && !memcmp(t, "PROTO=TCP", 9)) have_tcp = 1;
    } else if (n > 4 && !memcmp(t, "DPT=", 4)) {
      port = 0;
      for (size_t k = 4; k < n; k++) {
        if (t[k] < '0' || t[k] > '9' || port > 65535) { port = 0; break; }
        port = port * 10 + (t[k] - '0');
      }
      if (port > 65535) port = 0;
    } else if (n > 4 && !memcmp(t, "RES=", 4)) after_res = 1;
    else if (after_res && !memchr(t, '=', n)) mask |= flag_of(t, n);
  }
  if (field < 5) return 0;
  if (netfilter) *netfilter = seen_src && seen_dst && seen_proto;
  if (!have_src || !have_dst || !have_tcp || port < 1) return 0;
  p->dst_port = port;
  p->kind = kind_of(mask);
  return 1;
}

int hp_scan_parse(const unsigned char *line, size_t len, struct hp_scan_packet *p) {
  return parse_line(line, len, p, NULL);
}

struct hp_scan_tracker *hp_scan_new(int threshold, int window_seconds) {
  struct hp_scan_tracker *t = calloc(1, sizeof(*t));
  if (!t) return NULL;
  t->threshold = threshold < 1 ? 1 : threshold > HP_SCAN_PORTS_MAX ? HP_SCAN_PORTS_MAX : threshold;
  t->window = window_seconds < 1 ? 1 : window_seconds;
  return t;
}

void hp_scan_free(struct hp_scan_tracker *t) { free(t); }

static void start_entry(struct entry *e, const struct hp_scan_packet *p, time_t now) {
  memset(e, 0, sizeof(*e));
  e->used = 1;
  e->first = now;
  e->kind = p->kind;
  snprintf(e->src, sizeof(e->src), "%s", p->src_ip);
  snprintf(e->dst, sizeof(e->dst), "%s", p->dst_ip);
}

int hp_scan_feed(struct hp_scan_tracker *t, const unsigned char *line, size_t len, time_t now,
                 struct hp_scan_hit *hit) {
  struct hp_scan_packet p;
  int netfilter;
  if (!parse_line(line, len, &p, &netfilter)) return netfilter; /* inne protokoly: skonsumowane, nie liczone */
  struct entry *e = NULL, *oldest = &t->e[0];
  for (size_t i = 0; i < HP_SCAN_SOURCES; i++) {
    struct entry *c = &t->e[i];
    if (c->used && !strcmp(c->src, p.src_ip)) { e = c; break; }
    if (!c->used) { if (oldest->used) oldest = c; }
    else if (oldest->used && c->first < oldest->first) oldest = c;
  }
  if (!e) { e = oldest; start_entry(e, &p, now); }
  else if (now - e->first > t->window) start_entry(e, &p, now);
  int known = 0;
  for (int k = 0; k < e->nports; k++) if (e->ports[k] == p.dst_port) { known = 1; break; }
  if (!known && e->nports < t->threshold) e->ports[e->nports++] = (unsigned short)p.dst_port;
  if (e->muted || e->nports < t->threshold) return 1;
  memset(hit, 0, sizeof(*hit));
  snprintf(hit->src_ip, sizeof(hit->src_ip), "%s", e->src);
  snprintf(hit->dst_ip, sizeof(hit->dst_ip), "%s", e->dst);
  hit->ports = e->nports;
  hit->kind = e->kind;
  hit->window_seconds = t->window;
  return 2;
}

void hp_scan_ack(struct hp_scan_tracker *t, const char *src_ip) {
  for (size_t i = 0; i < HP_SCAN_SOURCES; i++)
    if (t->e[i].used && !strcmp(t->e[i].src, src_ip)) { t->e[i].muted = 1; return; }
}
