#define _GNU_SOURCE
#include "scan.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Linie SYNTETYCZNE (zakladany format firewalld; do potwierdzenia na Almie). */
static void fw(char *out, size_t n, const char *ip, int port, const char *flags) {
  snprintf(out, n,
           "Nov 20 12:00:00 honey kernel: filter_IN_public_REJECT: IN=eth0 OUT= SRC=%s DST=10.0.0.2 LEN=44 "
           "PROTO=TCP SPT=51000 DPT=%d WINDOW=1024 RES=0x00 %s URGP=0", ip, port, flags);
}

static int feed(struct hp_scan_tracker *t, const char *line, time_t now, struct hp_scan_hit *h) {
  return hp_scan_feed(t, (const unsigned char *)line, strlen(line), now, h);
}

static int parse(const char *line, struct hp_scan_packet *p) {
  return hp_scan_parse((const unsigned char *)line, strlen(line), p);
}

static void parse_syn(void) {
  char l[512]; struct hp_scan_packet p;
  fw(l, sizeof(l), "192.0.2.50", 81, "SYN");
  assert(parse(l, &p) == 1);
  assert(!strcmp(p.src_ip, "192.0.2.50") && !strcmp(p.dst_ip, "10.0.0.2") && p.dst_port == 81);
  assert(!strcmp(p.kind, "syn"));
  fw(l, sizeof(l), "192.0.2.50", 81, "");          assert(parse(l, &p) && !strcmp(p.kind, "null"));
  fw(l, sizeof(l), "192.0.2.50", 81, "FIN PSH URG"); assert(parse(l, &p) && !strcmp(p.kind, "xmas"));
  fw(l, sizeof(l), "192.0.2.50", 81, "URG FIN PSH"); assert(parse(l, &p) && !strcmp(p.kind, "xmas"));
  fw(l, sizeof(l), "192.0.2.50", 81, "FIN");       assert(parse(l, &p) && !strcmp(p.kind, "fin"));
  fw(l, sizeof(l), "192.0.2.50", 81, "SYN ACK");   assert(parse(l, &p) && !strcmp(p.kind, "other"));
  fw(l, sizeof(l), "2001:db8::1", 81, "SYN");      assert(parse(l, &p) && !strcmp(p.src_ip, "2001:db8::1"));
}

static void parse_rejects(void) {
  char l[512]; struct hp_scan_packet p;
  assert(!parse("Nov 20 12:00:00 honey sshd[1]: Failed password for invalid user SRC=1.2.3.4 DPT=80 PROTO=TCP IN=x "
                "from 203.0.113.9 port 1 ssh2", &p));
  fw(l, sizeof(l), "192.0.2.50", 81, "SYN");
  char udp[512]; memcpy(udp, l, sizeof(l)); char *x = strstr(udp, "PROTO=TCP"); memcpy(x, "PROTO=UDP", 9);
  assert(!parse(udp, &p));
  fw(l, sizeof(l), "192.0.2.50", 0, "SYN");     assert(!parse(l, &p));
  fw(l, sizeof(l), "192.0.2.50", 70000, "SYN"); assert(!parse(l, &p));
  fw(l, sizeof(l), "not-an-ip", 81, "SYN");     assert(!parse(l, &p));
  assert(!parse("", &p));
  assert(!parse("kernel: SRC=1.2.3.4 DST=1.2.3.5 PROTO=TCP DPT=1", &p));
}

static void threshold(void) {
  struct hp_scan_tracker *t = hp_scan_new(10, 10); assert(t);
  struct hp_scan_hit h; char l[512];
  for (int i = 0; i < 9; i++) { fw(l, sizeof(l), "192.0.2.50", 100 + i, "SYN"); assert(feed(t, l, 1000, &h) == 1); }
  for (int i = 0; i < 3; i++) { fw(l, sizeof(l), "192.0.2.50", 100, "SYN"); assert(feed(t, l, 1000, &h) == 1); }
  fw(l, sizeof(l), "192.0.2.50", 200, "SYN");
  assert(feed(t, l, 1001, &h) == 2);
  assert(h.ports == 10 && !strcmp(h.kind, "syn") && h.window_seconds == 10);
  assert(!strcmp(h.src_ip, "192.0.2.50") && !strcmp(h.dst_ip, "10.0.0.2"));
  hp_scan_free(t);
}

static void ack_and_window(void) {
  struct hp_scan_tracker *t = hp_scan_new(10, 10); struct hp_scan_hit h; char l[512];
  for (int i = 0; i < 10; i++) { fw(l, sizeof(l), "192.0.2.50", 100 + i, "SYN"); feed(t, l, 1000, &h); }
  fw(l, sizeof(l), "192.0.2.50", 300, "SYN");
  assert(feed(t, l, 1000, &h) == 2);               /* bez ack: ponowienie zwraca znow 2 */
  hp_scan_ack(t, "192.0.2.50");
  for (int i = 0; i < 5; i++) { fw(l, sizeof(l), "192.0.2.50", 400 + i, "SYN"); assert(feed(t, l, 1005, &h) == 1); }
  for (int i = 0; i < 10; i++) {                   /* po oknie: znow mozna */
    fw(l, sizeof(l), "192.0.2.50", 500 + i, "SYN");
    int r = feed(t, l, 1011, &h);
    assert(r == (i == 9 ? 2 : 1));
  }
  hp_scan_free(t);
}

static void two_sources(void) {
  struct hp_scan_tracker *t = hp_scan_new(10, 10); struct hp_scan_hit h; char l[512];
  for (int i = 0; i < 6; i++) {
    fw(l, sizeof(l), "192.0.2.1", 100 + i, "SYN"); assert(feed(t, l, 1000, &h) == 1);
    fw(l, sizeof(l), "192.0.2.2", 100 + i, "SYN"); assert(feed(t, l, 1000, &h) == 1);
  }
  hp_scan_free(t);
}

static void flood_bounded(void) {
  struct hp_scan_tracker *t = hp_scan_new(10, 10); struct hp_scan_hit h; char l[512], ip[32];
  for (int i = 0; i < 100000; i++) {
    snprintf(ip, sizeof(ip), "10.%d.%d.%d", (i >> 16) & 255, (i >> 8) & 255, i & 255);
    fw(l, sizeof(l), ip, 80, "SYN");
    assert(feed(t, l, 1000 + i / 1000, &h) == 1);
  }
  int r = 0;
  for (int i = 0; i < 10; i++) { fw(l, sizeof(l), "198.51.100.9", 100 + i, "SYN"); r = feed(t, l, 1200, &h); }
  assert(r == 2);
  hp_scan_free(t);
}

static void not_firewall(void) {
  struct hp_scan_tracker *t = hp_scan_new(10, 10); struct hp_scan_hit h;
  assert(feed(t, "Nov 20 12:00:00 honey sshd[1]: Failed password for bob from 1.2.3.4 port 5 ssh2", 1, &h) == 0);
  hp_scan_free(t);
}

static void consume_non_tcp(void) {
  struct hp_scan_tracker *t = hp_scan_new(10, 10); struct hp_scan_hit h; char l[512];
  struct hp_scan_packet p;
  /* UDP/ICMP z logu zapory sa konsumowane (nie wolno ich raportowac osobno), ale nigdy nie licza sie do skanu */
  for (int i = 0; i < 20; i++) {
    snprintf(l, sizeof(l), "Nov 20 12:00:00 honey kernel: filter_IN_public_REJECT: IN=eth0 OUT= SRC=192.0.2.9 "
             "DST=255.255.255.255 LEN=229 PROTO=UDP SPT=138 DPT=%d LEN=209", 100 + i);
    assert(!parse(l, &p));
    assert(feed(t, l, 1000, &h) == 1);
  }
  const char *icmp = "Nov 20 12:00:00 honey kernel: filter_IN_public_REJECT: IN=eth0 OUT= SRC=192.0.2.9 DST=10.0.0.2 "
                     "LEN=84 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1";
  assert(feed(t, icmp, 1000, &h) == 1);
  /* podrobiona linia (znacznik sshd[1]:) nie jest konsumowana */
  const char *forged = "Nov 20 12:00:00 honey sshd[1]: Failed password for invalid user SRC=1.2.3.4 DST=1.2.3.5 "
                       "PROTO=UDP from 203.0.113.9 port 1 ssh2";
  assert(feed(t, forged, 1000, &h) == 0);
  hp_scan_free(t);
}

int main(void) {
  consume_non_tcp();
  parse_syn(); parse_rejects(); threshold(); ack_and_window(); two_sources(); flood_bounded(); not_firewall();
  puts("PASS scan");
  return 0;
}
