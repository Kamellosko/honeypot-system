#pragma once
#include <arpa/inet.h>
#include <stddef.h>
#include <time.h>

#define HP_SCAN_PORTS_DEFAULT 10
#define HP_SCAN_WINDOW_DEFAULT 10
#define HP_SCAN_SOURCES 1024
#define HP_SCAN_PORTS_MAX 64

/* Jeden odrzucony pakiet TCP z linii zapory (firewalld --set-log-denied). */
struct hp_scan_packet {
  char src_ip[INET6_ADDRSTRLEN];
  char dst_ip[INET6_ADDRSTRLEN];
  int dst_port;
  const char *kind; /* syn | null | xmas | fin | other */
};

/* Wykryty skan: zrodlo, ktore dotknelo >= prog roznych portow w oknie. */
struct hp_scan_hit {
  char src_ip[INET6_ADDRSTRLEN];
  char dst_ip[INET6_ADDRSTRLEN];
  int ports;
  const char *kind;
  int window_seconds;
};

struct hp_scan_tracker;

/* 1 dla linii zapory (5. pole syslog to "kernel:", PROTO=TCP, SRC=, DST=, DPT=1..65535), inaczej 0. */
int hp_scan_parse(const unsigned char *line, size_t len, struct hp_scan_packet *p);

/* threshold jest przycinany do 1..HP_SCAN_PORTS_MAX; NULL przy bledzie alokacji. */
struct hp_scan_tracker *hp_scan_new(int threshold, int window_seconds);
void hp_scan_free(struct hp_scan_tracker *t);

/* 0: to nie linia zapory; 1: skonsumowana (takze linie jadra UDP/ICMP: konsumowane, nie liczone); 2: skonsumowana, prog osiagniety (hit wypelniony).
   Zrodlo zwraca 2, dopoki nie zostanie wyciszone przez hp_scan_ack (ponowienie po nieudanym raporcie). */
int hp_scan_feed(struct hp_scan_tracker *t, const unsigned char *line, size_t len, time_t now,
                 struct hp_scan_hit *hit);
void hp_scan_ack(struct hp_scan_tracker *t, const char *src_ip);
