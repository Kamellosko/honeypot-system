#pragma once
#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
#include "scan.h"

/* Ujednolicony blok "event" raportu v2. Pusty napis lub -1 oznacza brak danych (zapis jako null). */
struct hp_event {
  const char *category, *type, *severity, *outcome, *service, *action;
  char src_ip[INET6_ADDRSTRLEN];
  int src_port;
  char dst_ip[INET6_ADDRSTRLEN];
  int dst_port;
  char user[129];
  /* auth.attempt: probowane haslo (bajty, nie musza byc UTF-8; obciete do 256) */
  int has_password;
  unsigned char password[257];
  size_t password_len;
  /* net.scan: scan_ports > 0 oznacza blok "detail" */
  int scan_ports;
  const char *scan_kind;
  int scan_window;
};

const char *hp_classify(const char *operation, const unsigned char *content, size_t size);
void hp_event_from_log(struct hp_event *e, const char *source, const char *operation,
                       const unsigned char *content, size_t size);
void hp_event_scan(struct hp_event *e, const struct hp_scan_hit *hit);
void hp_event_file(struct hp_event *e, const char *action);
void hp_event_connection(struct hp_event *e, const char *local_ip, unsigned short local_port,
                         const char *peer_ip, unsigned short peer_port);
void hp_event_write(FILE *out, const struct hp_event *e);
