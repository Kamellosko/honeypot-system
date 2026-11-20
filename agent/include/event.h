#pragma once
#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>

/* Ujednolicony blok "event" raportu v2. Pusty napis lub -1 oznacza brak danych (zapis jako null). */
struct hp_event {
  const char *category, *type, *severity, *outcome, *service, *action;
  char src_ip[INET6_ADDRSTRLEN];
  int src_port;
  char dst_ip[INET6_ADDRSTRLEN];
  int dst_port;
  char user[129];
};

const char *hp_classify(const char *operation, const unsigned char *content, size_t size);
void hp_event_from_log(struct hp_event *e, const char *source, const char *operation,
                       const unsigned char *content, size_t size);
void hp_event_write(FILE *out, const struct hp_event *e);
