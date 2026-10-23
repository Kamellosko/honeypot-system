#pragma once
#include <arpa/inet.h>
#include <net/if.h>
#include <stddef.h>
#include <stdio.h>

#define HP_NETWORK_MAX 8
struct hp_network_context {
  char ips[HP_NETWORK_MAX][INET6_ADDRSTRLEN];
  size_t count;
  int truncated;
};

void hp_extract_ips(const unsigned char *content, size_t size, struct hp_network_context *context);
const char *hp_lookup_mac(const char *ip, char mac[18], char device[IF_NAMESIZE]);
void hp_write_network_context(FILE *out, const unsigned char *content, size_t size);
void hp_write_endpoint(FILE *out, const char *ip);
