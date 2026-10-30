#define _GNU_SOURCE
#include "network.h"
#include "protocol.h"
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int address_char(unsigned char c) {
  return isalnum(c) || c == '.' || c == ':' || c == '_' || c == '%' || c == '-';
}

static void add_ip_token(const unsigned char *text, size_t length, struct hp_network_context *context) {
  char token[128], ip[INET6_ADDRSTRLEN];
  if (length >= sizeof(token)) return;
  memcpy(token, text, length); token[length] = 0;
  char *addr = token;
  if (!strncmp(addr, "ipv4:", 5)) addr += 5;   // format Samby: [ipv4:A.B.C.D:port]
  struct in6_addr v6;
  struct in_addr v4;
  int family = 0;
  if (inet_pton(AF_INET, addr, &v4) == 1) family = AF_INET;
  else if (inet_pton(AF_INET6, addr, &v6) == 1) {
    family = AF_INET6;
    if (IN6_IS_ADDR_V4MAPPED(&v6)) { memcpy(&v4, &v6.s6_addr[12], sizeof(v4)); family = AF_INET; }
  } else {
    char *colon = strchr(addr, ':');
    if (colon && colon == strrchr(addr, ':') && colon[1]) {
      char *end;
      errno = 0;
      unsigned long port = strtoul(colon + 1, &end, 10);
      if (!errno && !*end && port > 0 && port <= 65535) {
        *colon = 0;
        if (inet_pton(AF_INET, addr, &v4) == 1) family = AF_INET;
      }
    }
  }
  if (family && inet_ntop(family, family == AF_INET ? (void *)&v4 : (void *)&v6, ip, sizeof(ip))) {
    size_t j = 0;
    while (j < context->count && strcmp(context->ips[j], ip)) j++;
    if (j == context->count) {
      if (j == HP_NETWORK_MAX) context->truncated = 1;
      else { strcpy(context->ips[j], ip); context->count++; }
    }
  }
  explicit_bzero(token, sizeof(token));
  explicit_bzero(ip, sizeof(ip));
}

void hp_extract_ips(const unsigned char *content, size_t size, struct hp_network_context *context) {
  memset(context, 0, sizeof(*context));
  // Samba: the real client is in "remote host [ipv4:A.B.C.D:port]", but the user name before it is attacker-controlled, so add it first
  static const char marker[] = "remote host [";
  const unsigned char *remote = memmem(content, size, marker, sizeof(marker) - 1);
  if (remote) {
    const unsigned char *start = remote + sizeof(marker) - 1, *end = start;
    while (end < content + size && address_char(*end)) end++;
    add_ip_token(start, end - start, context);
  }
  for (size_t i = 0; i < size;) {
    if (!address_char(content[i])) { i++; continue; }
    size_t start = i;
    while (i < size && address_char(content[i])) i++;
    add_ip_token(content + start, i - start, context);
  }
}

void hp_write_endpoint(FILE *out, const char *ip) {
  char mac[18] = {0}, device[IF_NAMESIZE] = {0};
  const char *status = hp_lookup_mac(ip, mac, device);
  fputs("{\"ip\":", out); hp_json_string(out, (const unsigned char *)ip, strlen(ip));
  fputs(",\"mac\":", out);
  if (mac[0]) hp_json_string(out, (const unsigned char *)mac, strlen(mac)); else fputs("null", out);
  fputs(",\"interface\":", out);
  if (device[0]) hp_json_string(out, (const unsigned char *)device, strlen(device)); else fputs("null", out);
  fprintf(out, ",\"mac_status\":\"%s\",\"mac_source\":\"local_arp_cache_at_report_time\",\"context_only\":true}", status);
  explicit_bzero(mac, sizeof(mac)); explicit_bzero(device, sizeof(device));
}

void hp_write_text_endpoint(FILE *out, const char *ip) {
  fputs("{\"ip\":", out); hp_json_string(out, (const unsigned char *)ip, strlen(ip));
  fputs(",\"mac\":null,\"interface\":null,\"mac_status\":\"not_looked_up\",\"mac_source\":\"none\",\"context_only\":true}", out);
}

void hp_write_network_context(FILE *out, const unsigned char *content, size_t size) {
  struct hp_network_context context;
  hp_extract_ips(content, size, &context);
  fputs("{\"endpoints\":[", out);
  for (size_t i = 0; i < context.count; i++) {
    if (i) fputc(',', out);
    hp_write_text_endpoint(out, context.ips[i]);
  }
  fprintf(out, "],\"truncated\":%s}", context.truncated ? "true" : "false");
  explicit_bzero(&context, sizeof(context));
}
