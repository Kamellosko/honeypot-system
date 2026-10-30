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

const char *hp_lookup_mac(const char *ip, char mac[18], char device[IF_NAMESIZE]) {
  mac[0] = device[0] = 0;
  struct sockaddr_in target = { .sin_family = AF_INET };
  if (inet_pton(AF_INET, ip, &target.sin_addr) != 1) {
    struct in6_addr v6;
    return inet_pton(AF_INET6, ip, &v6) == 1 ? "ipv6_no_arp" : "invalid_ip";
  }
  struct ifaddrs *interfaces;
  if (getifaddrs(&interfaces)) return "lookup_error";
  int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { freeifaddrs(interfaces); return "lookup_error"; }
  const char *status = "not_in_local_arp_cache";
  int failed = 0;
  for (const struct ifaddrs *p = interfaces; p; p = p->ifa_next) {
    if (!p->ifa_name || !p->ifa_addr || !p->ifa_netmask || p->ifa_addr->sa_family != AF_INET ||
        !(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
    const struct sockaddr_in *local = (const struct sockaddr_in *)p->ifa_addr;
    const struct sockaddr_in *mask = (const struct sockaddr_in *)p->ifa_netmask;
    if ((local->sin_addr.s_addr ^ target.sin_addr.s_addr) & mask->sin_addr.s_addr) continue;
    struct arpreq entry = {0};
    memcpy(&entry.arp_pa, &target, sizeof(target));
    if (snprintf(entry.arp_dev, sizeof(entry.arp_dev), "%s", p->ifa_name) >= (int)sizeof(entry.arp_dev)) {
      failed = 1; continue;
    }
    if (ioctl(fd, SIOCGARP, &entry)) {
      if (errno != ENXIO && errno != ENOENT && errno != ENODEV) failed = 1;
      continue;
    }
    const unsigned char *bytes = (const unsigned char *)entry.arp_ha.sa_data;
    static const unsigned char zero[6];
    if (!(entry.arp_flags & ATF_COM) || entry.arp_ha.sa_family != ARPHRD_ETHER ||
        (bytes[0] & 1) || !memcmp(bytes, zero, sizeof(zero))) continue;
    if (device[0] && strcmp(device, p->ifa_name)) { status = "ambiguous_interfaces"; break; }
    snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    snprintf(device, IF_NAMESIZE, "%s", p->ifa_name);
    status = "resolved";
  }
  close(fd); freeifaddrs(interfaces);
  if (failed && strcmp(status, "ambiguous_interfaces")) status = "lookup_error";
  if (strcmp(status, "resolved")) { explicit_bzero(mac, 18); explicit_bzero(device, IF_NAMESIZE); }
  return status;
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
