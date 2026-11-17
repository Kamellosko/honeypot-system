#define _GNU_SOURCE
#include "network.h"
#include <errno.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// Kept apart from network.c on purpose: the tests replace hp_lookup_mac with the linker's
// --wrap, and that only works for calls that cross a file boundary.

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
