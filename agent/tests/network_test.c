#define _GNU_SOURCE
#include "network.h"
#include "cJSON.h"
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static struct ifaddrs interfaces[2];
static struct sockaddr_in addresses[2], masks[2];
static int socket_error, list_error, arp_error, incomplete, invalid_mac;
static int arp_calls, socket_calls;

int __wrap_getifaddrs(struct ifaddrs **out) {
  if (list_error) { errno = EIO; return -1; }
  *out = interfaces;
  return 0;
}
void __wrap_freeifaddrs(struct ifaddrs *list) { assert(list == interfaces); }
int __wrap_socket(int family, int type, int protocol) {
  assert(family == AF_INET && type == (SOCK_DGRAM | SOCK_CLOEXEC) && !protocol);
  socket_calls++;
  if (socket_error) { errno = EPERM; return -1; }
  return 12345;
}
int __real_close(int fd);
int __wrap_close(int fd) { return fd == 12345 ? 0 : __real_close(fd); }
int __wrap_ioctl(int fd, unsigned long request, ...) {
  assert(fd == 12345 && request == SIOCGARP);
  va_list args;
  va_start(args, request);
  struct arpreq *entry = va_arg(args, struct arpreq *);
  va_end(args);
  arp_calls++;
  if (arp_error) { errno = arp_error; return -1; }
  assert(!strcmp(entry->arp_dev, "eth0") || !strcmp(entry->arp_dev, "eth1"));
  struct sockaddr_in target;
  memcpy(&target, &entry->arp_pa, sizeof(target));
  assert(target.sin_family == AF_INET && target.sin_addr.s_addr == inet_addr("192.0.2.8"));
  entry->arp_flags = incomplete ? 0 : ATF_COM;
  entry->arp_ha.sa_family = ARPHRD_ETHER;
  const unsigned char mac[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
  memcpy(entry->arp_ha.sa_data, mac, sizeof(mac));
  if (invalid_mac) memset(entry->arp_ha.sa_data, 0, sizeof(mac));
  return 0;
}

static void setup(void) {
  memset(interfaces, 0, sizeof(interfaces));
  for (int i = 0; i < 2; i++) {
    addresses[i].sin_family = masks[i].sin_family = AF_INET;
    assert(inet_pton(AF_INET, "192.0.2.1", &addresses[i].sin_addr) == 1);
    assert(inet_pton(AF_INET, "255.255.255.0", &masks[i].sin_addr) == 1);
    interfaces[i].ifa_addr = (struct sockaddr *)&addresses[i];
    interfaces[i].ifa_netmask = (struct sockaddr *)&masks[i];
    interfaces[i].ifa_flags = IFF_UP;
  }
  interfaces[0].ifa_name = "eth0";
  interfaces[1].ifa_name = "eth1";
}

int main(void) {
  struct hp_network_context context;
  const unsigned char log[] = "rhost=192.0.2.8 from [2001:db8::1]:445 SRC=192.0.2.8 invalid=999.1.2.3 v192.0.2.1";
  hp_extract_ips(log, sizeof(log) - 1, &context);
  assert(context.count == 2 && !context.truncated);
  assert(!strcmp(context.ips[0], "192.0.2.8") && !strcmp(context.ips[1], "2001:db8::1"));
  const unsigned char ports[] = "client=192.0.2.8:445 mapped=::ffff:192.0.2.8 junk=192.0.2.7:99999 bad=192.0.2.4oops";
  hp_extract_ips(ports, sizeof(ports) - 1, &context);
  assert(context.count == 1 && !strcmp(context.ips[0], "192.0.2.8"));
  const unsigned char samba[] = "status [NT_STATUS_WRONG_PASSWORD] remote host [ipv4:192.0.2.8:49282]. local host [ipv4:192.0.2.1:445]";
  hp_extract_ips(samba, sizeof(samba) - 1, &context);
  assert(context.count == 2 && !strcmp(context.ips[0], "192.0.2.8") && !strcmp(context.ips[1], "192.0.2.1"));
  const unsigned char spoofed[] = "user=192.0.2.11 192.0.2.12 192.0.2.13 192.0.2.14 192.0.2.15 192.0.2.16 192.0.2.17 192.0.2.18 192.0.2.19 remote host [ipv4:192.0.2.8:49282]";
  hp_extract_ips(spoofed, sizeof(spoofed) - 1, &context);
  assert(context.count == HP_NETWORK_MAX && context.truncated && !strcmp(context.ips[0], "192.0.2.8"));
  const unsigned char binary[] = {'x', 0, '1','9','2','.','0','.','2','.','8',' ', 0xff};
  hp_extract_ips(binary, sizeof(binary), &context);
  assert(context.count == 1);
  const unsigned char many[] = "192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4 192.0.2.5 192.0.2.6 192.0.2.7 192.0.2.8 192.0.2.9";
  hp_extract_ips(many, sizeof(many) - 1, &context);
  assert(context.count == HP_NETWORK_MAX && context.truncated);
  setup();
  char mac[18], device[IF_NAMESIZE];
  assert(!strcmp(hp_lookup_mac("192.0.2.8", mac, device), "resolved"));
  assert(!strcmp(mac, "02:11:22:33:44:55") && !strcmp(device, "eth0"));
  arp_error = ENXIO;
  assert(!strcmp(hp_lookup_mac("192.0.2.8", mac, device), "not_in_local_arp_cache") && !mac[0] && !device[0]);
  arp_error = EACCES;
  assert(!strcmp(hp_lookup_mac("192.0.2.8", mac, device), "lookup_error"));
  arp_error = 0;
  incomplete = 1;
  assert(!strcmp(hp_lookup_mac("192.0.2.8", mac, device), "not_in_local_arp_cache"));
  incomplete = 0; invalid_mac = 1;
  assert(!strcmp(hp_lookup_mac("192.0.2.8", mac, device), "not_in_local_arp_cache"));
  invalid_mac = 0;
  interfaces[0].ifa_next = &interfaces[1];
  assert(!strcmp(hp_lookup_mac("192.0.2.8", mac, device), "ambiguous_interfaces") && !mac[0] && !device[0]);
  interfaces[0].ifa_next = NULL;
  int previous = arp_calls;
  assert(!strcmp(hp_lookup_mac("198.51.100.8", mac, device), "not_in_local_arp_cache"));
  assert(arp_calls == previous);
  previous = socket_calls;
  assert(!strcmp(hp_lookup_mac("2001:db8::1", mac, device), "ipv6_no_arp"));
  assert(socket_calls == previous);
  socket_error = 1;
  assert(!strcmp(hp_lookup_mac("192.0.2.8", mac, device), "lookup_error"));
  socket_error = 0; list_error = 1;
  assert(!strcmp(hp_lookup_mac("192.0.2.8", mac, device), "lookup_error"));
  list_error = 0;
  char *text = NULL;
  size_t size = 0;
  FILE *out = open_memstream(&text, &size);
  assert(out);
  hp_write_network_context(out, log, sizeof(log) - 1);
  assert(!fclose(out));
  cJSON *json = cJSON_Parse(text);
  assert(json);
  cJSON *endpoints = cJSON_GetObjectItem(json, "endpoints");
  assert(cJSON_GetArraySize(endpoints) == 2);
  cJSON *entry = cJSON_GetArrayItem(endpoints, 0);
  assert(!strcmp(cJSON_GetObjectItem(entry, "ip")->valuestring, "192.0.2.8"));
  assert(cJSON_GetObjectItem(entry, "mac")->type == cJSON_NULL);
  assert(cJSON_GetObjectItem(entry, "context_only")->type == cJSON_True);
  entry = cJSON_GetArrayItem(endpoints, 1);
  assert(cJSON_GetObjectItem(entry, "mac")->type == cJSON_NULL);
  cJSON_Delete(json); free(text);
  const unsigned char text_only[] = "user=192.0.2.8";
  text = NULL; size = 0;
  out = open_memstream(&text, &size);
  assert(out);
  hp_write_network_context(out, text_only, sizeof(text_only) - 1);
  assert(!fclose(out));
  assert(strstr(text, "\"mac_status\":\"not_looked_up\"") && strstr(text, "\"mac\":null") && !strstr(text, "resolved"));
  free(text);
  return 0;
}
