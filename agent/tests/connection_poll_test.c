#define _GNU_SOURCE
#include "connections.h"
#include "network.h"
#include "snapshot.h"
#include <assert.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static int mode, family, interrupted;
static uint32_t sequence;
int __wrap_socket(int domain, int type, int protocol) {
  assert(domain == AF_NETLINK && type == (SOCK_DGRAM | SOCK_CLOEXEC) && protocol == NETLINK_SOCK_DIAG);
  return 12345;
}
int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t size) {
  (void)value; (void)size;
  assert(fd == 12345 && level == SOL_SOCKET && option == SO_RCVTIMEO);
  return 0;
}
int __real_close(int fd);
int __wrap_close(int fd) { return fd == 12345 ? 0 : __real_close(fd); }
const char *__wrap_hp_lookup_mac(const char *ip, char mac[18], char device[IF_NAMESIZE]) {
  (void)ip; mac[0] = device[0] = 0;
  return "not_in_local_arp_cache";
}
ssize_t __wrap_sendto(int fd, const void *data, size_t size, int flags, const struct sockaddr *to, socklen_t length) {
  (void)to; (void)length;
  assert(fd == 12345 && flags == 0);
  const struct nlmsghdr *header = data;
  const struct inet_diag_req_v2 *request = NLMSG_DATA(header);
  assert(header->nlmsg_type == SOCK_DIAG_BY_FAMILY && request->sdiag_protocol == IPPROTO_TCP);
  assert(request->idiag_states == ((1U << TCP_ESTABLISHED) | (1U << TCP_LISTEN)));
  family = request->sdiag_family; sequence = header->nlmsg_seq;
  return size;
}
ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags) {
  assert(fd == 12345 && flags == 0);
  if (interrupted) { interrupted = 0; errno = EINTR; return -1; }
  if (mode == 6) { errno = EAGAIN; return -1; }
  struct sockaddr_nl *sender = message->msg_name;
  sender->nl_family = AF_NETLINK; sender->nl_pid = mode == 5 ? 10 : 0;
  message->msg_namelen = sizeof(*sender);
  message->msg_flags = mode == 1 ? MSG_TRUNC : 0;
  unsigned char *buffer = message->msg_iov[0].iov_base;
  size_t used = 0;
  for (int i = 0; i < (family == AF_INET ? 2 : 0); i++) {
    struct nlmsghdr *header = (struct nlmsghdr *)(buffer + used);
    memset(header, 0, NLMSG_SPACE(sizeof(struct inet_diag_msg)));
    header->nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_msg));
    header->nlmsg_type = SOCK_DIAG_BY_FAMILY;
    header->nlmsg_seq = mode == 2 ? sequence + 1 : sequence;
    header->nlmsg_flags = mode == 3 ? NLM_F_DUMP_INTR : NLM_F_MULTI;
    struct inet_diag_msg *entry = NLMSG_DATA(header);
    entry->idiag_family = family; entry->idiag_state = i ? TCP_ESTABLISHED : TCP_LISTEN;
    entry->id.idiag_sport = htons(445); entry->id.idiag_dport = htons(i ? 50000 : 0);
    entry->id.idiag_cookie[0] = i + 1;
    assert(inet_pton(AF_INET, "192.0.2.1", entry->id.idiag_src) == 1);
    if (i) assert(inet_pton(AF_INET, "198.51.100.8", entry->id.idiag_dst) == 1);
    used += NLMSG_SPACE(sizeof(*entry));
  }
  struct nlmsghdr *done = (struct nlmsghdr *)(buffer + used);
  memset(done, 0, NLMSG_SPACE(sizeof(int)));
  done->nlmsg_len = NLMSG_LENGTH(mode == 4 ? 0 : sizeof(int));
  done->nlmsg_type = NLMSG_DONE; done->nlmsg_seq = sequence;
  used += NLMSG_ALIGN(done->nlmsg_len);
  return used;
}

int main(void) {
  char path[] = "/tmp/hp-connection-poll-XXXXXX";
  struct hp_store store;
  struct hp_connections observer = {0};
  assert(mkdtemp(path) && !hp_store_init(&store, path, "test"));
  interrupted = 1;
  assert(!hp_connections_poll(&observer, &store, 100));
  assert(observer.count == 1 && hp_store_pending_count(&store) == 1);
  assert(!hp_connections_poll(&observer, &store, 100.5));
  assert(!hp_connections_poll(&observer, &store, 101));
  assert(hp_store_pending_count(&store) == 1);
  for (mode = 1; mode <= 6; mode++) {
    double now = 102 + mode;
    assert(hp_connections_poll(&observer, &store, now) != 0);
    assert(hp_connections_poll(&observer, &store, now + .1) != 0);
    assert(observer.count == 1 && hp_store_pending_count(&store) == 1);
  }
  mode = 0;
  assert(!hp_connections_poll(&observer, &store, 200));
  assert(hp_store_pending_count(&store) == 1);
  hp_connections_close(&observer); hp_store_close(&store);
  return 0;
}
