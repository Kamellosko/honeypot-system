#define _GNU_SOURCE
#include "connections.h"
#include "snapshot.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define HP_SOCKET_LIMIT 65536

static int socket_compare(const void *a, const void *b) {
  const struct hp_tcp_socket *x = a, *y = b;
  int n = memcmp(x->cookie, y->cookie, sizeof(x->cookie));
  if (n) return n;
  if (x->family != y->family) return x->family - y->family;
  n = memcmp(x->local, y->local, sizeof(x->local));
  if (n) return n;
  n = memcmp(x->peer, y->peer, sizeof(x->peer));
  if (n) return n;
  if (x->local_port != y->local_port) return (int)x->local_port - y->local_port;
  return (int)x->peer_port - y->peer_port;
}

static int port_compare(const void *a, const void *b) {
  const struct hp_tcp_socket *x = a, *y = b;
  if (x->state != y->state) return (int)x->state - y->state;
  return (int)x->local_port - y->local_port;
}

static int has_listener(const struct hp_tcp_socket *socket, struct hp_tcp_socket *all, size_t count) {
  struct hp_tcp_socket key = { .state = TCP_LISTEN, .local_port = socket->local_port };
  struct hp_tcp_socket *match = bsearch(&key, all, count, sizeof(*all), port_compare);
  if (!match) return 0;
  while (match > all && !port_compare(&key, match - 1)) match--;
  static const unsigned char zero[16];
  for (; match < all + count && !port_compare(&key, match); match++) {
    if (match->family == socket->family &&
        (!memcmp(match->local, zero, sizeof(zero)) || !memcmp(match->local, socket->local, sizeof(socket->local)))) return 1;
  }
  return 0;
}

static int socket_ip(const struct hp_tcp_socket *socket, const unsigned char *address, char out[INET6_ADDRSTRLEN]) {
  int family = socket->family;
  struct in6_addr v6;
  memcpy(&v6, address, sizeof(v6));
  if (family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&v6)) { family = AF_INET; address += 12; }
  return inet_ntop(family, address, out, INET6_ADDRSTRLEN) ? 0 : -1;
}

int hp_connections_update(struct hp_connections *observer, struct hp_store *store,
                          struct hp_tcp_socket *sockets, size_t count) {
  if (count > HP_SOCKET_LIMIT) return -1;
  struct hp_tcp_socket *next = count ? calloc(count, sizeof(*next)) : NULL;
  if (count && !next) return -1;
  size_t next_count = 0;
  int failed = 0;
  if (count) qsort(sockets, count, sizeof(*sockets), port_compare);
  for (size_t i = 0; i < count; i++) {
    struct hp_tcp_socket *socket = &sockets[i];
    if (socket->state != TCP_ESTABLISHED) continue;
    int known = observer->count && bsearch(socket, observer->seen, observer->count, sizeof(*observer->seen), socket_compare);
    if (!known && !has_listener(socket, sockets, count)) continue;
    char local[INET6_ADDRSTRLEN], peer[INET6_ADDRSTRLEN];
    int report_failed = !known && (socket_ip(socket, socket->local, local) || socket_ip(socket, socket->peer, peer) ||
                   hp_report_connection(store, local, socket->local_port, peer, socket->peer_port));
    explicit_bzero(local, sizeof(local)); explicit_bzero(peer, sizeof(peer));
    if (report_failed) { failed = 1; continue; }
    next[next_count++] = *socket;
  }
  if (next_count) qsort(next, next_count, sizeof(*next), socket_compare);
  if (observer->seen) explicit_bzero(observer->seen, observer->count * sizeof(*observer->seen));
  free(observer->seen);
  observer->seen = next; observer->count = next_count;
  return failed ? -1 : 0;
}

static int append_socket(struct hp_tcp_socket **sockets, size_t *count, size_t *capacity,
                         const struct inet_diag_msg *message) {
  if (message->idiag_family != AF_INET && message->idiag_family != AF_INET6) return -1;
  if (*count == HP_SOCKET_LIMIT) return -1;
  if (*count == *capacity) {
    size_t size = *capacity ? *capacity * 2 : 128;
    struct hp_tcp_socket *next = malloc(size * sizeof(*next));
    if (!next) return -1;
    if (*count) memcpy(next, *sockets, *count * sizeof(*next));
    if (*sockets) explicit_bzero(*sockets, *count * sizeof(**sockets));
    free(*sockets);
    *sockets = next; *capacity = size;
  }
  struct hp_tcp_socket *socket = &(*sockets)[(*count)++];
  memset(socket, 0, sizeof(*socket));
  socket->family = message->idiag_family; socket->state = message->idiag_state;
  socket->local_port = ntohs(message->id.idiag_sport);
  socket->peer_port = ntohs(message->id.idiag_dport);
  memcpy(socket->local, message->id.idiag_src, socket->family == AF_INET ? 4 : 16);
  memcpy(socket->peer, message->id.idiag_dst, socket->family == AF_INET ? 4 : 16);
  memcpy(socket->cookie, message->id.idiag_cookie, sizeof(socket->cookie));
  return 0;
}

static int collect_family(int fd, int family, uint32_t sequence, struct hp_tcp_socket **sockets,
                           size_t *count, size_t *capacity) {
  union { struct nlmsghdr alignment; unsigned char bytes[32768]; } buffer;
  int result = -1;
  struct {
    struct nlmsghdr header;
    struct inet_diag_req_v2 request;
  } query = {
    .header = { .nlmsg_len = sizeof(query), .nlmsg_type = SOCK_DIAG_BY_FAMILY,
                .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP, .nlmsg_seq = sequence },
    .request = { .sdiag_family = family, .sdiag_protocol = IPPROTO_TCP,
                 .idiag_states = (1U << TCP_LISTEN) | (1U << TCP_ESTABLISHED) }
  };
  struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
  if (sendto(fd, &query, sizeof(query), 0, (struct sockaddr *)&kernel, sizeof(kernel)) != sizeof(query)) goto done;
  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start)) goto done;
  for (;;) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec >= 2) goto done;
    explicit_bzero(&buffer, sizeof(buffer));
    struct sockaddr_nl sender = {0};
    struct iovec io = { .iov_base = buffer.bytes, .iov_len = sizeof(buffer.bytes) };
    struct msghdr reply = { .msg_name = &sender, .msg_namelen = sizeof(sender), .msg_iov = &io, .msg_iovlen = 1 };
    ssize_t n = recvmsg(fd, &reply, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0 || reply.msg_flags & MSG_TRUNC || reply.msg_namelen != sizeof(sender) || sender.nl_pid) goto done;
    int remaining = (int)n;
    for (struct nlmsghdr *header = (struct nlmsghdr *)buffer.bytes; NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
      if (header->nlmsg_seq != sequence || header->nlmsg_flags & NLM_F_DUMP_INTR) goto done;
      if (header->nlmsg_type == NLMSG_DONE) {
        if (NLMSG_PAYLOAD(header, 0) < sizeof(int)) goto done;
        int error;
        memcpy(&error, NLMSG_DATA(header), sizeof(error));
        result = error ? -1 : 0; goto done;
      }
      if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY || NLMSG_PAYLOAD(header, 0) < sizeof(struct inet_diag_msg)) goto done;
      const struct inet_diag_msg *message = NLMSG_DATA(header);
      if (message->idiag_family != family || append_socket(sockets, count, capacity, message)) goto done;
    }
    if (remaining) goto done;
  }
done:
  explicit_bzero(&buffer, sizeof(buffer));
  return result;
}

int hp_connections_poll(struct hp_connections *observer, struct hp_store *store, double now) {
  if (now < observer->next_poll) return observer->failed ? -1 : 0;
  observer->next_poll = now + 1;
  int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
  if (fd < 0) { observer->failed = 1; return -1; }
  struct timeval timeout = { .tv_sec = 1 };
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) { close(fd); observer->failed = 1; return -1; }
  struct hp_tcp_socket *sockets = NULL;
  size_t count = 0, capacity = 0;
  int failed = collect_family(fd, AF_INET, 1, &sockets, &count, &capacity) ||
               collect_family(fd, AF_INET6, 2, &sockets, &count, &capacity);
  close(fd);
  if (!failed) failed = hp_connections_update(observer, store, sockets, count);
  if (sockets) explicit_bzero(sockets, count * sizeof(*sockets));
  free(sockets);
  observer->failed = !!failed;
  return failed ? -1 : 0;
}

void hp_connections_close(struct hp_connections *observer) {
  if (observer->seen) explicit_bzero(observer->seen, observer->count * sizeof(*observer->seen));
  free(observer->seen);
  explicit_bzero(observer, sizeof(*observer));
}
