#pragma once
#include <stddef.h>
#include <stdint.h>

struct hp_store;
struct hp_tcp_socket {
  int family;
  unsigned char local[16], peer[16];
  unsigned short local_port, peer_port;
  unsigned char state;
  uint32_t cookie[2];
};
struct hp_connections {
  struct hp_tcp_socket *seen;
  size_t count;
  double next_poll;
  int failed;
};

/* update sorts the supplied complete socket snapshot in place. */
int hp_connections_update(struct hp_connections *observer, struct hp_store *store,
                          struct hp_tcp_socket *sockets, size_t count);
int hp_connections_poll(struct hp_connections *observer, struct hp_store *store, double now);
void hp_connections_close(struct hp_connections *observer);
