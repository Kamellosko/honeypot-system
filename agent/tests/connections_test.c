#define _GNU_SOURCE
#include "connections.h"
#include "snapshot.h"
#include "cJSON.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct hp_tcp_socket connection(int state, unsigned port, unsigned cookie) {
  struct hp_tcp_socket socket = { .family = AF_INET, .state = state, .local_port = port,
                                 .peer_port = 50000, .cookie = {cookie, 0} };
  assert(inet_pton(AF_INET, "192.0.2.1", socket.local) == 1);
  assert(inet_pton(AF_INET, "198.51.100.8", socket.peer) == 1);
  return socket;
}

int main(void) {
  char path[] = "/tmp/hp-connections-XXXXXX";
  struct hp_store store;
  struct hp_connections observer = {0};
  assert(mkdtemp(path) && !hp_store_init(&store, path, "test"));
  struct hp_tcp_socket sockets[] = { connection(TCP_LISTEN, 445, 1), connection(TCP_SYN_RECV, 445, 2),
    connection(TCP_ESTABLISHED, 445, 3), connection(TCP_ESTABLISHED, 50001, 4) };
  assert(!hp_connections_update(&observer, &store, sockets, 4));
  assert(hp_store_pending_count(&store) == 1 && observer.count == 1);
  assert(!hp_connections_update(&observer, &store, sockets, 4));
  assert(hp_store_pending_count(&store) == 1);
  struct hp_tcp_socket ongoing = connection(TCP_ESTABLISHED, 445, 3);
  assert(!hp_connections_update(&observer, &store, &ongoing, 1));
  assert(observer.count == 1 && hp_store_pending_count(&store) == 1);
  sockets[0] = connection(TCP_LISTEN, 65535, 5);
  sockets[1] = connection(TCP_ESTABLISHED, 65535, 6);
  assert(!hp_connections_update(&observer, &store, sockets, 2));
  assert(hp_store_pending_count(&store) == 2);
  for (size_t i = 0; i < 2; i++) if (sockets[i].state == TCP_ESTABLISHED) sockets[i].cookie[0] = 7;
  int fd = store.pending_fd;
  store.pending_fd = -1;
  assert(hp_connections_update(&observer, &store, sockets, 2) != 0);
  store.pending_fd = fd;
  assert(!hp_connections_update(&observer, &store, sockets, 2));
  assert(hp_store_pending_count(&store) == 3);
  assert(!hp_connections_update(&observer, &store, NULL, 0) && observer.count == 0);
  sockets[0] = connection(TCP_LISTEN, 22, 8);
  sockets[1] = connection(TCP_ESTABLISHED, 22, 9);
  for (size_t i = 0; i < 2; i++) {
    sockets[i].family = AF_INET6;
    memset(sockets[i].local, 0, sizeof(sockets[i].local));
    memset(sockets[i].peer, 0, sizeof(sockets[i].peer));
  }
  assert(inet_pton(AF_INET6, "2001:db8::2", sockets[1].local) == 1);
  assert(inet_pton(AF_INET6, "2001:db8::1", sockets[1].peer) == 1);
  assert(!hp_connections_update(&observer, &store, sockets, 2));
  assert(hp_store_pending_count(&store) == 4 && observer.count == 1);
  hp_connections_close(&observer);
  char pending[256];
  snprintf(pending, sizeof(pending), "%s/pending", path);
  DIR *dir = opendir(pending);
  assert(dir);
  struct dirent *ent;
  while ((ent = readdir(dir))) {
    if (!strstr(ent->d_name, ".json")) continue;
    char file[512], text[4096];
    snprintf(file, sizeof(file), "%s/%s", pending, ent->d_name);
    FILE *in = fopen(file, "r");
    assert(in);
    size_t n = fread(text, 1, sizeof(text) - 1, in);
    text[n] = 0; fclose(in);
    cJSON *json = cJSON_Parse(text);
    assert(json && !strcmp(cJSON_GetObjectItem(json, "operation")->valuestring, "tcp_connection_observed"));
    cJSON *details = cJSON_GetObjectItem(json, "connection");
    assert(details && !strcmp(cJSON_GetObjectItem(details, "state")->valuestring, "ESTABLISHED"));
    assert(cJSON_GetObjectItem(details, "peer_port")->valueint == 50000);
    cJSON *peer = cJSON_GetObjectItem(details, "peer");
    const char *ip = cJSON_GetObjectItem(peer, "ip")->valuestring;
    assert(!strcmp(ip, "198.51.100.8") || !strcmp(ip, "2001:db8::1"));
    cJSON_Delete(json);
  }
  closedir(dir);
  hp_store_close(&store);
  return 0;
}
