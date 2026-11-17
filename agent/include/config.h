#pragma once
#include <stddef.h>

#ifndef AGENT_ID
#define AGENT_ID "alma10-01"
#endif
#ifndef DEST_IP
#define DEST_IP "127.0.0.1"
#endif
#ifndef DEST_PORT
#define DEST_PORT 443
#endif
#ifndef HEARTBEAT_INTERVAL
#define HEARTBEAT_INTERVAL 60
#endif
#if HEARTBEAT_INTERVAL <= 0
#error "HEARTBEAT_INTERVAL must be positive"
#endif

struct hp_options {
  const char *id;
  const char *ip;
  unsigned short port;
};
int hp_parse_args(int argc, char *const argv[], struct hp_options *options);

enum hp_source_kind { HP_SHARE, HP_LOG, HP_SOURCE_STATUS };
struct hp_source {
  enum hp_source_kind kind;
  char *name;
  char *path;
  char *error;
};
struct hp_sources {
  struct hp_source *items;
  size_t count;
};

int hp_validate_args(const char *id, const char *ip, const char *port);
int hp_discover_config(const char *path, struct hp_sources *sources);
int hp_discover_sources(struct hp_sources *sources);
void hp_sources_free(struct hp_sources *sources);
