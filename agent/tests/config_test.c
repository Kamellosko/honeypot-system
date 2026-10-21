#define _GNU_SOURCE
#include "config.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <tdb.h>
#include <sys/stat.h>

int main(void) {
  struct hp_options options;
  char *defaults[] = { "agent", NULL };
  assert(hp_parse_args(1, defaults, &options) == 0);
  assert(!strcmp(options.id, AGENT_ID) && !strcmp(options.ip, DEST_IP));
  assert(options.port == DEST_PORT);
  char *partial[] = { "agent", "--port", "8443", NULL };
  assert(hp_parse_args(3, partial, &options) == 0 && options.port == 8443);
  char *override[] = { "agent", "--id", "other", "--ip", "::1", "--port", "9443", NULL };
  assert(hp_parse_args(7, override, &options) == 0);
  assert(!strcmp(options.id, "other") && !strcmp(options.ip, "::1") && options.port == 9443);
  char *duplicate[] = { "agent", "--id", "a", "--id", "b", NULL };
  assert(hp_parse_args(5, duplicate, &options) != 0);
  assert(hp_parse_args(2, partial, &options) != 0);
  char *unknown[] = { "agent", "--other", "x", NULL };
  assert(hp_parse_args(3, unknown, &options) != 0);
  struct hp_sources sources = {0};
  assert(hp_validate_args("agent", "127.0.0.1", "443") == 0);
  assert(hp_validate_args("", "127.0.0.1", "443") != 0);
  assert(hp_validate_args("agent", "host.example", "443") != 0);
  assert(hp_validate_args("agent", "127.0.0.1", "65536") != 0);
  char root[] = "/tmp/hp-native-config-XXXXXX", config[256], include[256], database[256], text[4096];
  assert(mkdtemp(root));
  snprintf(config, sizeof(config), "%s/smb.conf", root);
  snprintf(include, sizeof(include), "%s/included.conf", root);
  snprintf(database, sizeof(database), "%s/passdb.tdb", root);
  FILE *file = fopen(include, "w");
  assert(file && fputs("[files]\npath = /tmp\n[print$]\nprintable = Yes\n", file) >= 0 && !fclose(file));
  file = fopen(config, "w");
  assert(file && fprintf(file, "[global]\ninclude = %s\n", include) > 0 && !fclose(file));
  assert(!hp_discover_config(config, &sources));
  assert(sources.count == 1 && !strcmp(sources.items[0].path, "/tmp"));
  hp_sources_free(&sources);
  struct passwd *pw = getpwuid(geteuid());
  assert(pw);
  struct tdb_context *db = tdb_open(database, 0, TDB_DEFAULT, O_CREAT | O_EXCL | O_RDWR, 0600);
  assert(db);
  unsigned char version[] = {4,0,0,0}, value[] = "fixture";
  TDB_DATA key = {(unsigned char *)"INFO/version", sizeof("INFO/version")}, data = {version, sizeof(version)};
  assert(!tdb_store(db, key, data, TDB_INSERT));
  snprintf(text, sizeof(text), "USER_%s", pw->pw_name);
  key = (TDB_DATA){(unsigned char *)text, strlen(text) + 1};
  data = (TDB_DATA){value, sizeof(value)};
  assert(!tdb_store(db, key, data, TDB_INSERT) && !tdb_close(db));
  file = fopen(config, "w");
  assert(file && fprintf(file, "[global]\npassdb backend = tdbsam:%s\n[homes]\npath = %%H\n", database) > 0 && !fclose(file));
  assert(!hp_discover_config(config, &sources));
  assert(sources.count == 1 && sources.items[0].kind == HP_SHARE && !strcmp(sources.items[0].path, pw->pw_dir));
  hp_sources_free(&sources);
  file = fopen(config, "w");
  assert(file && fputs("[global]\nconfig backend = registry\n[files]\npath = /tmp\n", file) >= 0 && !fclose(file));
  assert(!hp_discover_config(config, &sources));
  assert(sources.count == 1 && sources.items[0].kind == HP_SOURCE_STATUS && sources.items[0].error);
  hp_sources_free(&sources);
  file = fopen(config, "w");
  assert(file && fprintf(file, "[global]\ninclude = %s\n", config) > 0 && !fclose(file));
  assert(!hp_discover_config(config, &sources));
  assert(sources.count == 1 && !strcmp(sources.items[0].error, "include_depth_or_cycle"));
  hp_sources_free(&sources);
  assert(!unlink(config) && !unlink(include) && !unlink(database) && !rmdir(root));
  return 0;
}
