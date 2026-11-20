#define _GNU_SOURCE
#include "cJSON.h"
#include "monitor.h"
#include "snapshot.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Linie SYNTETYCZNE (zakladany format firewalld; do potwierdzenia na Almie). */
static void fw(char *out, size_t n, const char *tag, int port) {
  snprintf(out, n,
           "Nov 20 12:00:00 honey %s filter_IN_public_REJECT: IN=eth0 OUT= SRC=192.0.2.50 DST=10.0.0.2 LEN=44 "
           "PROTO=TCP SPT=51000 DPT=%d WINDOW=1024 RES=0x00 SYN URGP=0\n", tag, port);
}

struct env { char dir[64], state[128], log[160]; struct hp_store store; struct hp_monitor monitor; };

static void setup(struct env *e, const char *logname) {
  strcpy(e->dir, "/tmp/hp-scan-XXXXXX");
  assert(mkdtemp(e->dir));
  snprintf(e->state, sizeof(e->state), "%s/state", e->dir);
  snprintf(e->log, sizeof(e->log), "%s/%s", e->dir, logname);
  FILE *f = fopen(e->log, "w"); assert(f); fclose(f);
  assert(hp_store_init(&e->store, e->state, "agent") == 0);
  assert(hp_monitor_init(&e->monitor, &e->store) == 0);
  assert(hp_monitor_add_log(&e->monitor, e->log) == 0);
  assert(hp_monitor_poll(&e->monitor, 0) == 0);  /* pierwszy odczyt ustawia offset na koniec pliku */
}

static void append(const struct env *e, const char *text) {
  FILE *f = fopen(e->log, "a"); assert(f); fputs(text, f); assert(!fclose(f));
}

static void append_fw(const struct env *e, const char *tag, int first, int count) {
  char line[512];
  for (int i = 0; i < count; i++) { fw(line, sizeof(line), tag, first + i); append(e, line); }
}

/* Liczy raporty w pending/ o danym event.type (type == NULL: wszystkie). */
static int count_type(const struct env *e, const char *type) {
  char pending[256];
  snprintf(pending, sizeof(pending), "%s/pending", e->state);
  DIR *d = opendir(pending); assert(d);
  int count = 0;
  struct dirent *ent;
  while ((ent = readdir(d))) {
    if (ent->d_name[0] == '.') continue;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", pending, ent->d_name);
    FILE *f = fopen(path, "r"); assert(f);
    char *buf = malloc(1 << 20); assert(buf);
    size_t n = fread(buf, 1, (1 << 20) - 1, f); buf[n] = 0; fclose(f);
    cJSON *j = cJSON_Parse(buf); assert(j);
    cJSON *ev = cJSON_GetObjectItem(j, "event");
    cJSON *t = ev ? cJSON_GetObjectItem(ev, "type") : NULL;
    if (!type || (t && (t->type & 0xFF) == cJSON_String && !strcmp(t->valuestring, type))) count++;
    cJSON_Delete(j); free(buf);
  }
  closedir(d);
  return count;
}

static void finish(struct env *e) { hp_monitor_close(&e->monitor); hp_store_close(&e->store); }

int main(void) {
  struct env e;

  /* jeden skan: jedno net.scan, zadnych raportow z linii zapory, zwykla linia nadal raportowana */
  setup(&e, "messages");
  append(&e, "Nov 20 12:00:00 honey sshd[7]: Failed password for bob from 203.0.113.9 port 5 ssh2\n");
  append_fw(&e, "kernel:", 100, 12);
  assert(hp_monitor_poll(&e.monitor, 0) == 0);
  assert(count_type(&e, "net.scan") == 1);
  assert(count_type(&e, "auth.failure") == 1);
  assert(count_type(&e, NULL) == 2);
  finish(&e);

  /* ponizej progu: nic nie jest raportowane (linie zapory sa konsumowane) */
  setup(&e, "messages");
  append_fw(&e, "kernel:", 100, 9);
  assert(hp_monitor_poll(&e.monitor, 0) == 0);
  assert(count_type(&e, NULL) == 0);
  finish(&e);

  /* podrobione linie (znacznik sshd[1]:) sa zwyklymi wpisami loga, nie skanem */
  setup(&e, "messages");
  append_fw(&e, "sshd[1]:", 100, 12);
  assert(hp_monitor_poll(&e.monitor, 0) == 0);
  assert(count_type(&e, "net.scan") == 0 && count_type(&e, NULL) == 12);
  finish(&e);

  /* UDP/ICMP z logu zapory: zero raportow (nie zalewamy serwera szumem broadcastow) */
  setup(&e, "messages");
  for (int i = 0; i < 20; i++) {
    char line[512];
    snprintf(line, sizeof(line), "Nov 20 12:00:00 honey kernel: filter_IN_public_REJECT: IN=eth0 OUT= SRC=192.0.2.9 "
             "DST=255.255.255.255 LEN=229 PROTO=UDP SPT=138 DPT=%d LEN=209\n", 100 + i);
    append(&e, line);
  }
  assert(hp_monitor_poll(&e.monitor, 0) == 0);
  assert(count_type(&e, NULL) == 0);
  finish(&e);

  /* tylko log o nazwie "messages" zasila tracker */
  setup(&e, "other.log");
  append_fw(&e, "kernel:", 100, 3);
  assert(hp_monitor_poll(&e.monitor, 0) == 0);
  assert(count_type(&e, NULL) == 3 && count_type(&e, "net.scan") == 0);
  finish(&e);

  /* nieudany zapis raportu net.scan jest ponawiany, nic sie nie gubi, bez duplikatu */
  setup(&e, "messages");
  char pending[256];
  snprintf(pending, sizeof(pending), "%s/pending", e.state);
  append_fw(&e, "kernel:", 100, 12);
  assert(chmod(pending, 0500) == 0);
  assert(hp_monitor_poll(&e.monitor, 0) != 0);
  assert(chmod(pending, 0700) == 0);
  assert(hp_monitor_poll(&e.monitor, 0) == 0);
  assert(count_type(&e, "net.scan") == 1);
  assert(hp_monitor_poll(&e.monitor, 0) == 0);
  assert(count_type(&e, "net.scan") == 1);
  finish(&e);

  puts("PASS monitor_scan");
  return 0;
}
