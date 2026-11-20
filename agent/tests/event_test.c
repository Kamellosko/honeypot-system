#define _GNU_SOURCE
#include "event.h"
#include "cJSON.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define IS_NULL(x) ((x) && ((x)->type & 0xFF) == cJSON_NULL)
#define LOG(e, text) hp_event_from_log(&(e), "log", "append", (const unsigned char *)(text), strlen(text))

static cJSON *written(const struct hp_event *e) {
  char *buf = NULL; size_t len = 0;
  FILE *f = open_memstream(&buf, &len);
  assert(f);
  fputc('{', f);
  hp_event_write(f, e);
  fputc('}', f);
  fclose(f);
  /* zapis zaczyna sie od przecinka: {,"event":...} -> zamien na {"event":...} */
  assert(buf[1] == ',');
  buf[1] = ' ';
  cJSON *json = cJSON_Parse(buf);
  free(buf);
  assert(json);
  return json;
}

int main(void) {
  struct hp_event e;

  LOG(e, "Failed password for invalid user bob from 203.0.113.9 port 4242 ssh2");
  assert(!strcmp(e.type, "auth.failure") && !strcmp(e.category, "authentication"));
  assert(!strcmp(e.outcome, "failure") && !strcmp(e.severity, "medium") && !strcmp(e.service, "ssh"));
  assert(!strcmp(e.src_ip, "203.0.113.9") && e.src_port == 4242 && !strcmp(e.user, "bob"));

  LOG(e, "Accepted password for finance from 198.51.100.7 port 5000 ssh2");
  assert(!strcmp(e.type, "auth.success") && !strcmp(e.outcome, "success") && !strcmp(e.severity, "high"));
  assert(!strcmp(e.user, "finance") && !strcmp(e.src_ip, "198.51.100.7") && e.src_port == 5000);

  LOG(e, "Failed password for invalid user a b from 203.0.113.9 port 1 ssh2");
  assert(!strcmp(e.user, "a"));

  char longuser[400] = "Failed password for ";
  memset(longuser + strlen(longuser), 'x', 300);
  strcpy(longuser + strlen(longuser), " from 203.0.113.9 port 1 ssh2");
  LOG(e, longuser);
  assert(strlen(e.user) == 128);

  LOG(e, "Failed password for alice from 203.0.113.9 port 1 ssh2\nAccepted password for alice from 203.0.113.9 port 2 ssh2\n");
  assert(!strcmp(e.type, "auth.failure") && e.src_port == 1);

  LOG(e, "Nov 18 13:16:46 fs smbd_audit[39615]: a.kowalska|192.0.2.8|pc|Archiwum_|openat|ok|r|/srv/samba/x");
  assert(!strcmp(e.type, "samba.audit") && !strcmp(e.service, "smb") && !strcmp(e.severity, "low"));
  assert(!strcmp(e.user, "a.kowalska") && !strcmp(e.src_ip, "192.0.2.8"));

  LOG(e, "Auth: [SMB2,(null)] user [DOM]\\[bob] at [x] status [NT_STATUS_WRONG_PASSWORD] remote host [ipv4:192.0.2.8:49282]");
  assert(!strcmp(e.type, "auth.failure") && !strcmp(e.service, "smb") && !strcmp(e.user, "bob"));
  assert(!strcmp(e.src_ip, "192.0.2.8"));

  LOG(e, "status [NT_STATUS_WRONG_PASSWORD] remote host [ipv4:192.0.2.8:49282]");
  assert(!strcmp(e.type, "auth.failure") && !strcmp(e.service, "smb") && !e.user[0]);

  LOG(e, "Failed password for root from 2001:db8::1 port 22 ssh2");
  assert(!strcmp(e.src_ip, "2001:db8::1"));

  LOG(e, "some unrelated syslog line");
  assert(!strcmp(e.type, "log.entry") && !strcmp(e.severity, "info") && !e.src_ip[0] && e.src_port == -1);

  hp_event_from_log(&e, "system", "heartbeat", NULL, 0);
  assert(!strcmp(e.type, "system.heartbeat") && !strcmp(e.severity, "info") && !strcmp(e.category, "system"));
  assert(!e.service && !e.src_ip[0] && !e.dst_ip[0] && !e.user[0] && e.src_port == -1 && e.dst_port == -1);

  hp_event_from_log(&e, "monitor", "observation_gap", NULL, 0);
  assert(!strcmp(e.type, "system.observation_gap") && !strcmp(e.severity, "medium"));
  hp_event_from_log(&e, "source", "source_unavailable", NULL, 0);
  assert(!strcmp(e.type, "system.source_unavailable"));

  assert(!strcmp(hp_classify("append", (const unsigned char *)"Failed password for x", 21), "authentication_failure"));
  assert(!strcmp(hp_classify("heartbeat", NULL, 0), "heartbeat"));
  assert(!strcmp(hp_classify("append", NULL, 0), "unknown"));

  /* JSON: brak danych -> null; user ze znakami specjalnymi jest poprawnie zescapowany */
  hp_event_from_log(&e, "system", "heartbeat", NULL, 0);
  cJSON *j = written(&e);
  cJSON *ev = cJSON_GetObjectItem(j, "event");
  assert(IS_NULL(cJSON_GetObjectItem(ev, "src")) && IS_NULL(cJSON_GetObjectItem(ev, "user")));
  assert(!strcmp(cJSON_GetObjectItem(ev, "type")->valuestring, "system.heartbeat"));
  cJSON_Delete(j);

  hp_event_from_log(&e, "log", "append", (const unsigned char *)"Failed password for x from 203.0.113.9 port 7 ssh2", 51);
  strcpy(e.user, "a\"b|c");
  j = written(&e);
  ev = cJSON_GetObjectItem(j, "event");
  assert(!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(ev, "user"), "name")->valuestring, "a\"b|c"));
  cJSON *src = cJSON_GetObjectItem(ev, "src");
  assert(!strcmp(cJSON_GetObjectItem(src, "ip")->valuestring, "203.0.113.9"));
  assert(cJSON_GetObjectItem(src, "port")->valueint == 7 && IS_NULL(cJSON_GetObjectItem(src, "mac")));
  assert(IS_NULL(cJSON_GetObjectItem(ev, "dst")));
  cJSON_Delete(j);
  return 0;
}
