#define _GNU_SOURCE
#include "event.h"
#include "cJSON.h"
#include "protocol.h"
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

  /* nazwa uzytkownika wygladajaca jak IP nie podmienia adresu klienta (takze loopback i adres admina) */
  LOG(e, "Failed password for invalid user 9.9.9.9 from 203.0.113.50 port 5000 ssh2");
  assert(!strcmp(e.user, "9.9.9.9") && !strcmp(e.src_ip, "203.0.113.50") && e.src_port == 5000);
  LOG(e, "Failed password for invalid user 127.0.0.1 from 203.0.113.50 port 5001 ssh2");
  assert(!strcmp(e.src_ip, "203.0.113.50") && e.src_port == 5001);
  LOG(e, "Failed password for 10.0.0.5 from 203.0.113.50 port 5002 ssh2");
  assert(!strcmp(e.src_ip, "203.0.113.50") && !strcmp(e.user, "10.0.0.5"));
  LOG(e, "Failed password for invalid user x from 9.9.9.9 port 1 from 203.0.113.50 port 7 ssh2");
  assert(!strcmp(e.src_ip, "203.0.113.50") && e.src_port == 7);
  LOG(e, "Failed password for 192.168.56.1");
  assert(!e.src_ip[0]);   /* bez " from " nie zgadujemy adresu z nazwy uzytkownika */
  /* sshd: nieistniejace konto -> auth.invalid_user (nie auth.failure, bo "Failed password" liczy sie osobno) */
  LOG(e, "Nov 26 10:00:00 honey sshd[9]: Invalid user admin from 203.0.113.9 port 50022");
  assert(!strcmp(e.type, "auth.invalid_user") && !strcmp(e.service, "ssh") && !strcmp(e.outcome, "failure"));
  assert(!strcmp(e.user, "admin") && !strcmp(e.src_ip, "203.0.113.9") && e.src_port == 50022);
  assert(!strcmp(hp_classify("append", (const unsigned char *)"Invalid user a from 1.2.3.4 port 1", 34), "invalid_user"));
  /* nazwa z " from " i falszywym IP nie podmienia adresu klienta */
  LOG(e, "Invalid user x from 9.9.9.9 port 1 from 203.0.113.9 port 7");
  assert(!strcmp(e.src_ip, "203.0.113.9") && e.src_port == 7 && !strcmp(e.user, "x from 9.9.9.9 port 1"));
  LOG(e, "Invalid user root from 2001:db8::5 port 22");
  assert(!strcmp(e.src_ip, "2001:db8::5") && e.src_port == 22);
  /* linia z haslem wygrywa: to nadal auth.failure */
  LOG(e, "Invalid user bob from 203.0.113.9 port 1\nFailed password for invalid user bob from 203.0.113.9 port 1 ssh2");
  assert(!strcmp(e.type, "auth.failure"));

  /* sonda banera SSH (nmap -sV) -> net.probe */
  LOG(e, "sshd[3]: Did not receive identification string from 198.51.100.4 port 61000");
  assert(!strcmp(e.type, "net.probe") && !strcmp(e.category, "network") && !strcmp(e.service, "ssh"));
  assert(!strcmp(e.src_ip, "198.51.100.4") && e.src_port == 61000);
  LOG(e, "sshd[3]: banner exchange: Connection from 198.51.100.4 port 61001: invalid format");
  assert(!strcmp(e.type, "net.probe") && !strcmp(e.src_ip, "198.51.100.4") && e.src_port == 61001);
  LOG(e, "sshd[3]: error: kex_exchange_identification: Connection closed by remote host");
  assert(!strcmp(e.type, "net.probe") && !e.src_ip[0]);

  /* Samba: odmowa dostepu -> auth.denied, serwis smb */
  LOG(e, "Auth: [SMB2,(null)] user [DOM]\\[guest] at [x] status [NT_STATUS_ACCESS_DENIED] remote host [ipv4:192.0.2.8:49282]");
  assert(!strcmp(e.type, "auth.denied") && !strcmp(e.service, "smb") && !strcmp(e.user, "guest"));
  assert(!strcmp(e.src_ip, "192.0.2.8"));
  LOG(e, "smbd_audit[5]: bob|192.0.2.8|pc|share|open|fail (NT_STATUS_ACCESS_DENIED)|x");
  assert(!strcmp(e.type, "samba.audit"));

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

  /* auth.attempt: linia hp-pam (skrypt hook PAM), 5. pole syslog = znacznik programu */
  LOG(e, "Nov 20 12:00:00 honey hp-pam: u=Ym9i h=203.0.113.9 p=aHVudGVyMg==");
  assert(!strcmp(e.type, "auth.attempt") && !strcmp(e.category, "authentication"));
  assert(!strcmp(e.outcome, "failure") && !strcmp(e.severity, "medium") && !strcmp(e.service, "ssh"));
  assert(!strcmp(e.user, "bob") && !strcmp(e.src_ip, "203.0.113.9"));
  assert(e.has_password && e.password_len == 7 && !memcmp(e.password, "hunter2", 7));
  assert(!strcmp(hp_classify("append", (const unsigned char *)"Nov 20 12:00:00 honey hp-pam: u=Ym9i h=1.2.3.4 p=QQ==", 49),
                 "authentication_attempt"));
  j = written(&e);
  ev = cJSON_GetObjectItem(j, "event");
  assert(!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(ev, "credential"), "password")->valuestring, "hunter2"));
  assert(IS_NULL(cJSON_GetObjectItem(ev, "detail")));
  cJSON_Delete(j);

  LOG(e, "Nov 20 12:00:00 honey hp-pam: u=Ym9i h=203.0.113.9 p=");
  assert(!strcmp(e.type, "auth.attempt") && e.has_password && e.password_len == 0);
  j = written(&e);
  assert(!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(j, "event"), "credential"), "password")->valuestring, ""));
  cJSON_Delete(j);

  LOG(e, "Nov 20 12:00:00 honey hp-pam: u=Ym9i h=203.0.113.9 p=YSJiCmM=");  /* a"b<LF>c */
  j = written(&e);
  assert(!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(cJSON_GetObjectItem(j, "event"), "credential"), "password")->valuestring, "a\"b\nc"));
  cJSON_Delete(j);

  LOG(e, "Nov 20 12:00:00 honey hp-pam: u=Ym9i h=203.0.113.9 p=eP8=");     /* 'x' 0xff: nie-UTF-8 */
  j = written(&e);
  cJSON *cred = cJSON_GetObjectItem(cJSON_GetObjectItem(j, "event"), "credential");
  assert(IS_NULL(cJSON_GetObjectItem(cred, "password")));
  assert(!strcmp(cJSON_GetObjectItem(cred, "password_base64")->valuestring, "eP8="));
  cJSON_Delete(j);

  /* podrobiona linia: nazwa uzytkownika sshd zawiera "hp-pam: ..." (znacznik programu to sshd[7]:) */
  LOG(e, "Nov 20 12:00:00 honey sshd[7]: Failed password for invalid user hp-pam: u=Ym9i h=1.2.3.4 p=QQ== from 203.0.113.9 port 1 ssh2");
  assert(!strcmp(e.type, "auth.failure") && !e.has_password);

  /* uszkodzone: zly base64, brak p=, brak u=, puste u= */
  LOG(e, "Nov 20 12:00:00 honey hp-pam: u=Ym9i h=203.0.113.9 p=@@@");
  assert(!strcmp(e.type, "log.entry") && !e.has_password);
  LOG(e, "Nov 20 12:00:00 honey hp-pam: u=Ym9i h=203.0.113.9");
  assert(!strcmp(e.type, "log.entry"));
  LOG(e, "Nov 20 12:00:00 honey hp-pam: h=203.0.113.9 p=QQ==");
  assert(!strcmp(e.type, "log.entry"));
  LOG(e, "Nov 20 12:00:00 honey hp-pam: u= h=203.0.113.9 p=QQ==");
  assert(!strcmp(e.type, "log.entry"));

  /* haslo dluzsze niz 256 bajtow jest obcinane (300 x 'A') */
  char longpw[900] = "Nov 20 12:00:00 honey hp-pam: u=Ym9i h=203.0.113.9 p=";
  for (int i = 0; i < 100; i++) strcat(longpw, "QUFB");
  LOG(e, longpw);
  assert(e.has_password && e.password_len == 256);

  /* nazwa uzytkownika spoza UTF-8 (base64 w linii hp-pam) nie moze dawac niepoprawnego JSON */
  LOG(e, "Nov 20 12:00:00 honey hp-pam: u=/3g= h=203.0.113.9 p=QQ==");
  assert(!strcmp(e.type, "auth.attempt") && e.has_password);
  assert(!strcmp(e.user, "?x") && hp_valid_utf8((const unsigned char *)e.user, strlen(e.user)));
  LOG(e, "Nov 20 12:00:00 honey hp-pam: u=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYcOp h=203.0.113.9 p=QQ==");  /* 127 x 'a' + e-acute: ciecie w srodku znaku */
  assert(strlen(e.user) == 128 && hp_valid_utf8((const unsigned char *)e.user, strlen(e.user)));

  /* dobrze zbudowana linia z blednym znacznikiem programu nie jest hp-pam (znacznik to 5. pole) */
  LOG(e, "Nov 20 12:00:00 honey sshd[7]: u=Ym9i h=1.2.3.4 p=QQ==");
  assert(!strcmp(e.type, "log.entry") && !e.has_password);
  /* udane logowanie nigdy nie daje auth.attempt */
  LOG(e, "Accepted password for bob from 203.0.113.9 port 1 ssh2");
  assert(!strcmp(e.type, "auth.success") && !e.has_password);

  /* net.scan */
  struct hp_scan_hit hit = { "192.0.2.50", "10.0.0.2", 12, "syn", 10 };
  hp_event_scan(&e, &hit);
  assert(!strcmp(e.type, "net.scan") && !strcmp(e.category, "network") && !strcmp(e.severity, "medium"));
  assert(!strcmp(e.outcome, "unknown") && !strcmp(e.src_ip, "192.0.2.50") && e.dst_port == -1 && e.src_port == -1);
  j = written(&e);
  ev = cJSON_GetObjectItem(j, "event");
  cJSON *det = cJSON_GetObjectItem(ev, "detail");
  assert(cJSON_GetObjectItem(det, "ports")->valueint == 12 && cJSON_GetObjectItem(det, "window_seconds")->valueint == 10);
  assert(!strcmp(cJSON_GetObjectItem(det, "scan")->valuestring, "syn"));
  assert(IS_NULL(cJSON_GetObjectItem(cJSON_GetObjectItem(ev, "dst"), "port")));
  assert(!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(ev, "dst"), "ip")->valuestring, "10.0.0.2"));
  assert(IS_NULL(cJSON_GetObjectItem(ev, "credential")));
  cJSON_Delete(j);

  /* wszystkie pozostale zdarzenia maja credential i detail = null */
  LOG(e, "Failed password for alice from 203.0.113.9 port 1 ssh2");
  j = written(&e);
  ev = cJSON_GetObjectItem(j, "event");
  assert(IS_NULL(cJSON_GetObjectItem(ev, "credential")) && IS_NULL(cJSON_GetObjectItem(ev, "detail")));
  cJSON_Delete(j);
  hp_event_file(&e, "create");
  j = written(&e);
  ev = cJSON_GetObjectItem(j, "event");
  assert(IS_NULL(cJSON_GetObjectItem(ev, "credential")) && IS_NULL(cJSON_GetObjectItem(ev, "detail")));
  cJSON_Delete(j);
  return 0;
}
