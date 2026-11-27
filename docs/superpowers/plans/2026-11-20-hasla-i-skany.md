# Hasła z prób SSH i wykrywanie skanów portów Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agent wysyła zdarzenia `auth.attempt` (próbowane hasło SSH) i `net.scan` (skan portów po progu); serwer je przyjmuje i liczy.

**Architecture:** Hasła: skrypt `hp-pam-log` wywoływany z PAM po nieudanym sprawdzeniu hasła zapisuje linię `hp-pam:` do syslogu (`/var/log/secure`), a agent parsuje ją w `event.c`. Skany: `firewalld --set-log-denied` zapisuje odrzucone pakiety do `/var/log/messages`; nowy moduł `scan.c` konsumuje te linie w `poll_logs`, liczy różne porty na źródło w oknie i po progu emituje jedno `net.scan`. Serwer: walidacja nowych pól i atakujący z `net.scan`.

**Tech Stack:** C (agent, `agent/Makefile`, testy `assert`), Java 17 + Javalin + JUnit 5 (`server/`, `mvn -q test`), sh (skrypty).

**Spec:** `docs/superpowers/specs/2026-11-20-hasla-i-skany-design.md`. Plan etapu 1 (styl, wcześniejsze zmiany): `docs/superpowers/plans/2026-11-20-schemat-zdarzen-wersja-dev.md`.

## Global Constraints

- Agent: prefiks `hp_`, dwie spacje wcięcia, sprawdzanie błędów, bez zmian w `third_party/` (cJSON).
- `auth.attempt`: `category` `authentication`, `severity` `medium`, `outcome` `failure`, `service` `ssh`. `net.scan`: `category` `network`, `severity` `medium`, `outcome` `unknown`, `src.ip` ustawione, `dst.port` `null`.
- Próg skanu: **10** różnych portów w **10** s; tablica źródeł: **1024** wpisy, wypieranie najstarszego. Rodzaje: `syn`, `null`, `xmas`, `fin`, `other` (rodzaj pierwszego pakietu w oknie).
- `event.credential` to `null` albo `{"password": <tekst>}`; hasło nie-UTF-8 to `{"password": null, "password_base64": <tekst>}`. `event.detail` to `null` albo `{"ports": <int>, "scan": <rodzaj>, "window_seconds": <int>}`. Oba pola są zapisywane zawsze (`null` gdy nie dotyczą). Zmiana jest addytywna w `schema_version` 2.
- Hasło udanego logowania **nigdy** nie jest zapisywane. Hook PAM nie może blokować, opóźniać ani zmieniać wyniku uwierzytelniania.
- Linia `hp-pam:` ma postać `hp-pam: u=<base64 użytkownika> h=<rhost> p=<base64 hasła>` (moja decyzja ze spec §4.1: użytkownik też w base64, bo nazwa może zawierać spacje).
- `VERSION` i `server/pom.xml`: `0.3.0`.
- Kolejność zadań: T1 → T2 → T3 (agent, jedno drzewo plików); T4 (skrypt) i T5 (serwer) są niezależne od siebie i od T1–T3; T6 po T4; T7 na końcu.

## Review Focus

Wejścia, których spec nie wymienia, a które realnie wystąpią (każde ma test w zadaniu-właścicielu):
1. **Podrobione linie w logu** (T2, T1): atakujący wpisuje w nazwie użytkownika SSH tekst `hp-pam: u=... p=...` albo `SRC=... DPT=... PROTO=TCP`; linia trafia do `/var/log/secure`. Fałszywe `auth.attempt` i fałszywy skan nie mogą powstać, a prawdziwa linia `Failed password` nie może zniknąć z raportów. Dlatego oba parsery wymagają znacznika programu w 5. polu linii syslog (`hp-pam:` albo `kernel:`).
2. **Hasło z bajtami spoza UTF-8, cudzysłowem, `\n`, puste** (T2): JSON nadal poprawny, puste hasło daje `"password":""`.
3. **Zalew źródeł** (T1): 100 000 różnych (podrobionych) adresów nie zwiększa pamięci ponad tablicę 1024 i nie wiesza agenta.
4. **Ten sam port wielokrotnie, granica progu** (T1): 9 różnych portów (też z powtórzeniami) nie daje zdarzenia, 10 daje jedno, dalsze porty w oknie nie dają drugiego, po wygaśnięciu okna można znów.
5. **Uszkodzony base64 lub brak pola w `hp-pam:`** (T2): brak `auth.attempt`, linia zostaje zwykłym wpisem loga, brak awarii.

---

### Task 1: Moduł `scan` (parser linii zapory i licznik źródeł)

**Files:**
- Create: `agent/include/scan.h`, `agent/src/scan.c`, `agent/tests/scan_test.c`
- Modify: `agent/Makefile` (dopisz `scan` do `TESTS`; jeśli reguła testów wymaga listy obiektów, dodaj `scan.c`)

**Interfaces:**
- Produces (`scan.h`, dołącza `<arpa/inet.h>`, `<stddef.h>`, `<time.h>`):
  - `#define HP_SCAN_PORTS_DEFAULT 10`, `HP_SCAN_WINDOW_DEFAULT 10`, `HP_SCAN_SOURCES 1024`, `HP_SCAN_PORTS_MAX 64`
  - `struct hp_scan_packet { char src_ip[INET6_ADDRSTRLEN]; char dst_ip[INET6_ADDRSTRLEN]; int dst_port; const char *kind; };`
  - `struct hp_scan_hit { char src_ip[INET6_ADDRSTRLEN]; char dst_ip[INET6_ADDRSTRLEN]; int ports; const char *kind; int window_seconds; };`
  - `int hp_scan_parse(const unsigned char *line, size_t len, struct hp_scan_packet *p);` zwraca 1 dla linii zapory (patrz Step 3), inaczej 0.
  - `struct hp_scan_tracker` (nieprzezroczysta dla wywołującego, alokowana przez `hp_scan_new`)
  - `struct hp_scan_tracker *hp_scan_new(int threshold, int window_seconds);` (`NULL` przy błędzie; `threshold` przycinany do `HP_SCAN_PORTS_MAX`), `void hp_scan_free(struct hp_scan_tracker *t);`
  - `int hp_scan_feed(struct hp_scan_tracker *t, const unsigned char *line, size_t len, time_t now, struct hp_scan_hit *hit);` zwraca `0` (to nie linia zapory), `1` (skonsumowana, brak zdarzenia), `2` (skonsumowana, próg osiągnięty, `hit` wypełnione).
  - `void hp_scan_ack(struct hp_scan_tracker *t, const char *src_ip);` wycisza źródło do końca jego okna.

- [ ] **Step 1: Napisz `agent/tests/scan_test.c`.** Linie testowe są **syntetyczne** (zakładany format firewalld, do potwierdzenia na Almie w T6), np. `"Nov 20 12:00:00 honey kernel: filter_IN_public_REJECT: IN=eth0 OUT= SRC=192.0.2.50 DST=10.0.0.2 LEN=44 PROTO=TCP SPT=51000 DPT=81 WINDOW=1024 RES=0x00 SYN URGP=0"`. Pomocnik `fw(ip, port, flags)` buduje linię. Testy i asercje:
  - `parse_syn`: `hp_scan_parse` → 1, `src_ip=="192.0.2.50"`, `dst_ip=="10.0.0.2"`, `dst_port==81`, `kind=="syn"`; flagi `""` → `"null"`, `"FIN PSH URG"` → `"xmas"`, `"FIN"` → `"fin"`, `"SYN ACK"` → `"other"`; źródło IPv6 `2001:db8::1` parsuje się.
  - `parse_rejects`: 0 dla linii bez `kernel:` w 5. polu (`"Nov 20 12:00:00 honey sshd[1]: Failed password for invalid user SRC=1.2.3.4 DPT=80 PROTO=TCP IN=x from 203.0.113.9 port 1 ssh2"`), dla `PROTO=UDP`, dla `DPT=0` i `DPT=70000`, dla `SRC=` nie będącego adresem IP, dla pustej linii.
  - `threshold`: `hp_scan_new(10,10)`; 9 różnych portów z jednego IP (i trzykrotne powtórzenie portu 81) → same `1`; 10. różny port → `2`, `hit.ports==10`, `hit.kind=="syn"`, `hit.window_seconds==10`, `hit.src_ip` zgodne.
  - `no_second_hit_after_ack`: po `hp_scan_ack` kolejne porty w tym samym oknie → `1`; bez `ack` kolejny pakiet znów zwraca `2` (ponowienie po nieudanym raporcie); po `now+11` s okno się resetuje i 10 nowych portów znów daje `2`.
  - `two_sources_independent`: dwa IP po 6 portów → brak `2`.
  - `flood_bounded`: 100 000 różnych IP po jednym pakiecie → wszystkie `1`, brak awarii (sprawdza wypieranie); potem prawdziwy skaner z 10 portami nadal daje `2`.
  - `not_firewall`: `hp_scan_feed` na zwykłej linii → `0`.
- [ ] **Step 2: Uruchom** `cd agent && make build/scan_test && build/scan_test` — oczekiwane: FAIL (brak `scan.h`).
- [ ] **Step 3: Zaimplementuj `scan.h`/`scan.c`.** `hp_scan_parse`: linia jest linią zapory tylko gdy 5. pole rozdzielone spacjami (pola: miesiąc, dzień, czas, host, znacznik) to dokładnie `kernel:` oraz zawiera tokeny `SRC=`, `DST=`, `PROTO=TCP`, `DPT=` (1–65535). Adresy walidować `inet_pton` (IPv4 lub IPv6). Rodzaj z samodzielnych słów flag po `RES=`: samo `SYN` → `syn`; brak flag → `null`; dokładnie `FIN PSH URG` (dowolna kolejność) → `xmas`; samo `FIN` → `fin`; reszta → `other`. Tracker: tablica `HP_SCAN_SOURCES` wpisów `{src_ip, dst_ip, first_seen, muted, kind, nports, ports[HP_SCAN_PORTS_MAX]}`; wpis wygasa, gdy `now - first_seen > window`; przy braku miejsca wypiera wpis o najstarszym `first_seen`; różne porty sprawdzane liniowo; `nports` nie przekracza `threshold`.
- [ ] **Step 4: Uruchom** `cd agent && make build/scan_test && build/scan_test` — oczekiwane: PASS.
- [ ] **Step 5: Drugi kompilator i sanitizer** (stała tablica): `cd agent && make clean && make CC=clang build/scan_test && build/scan_test` oraz zbuduj `scan_test` z `-fsanitize=address,undefined` (jeśli `Makefile` nie przyjmuje flag, skompiluj ręcznie `scan.c` i `scan_test.c`). Oczekiwane: PASS. W raporcie wymień, czego nie dało się uruchomić.
- [ ] **Step 6: Commit** `git add agent/include/scan.h agent/src/scan.c agent/tests/scan_test.c agent/Makefile && git commit -m "Agent: modul scan (parser linii zapory, licznik zrodel)"`

### Task 2: Zdarzenia `auth.attempt` i `net.scan` w `event.c`

**Files:**
- Modify: `agent/include/event.h`, `agent/src/event.c` (`hp_classify`, `hp_event_from_log`, `hp_event_write`; nowa `hp_event_scan`)
- Test: `agent/tests/event_test.c` (dopisz)

**Interfaces:**
- Consumes: `struct hp_scan_hit` z T1 (`event.h` dołącza `scan.h`).
- Produces: pola `struct hp_event`: `int has_password; unsigned char password[257]; size_t password_len; int scan_ports; const char *scan_kind; int scan_window;` (0/`NULL` = brak). `void hp_event_scan(struct hp_event *e, const struct hp_scan_hit *hit);` ustawia `net.scan` (kategoria `network`, `medium`, `outcome` `unknown`, `src_ip`, `dst_ip`, `dst_port=-1`, `scan_*`). `hp_classify` zwraca `"authentication_attempt"` dla linii `hp-pam:` (sprawdzane **przed** `is_failure`). `hp_event_write` zapisuje zawsze `"credential"` i `"detail"` (`null` gdy brak).

- [ ] **Step 1: Napisz testy w `event_test.c`** (linie z nagłówkiem syslog; asercje na `hp_event` i na JSON z `written()`):
  - `attempt_basic`: `"Nov 20 12:00:00 honey hp-pam: u=Ym9i h=203.0.113.9 p=aHVudGVyMg=="` → `type=="auth.attempt"`, `outcome=="failure"`, `severity=="medium"`, `service=="ssh"`, `user=="bob"`, `src_ip=="203.0.113.9"`, hasło `"hunter2"`; JSON: `event.credential.password=="hunter2"`.
  - `attempt_empty_password`: `p=` puste → `has_password==1`, długość 0, JSON `"password":""`.
  - `attempt_special`: hasło z `"`, `\n`, bajtem `0xff` → JSON się parsuje; dla `0xff` `credential.password` jest `null`, a `credential.password_base64` równe wejściowemu base64.
  - `attempt_forged`: `"Nov 20 12:00:00 honey sshd[7]: Failed password for invalid user hp-pam: u=Ym9i h=1.2.3.4 p=QQ== from 203.0.113.9 port 1 ssh2"` → `type=="auth.failure"` (nie `auth.attempt`), `has_password==0`.
  - `attempt_bad`: uszkodzony base64 (`p=@@@`), brak `p=`, brak `u=` → `type=="log.entry"`, brak awarii.
  - `attempt_long`: hasło 300 bajtów → obcięte do 256.
  - `scan_event`: `hp_event_scan` z `hit{src "192.0.2.50", dst "10.0.0.2", ports 12, kind "syn", window 10}` → `type=="net.scan"`, `src_ip`, `dst_port==-1`; JSON: `event.detail=={"ports":12,"scan":"syn","window_seconds":10}`, `event.dst.port` null.
  - `null_fields`: każde istniejące zdarzenie (np. `auth.failure`, `file.change`) ma w JSON `"credential":null` i `"detail":null`.
- [ ] **Step 2: Uruchom** `cd agent && make build/event_test && build/event_test` — oczekiwane: FAIL.
- [ ] **Step 3: Zaimplementuj.** `parse_pam_attempt(e, line, len)` w `event.c`: akceptuje linię tylko gdy 5. pole (po `Mon DD HH:MM:SS host`) to dokładnie `hp-pam:` i są pola `u=`, `h=`, `p=` w tej kolejności; dekoduje base64 (własna mała funkcja `static` w `event.c`; błąd dekodowania lub `u=` puste = linia odrzucona); `h=` kopiuje do `src_ip` tylko gdy to poprawny IP (`inet_pton`); użytkownik przez istniejące `copy_user`; hasło obcinane do 256 bajtów. `hp_event_write`: hasło jako tekst gdy `hp_valid_utf8` (z `io.h`/`protocol.h`, jak w `snapshot.c`), w przeciwnym razie `password:null` + `password_base64` przez `hp_json_base64`.
- [ ] **Step 4: Uruchom** `cd agent && make check` — oczekiwane: wszystkie PASS (istniejące testy JSON nie mogą zakładać braku nowych pól; popraw je, jeśli sprawdzają dokładny kształt).
- [ ] **Step 5: Commit** `git add agent && git commit -m "Agent: zdarzenia auth.attempt i net.scan, pola credential i detail"`

### Task 3: Podpięcie skanu w monitorze i raport `net.scan`

**Files:**
- Modify: `agent/include/monitor.h` (pole `struct hp_scan_tracker *scan;` w `struct hp_monitor`), `agent/src/monitor.c` (`hp_monitor_init`/`hp_monitor_close`, `poll_logs` ~linia 224), `agent/include/snapshot.h` + `agent/src/snapshot.c` (nowa `hp_report_scan`)
- Test: `agent/tests/log_test.c` (dopisz; użyj tych samych pomocników co istniejące testy raportów loga)

**Interfaces:**
- Consumes: `hp_scan_new/free/feed/ack`, `struct hp_scan_hit` (T1); `hp_event_scan` (T2).
- Produces: `int hp_report_scan(struct hp_store *s, const struct hp_scan_hit *hit);` raport o `source` `"network"`, `operation` `"port_scan_detected"`, `classification` `"port_scan"`, z blokiem `event` z `hp_event_scan`, wzorowany na `hp_report_connection`. Zwraca 0/-1.

- [ ] **Step 1: Napisz testy w `log_test.c`:** log `/var/log/messages`-podobny w katalogu tymczasowym, dopisane 12 linii zapory z jednego IP na 12 różnych portów oraz jedna zwykła linia (`Failed password ...`) przed nimi. Oczekiwane: dokładnie **jeden** raport `net.scan` (`event.detail.ports>=10`, `event.src.ip` zgodne), **zero** raportów `log.entry` z linii zapory, linia `Failed password` nadal ma własny raport `auth.failure`. Drugi test: 9 portów → zero `net.scan`, zero raportów z tych linii. Trzeci: linia zapory z `sshd[1]:` zamiast `kernel:` (podrobiona) → raportowana jak zwykła linia loga. Czwarty: po nieudanym zapisie raportu `net.scan` (wymuś błąd jak w `report_failure_test.c`) kolejne `hp_monitor_poll` ponawia raport i nie gubi go.
- [ ] **Step 2: Uruchom** `cd agent && make build/log_test && build/log_test` — oczekiwane: FAIL.
- [ ] **Step 3: Zaimplementuj.** `hp_monitor_init` tworzy `hp_scan_new(HP_SCAN_PORTS_DEFAULT, HP_SCAN_WINDOW_DEFAULT)` (błąd → zwróć błąd inicjalizacji), `hp_monitor_close` zwalnia. W `poll_logs`, w miejscu gdzie dziś jest `hp_report_simple(... "append" ...)` dla pełnej linii (z końcem `\n`): gdy ścieżka logu to `/var/log/messages`, wywołaj `hp_scan_feed(m->scan, log->partial, log->partial_size, time(NULL), &hit)`; dla `1` pomiń `hp_report_simple` (linia skonsumowana); dla `2` wywołaj `hp_report_scan`, a po sukcesie `hp_scan_ack`; porażka raportu obsługiwana jak dziś (przewiń `offset`, `failed=1`) — ponowne podanie tej samej linii zwróci `2` ponownie. `hp_store_record_log` nadal wywoływane dla każdej linii. Segmenty `long_record_segment` nie idą do trackera. Skan i próg: stałe domyślne, bez konfiguracji w czasie działania (shortcut: stałe z `scan.h`, konfigurowalne w etapie 4).
- [ ] **Step 4: Uruchom** `cd agent && make check` — oczekiwane: wszystkie PASS. Dodatkowo zbuduj `scan_test` i `log_test` pod `-fsanitize=address,undefined` i `CC=clang` (jak w T1 Step 5).
- [ ] **Step 5: Commit** `git add agent && git commit -m "Agent: net.scan z logu zapory (jeden raport na skan, linie zapory nie sa raportowane osobno)"`

### Task 4: Skrypt `hp-pam-log`

**Files:**
- Create: `scripts/hp-pam-log`, `scripts/tests/pam_log_test.sh`
- Modify: `agent/Makefile` (w `check` dodaj `sh ../scripts/tests/pam_log_test.sh`)

**Interfaces:**
- Produces: `scripts/hp-pam-log`: czyta hasło ze stdin (pierwsza linia, bez końcowego `\n`), bierze `PAM_USER` i `PAM_RHOST` ze środowiska, wywołuje `logger -p authpriv.info -t hp-pam "u=<b64 PAM_USER> h=<PAM_RHOST> p=<b64 hasła>"` (`base64 -w0`). Zawsze kończy się kodem 0 (hook nie może zmienić wyniku PAM), brak wyjścia na stdout/stderr.

- [ ] **Step 1: Napisz `pam_log_test.sh`:** podstaw `logger` skryptem-stubem w `PATH` zapisującym argumenty do pliku. Przypadki: zwykłe hasło (`hunter2`) → argument `u=<b64> h=203.0.113.9 p=aHVudGVyMg==`; hasło ze spacją, `"`, `=`; puste hasło (`p=`); brak `PAM_RHOST` (`h=` puste, nadal kod 0); `logger` zwraca błąd → skrypt nadal kod 0 i brak wyjścia. Test porównuje także, że stub dostał `-t hp-pam` i `-p authpriv.info`.
- [ ] **Step 2: Uruchom** `sh scripts/tests/pam_log_test.sh` — oczekiwane: FAIL (brak skryptu).
- [ ] **Step 3: Zaimplementuj `scripts/hp-pam-log`** (`#!/bin/sh`, `umask 077`, bez `set -e`; hasło czytane przez `IFS= read -r`).
- [ ] **Step 4: Uruchom** `sh scripts/tests/pam_log_test.sh` i `cd agent && make check` — oczekiwane: PASS.
- [ ] **Step 5: Commit** `git add scripts agent/Makefile && git commit -m "Skrypt hp-pam-log (hook PAM: proba hasla do syslogu)"`

### Task 5: Serwer, schemat i przykłady

**Files:**
- Modify: `server/src/main/java/pl/honeypot/server/api/EventValidator.java`, `server/src/main/java/pl/honeypot/server/store/ReportStore.java` (`KNOWN_EVENT_TYPES` ~linia 122, `index` ~linia 193, `attackers()` ~linia 346, `AttackerState`), `docs/schema/event-v2.schema.json`
- Create: `server/examples/report-auth-attempt.json`, `server/examples/report-net-scan.json`
- Test: `server/src/test/java/pl/honeypot/server/api/EventValidatorTest.java`, `server/src/test/java/pl/honeypot/server/store/ReportStoreEventTest.java`, `SchemaExamplesTest` (przechodzi po nowych przykładach)

**Interfaces:**
- Produces: `EventValidator.validate` sprawdza opcjonalne `credential` (`null` albo obiekt; `password` tekst ≤ 1024 znaków lub `null`; `password_base64` tekst ≤ 4096 lub brak) i `detail` (`null` albo obiekt; `ports` liczba całkowita ≥ 1, `scan` tekst zgodny z `NAME`, `window_seconds` liczba całkowita ≥ 1); zły kształt → `BadRequestResponse`. `KNOWN_EVENT_TYPES` zawiera `auth.attempt` i `net.scan`.

- [ ] **Step 1: Napisz testy.** `EventValidatorTest`: `credential` `{"password":"x"}` przyjęte; `{"password":null,"password_base64":"/w=="}` przyjęte; `credential` jako tekst odrzucone; `password` liczba odrzucone; `detail` z `ports:0` odrzucone; `detail` `{"ports":12,"scan":"syn","window_seconds":10}` przyjęte; oba `null` przyjęte. `ReportStoreEventTest`: raport v2 `net.scan` z `src.ip` `192.0.2.50` → `by_event_type["net.scan"]==1`, `unknown_event_types==0`, a `attackers()` zawiera ten IP z `threat=="fast_enum"` (moja decyzja: flaga trwała, niezależna od okna 60 s); raport `auth.attempt` → `unknown_event_types==0` i **nie** zwiększa `authFailures` atakującego (zlicza je dalej `auth.failure`, bez dublowania).
- [ ] **Step 2: Uruchom** `cd server && mvn -q test -Dtest='EventValidatorTest,ReportStoreEventTest,SchemaExamplesTest'` — oczekiwane: FAIL.
- [ ] **Step 3: Zaimplementuj.** Walidator: dwie nowe metody prywatne w stylu istniejących. `ReportStore.index`: dla `event.type == "net.scan"` wywołaj `markScanner(ip, at)` (nowa metoda jak `markAttacker`, ustawia `AttackerState.scanned=true`); `attackers()`: `threat` `fast_enum` także gdy `s.scanned`. Schemat: dodaj `credential`, `detail` (opcjonalne, z typami jak wyżej) i dopisz `auth.attempt`, `net.scan` do opisu katalogu. Przykłady: kopie `report-auth-failure.json` z `event` zmienionym na nowe typy (hasło w przykładzie to `"Lato2024!"`, sztuczne).
- [ ] **Step 4: Uruchom** `cd server && mvn -q test` — oczekiwane: wszystko PASS.
- [ ] **Step 5: Commit** `git add server docs/schema && git commit -m "Serwer: auth.attempt i net.scan (walidacja, atakujacy z net.scan, schemat i przyklady)"`

### Task 6: Instalator i sonda akceptacyjna na AlmaLinux

**Files:**
- Modify: `samba_structure/setup-honeypot.sh` (nowy krok po konfiguracji `sshd`, ~linia 218–225)
- Create: `docs/superpowers/plans/sonda-akceptacyjna-etap2.md` (lista kroków i oczekiwanych wyników z Step 3)

**Ten task wymaga prawdziwej maszyny Alma (9/10) i właściciela; lokalnie sprawdzalne są tylko `sh -n` i `shellcheck`, jeśli są. Wykonawca nie twierdzi „działa" bez wyniku sondy.**

- [ ] **Step 1: Zmiany w instalatorze (idempotentne):** instalacja `scripts/hp-pam-log` do `/usr/local/libexec/hp-pam-log` (`0755`, `root:root`, `restorecon`); wpis w `/etc/pam.d/sshd` uruchamiający `pam_exec.so expose_authtok quiet seteuid /usr/local/libexec/hp-pam-log` **tylko po porażce hasła** (kandydaci do sprawdzenia w Step 2: własny blok `pam_unix.so` z `[success=1 default=ignore]` przed `pam_exec` zamiast `substack password-auth`, albo osobny profil `authselect`); `firewall-cmd --set-log-denied=all` (przy `--permanent` i przeładowaniu, w istniejącym kroku firewalla ~linia 273). Przed zmianą PAM: kopia `/etc/pam.d/sshd.hp-orig` i sprawdzenie, że zalogowanie kluczem `HP_ADMIN_USER` nadal działa (nie zamykać aktywnej sesji administratora).
- [ ] **Step 2: Spike na Almie** (przed finalnym wpisem): sprawdź (a) czy PAM dostaje hasło dla nieistniejącego użytkownika, (b) które wpięcie w stos `sshd` uruchamia hook wyłącznie po nieudanym `pam_unix`, (c) że SELinux nie blokuje `logger`/`pam_exec`, (d) rzeczywisty format linii `firewalld` dla SYN/NULL/XMAS/FIN w `/var/log/messages` (porównaj z syntetycznymi liniami z T1; jeśli się różnią, **zatrzymaj się** i opisz różnicę w raporcie zamiast zgadywać). Jeśli żadne wpięcie nie spełnia „hasło udanego logowania nie jest zapisywane", **zatrzymaj się i opisz** (nie wdrażaj wariantu zapisującego zawsze).
- [ ] **Step 3: Sonda akceptacyjna** (wyniki do raportu z poleceniem i commitem): zły login istniejącego użytkownika → w `/var/log/secure` linia `hp-pam:` i w raportach `auth.attempt` z poprawnym hasłem; zły login nieistniejącego użytkownika → jak wyżej (albo udokumentowane „nie dostaje hasła"); **dobre hasło → brak linii `hp-pam:`**; logowanie kluczem → brak linii; logowanie `HP_ADMIN_USER` kluczem działa po zmianie PAM; `nmap -sS -p1-100 <ip>` → dokładnie jedno `net.scan` i brak osobnych raportów linii zapory; `smbclient` ze złym hasłem nadal daje `auth.failure`.
- [ ] **Step 4: Commit** `git add samba_structure scripts docs && git commit -m "Instalator: hook PAM, set-log-denied i sonda akceptacyjna etapu 2"`

### Task 7: Dokumentacja i wersja

**Files:**
- Modify: `VERSION` (`0.3.0`), `server/pom.xml` (`<version>0.3.0</version>`), `server/docs/api.md` (nowe typy, `credential`, `detail`), `docs/DOKUMENTACJA-TECHNICZNA.md` (sekcje protokołu i agenta, ryzyko haseł), `agent/README.md` (hook PAM, `set-log-denied`, próg skanu), `README.md`, `docs/POROWNANIE-OPENCANARY.md` (luki 2 i 3: stan po etapie 2)

- [ ] **Step 1:** Zaktualizuj dokumenty zgodnie z Global Constraints i spec §4, w tym: linie zapory nie są raportowane osobno (tylko `net.scan`), jedno `auth.attempt` obok `auth.failure`, ostrzeżenie o przechowywaniu haseł.
- [ ] **Step 2: Uruchom** `cd agent && make check && cd ../server && mvn -q test` — oczekiwane: oba zielone (testy wersji przyjmują `0.3.0`; popraw te, które mają `0.2.0` na stałe).
- [ ] **Step 3: Commit** `git add VERSION server docs agent/README.md README.md && git commit -m "Dokumentacja i wersja 0.3.0: hasla z prob SSH i skany portow"`

## Self-review

- **Pokrycie spec:** §4.1 hasła (T2, T4, T6), §4.2 skany (T1, T3, T6), §4.3 serwer i dokumentacja (T5, T7), §5 testy (T1–T5; sonda w T6), §6 do sprawdzenia (T6 Step 2), §8 ryzyka (Global Constraints, Review Focus 1).
- **Odstępstwa od spec (do wiadomości właściciela):** (1) linie zapory z `/var/log/messages` **nie są już raportowane osobno** (spec milczał; bez tego skan zalewa serwer, a pojedyncze odrzucone pakiety poniżej progu nie zostawiają śladu); (2) próg skanu to stałe w `scan.h`, nie konfiguracja w czasie działania; (3) użytkownik w linii `hp-pam:` też w base64; (4) flaga `scanned` w serwerze jest trwała, nie okienkowa; (5) parsery wymagają znacznika programu w logu (ochrona przed podrobionymi liniami).
- **Spójność nazw:** `hp_scan_*`, `struct hp_scan_hit`, `hp_event_scan`, `hp_report_scan`, `hp-pam-log`, `credential`, `detail` użyte identycznie we wszystkich zadaniach.
- **Do sprawdzenia przy wykonaniu:** czy reguła `build/%_test` w `agent/Makefile` wymaga ręcznej listy obiektów dla `scan.c`; czy testy wersji mają `0.2.0` na stałe; układ nagłówka syslog (znacznik programu to pole 5 liczone od 1; testy w T1 i T2 to utrwalają).
