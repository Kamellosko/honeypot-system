# Etap 1: schemat zdarzeń v2, wersjonowanie, `--dev` — plan implementacji

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Każdy raport agenta ma stały blok `event` (schema v2), projekt ma jedno źródło wersji, a agent ma tryb `--dev`.

**Architecture:** Nowy moduł `agent/src/event.c` wyciąga pola (typ, IP, port, użytkownik) raz i zapisuje blok `event`; `snapshot.c` wywołuje go z każdego `hp_report_*`. Serwer przyjmuje v1 i v2, waliduje `event` w v2 i używa `event.src.ip` zamiast regexów, gdy blok jest. Wersja pochodzi z pliku `VERSION`.

**Tech Stack:** C11 (agent, testy `assert` + `make check`), Java 21 + Javalin + Jackson (serwer), JUnit 5 i `com.networknt:json-schema-validator` (testy serwera).

**Spec:** `docs/superpowers/specs/2026-11-20-schemat-zdarzen-wersja-dev-design.md`

## Global Constraints

- Stare pola raportu (`analysis`, `connection`, `content`, `network_context`, `evidence`, `content_changes`, `metadata`) zostają bez zmian; `event` jest dodawany obok.
- `schema_version`: agent wysyła `2`; serwer przyjmuje `1` i `2`.
- `event.severity` ∈ `info|low|medium|high`; `event.outcome` ∈ `success|failure|unknown`.
- Katalog `event.type` (wersja 1): `file.change`, `net.connection`, `auth.failure`, `auth.success`, `samba.audit`, `system.heartbeat`, `system.source_unavailable`, `system.observation_gap`. Typ spoza katalogu serwer zapisuje i liczy, **nie odrzuca**.
- Brak danych w `src`/`dst`/`user`/`service` to `null`; `src.mac` w etapie 1 zawsze `null`.
- Wersja startowa projektu: `0.2.0` (plik `VERSION`, jedna linia).
- Bez `--dev` agent zachowuje się jak dziś: stdout i stderr na `/dev/null`, zmieniona nazwa procesu.
- Kompilacja agenta ma `-Wall -Wextra -Werror`; nowe pliki muszą się z tym budować.
- Zapis raportu na dysk z `fsync` przed wysyłką zostaje bez zmian.

## Review Focus

- Nazwa użytkownika z `Failed password for invalid user a b from ...` albo z cudzysłowem/`|`/>128 znaków: `event.user.name` ma być pierwszym tokenem po `invalid user`, ucięty do 128 znaków i poprawnie zescapowany w JSON (test w Task 2).
- Porcja logu z kilkoma liniami (porażka + sukces): blok `event` opisuje pierwszą linię uwierzytelniania, klasyfikacja i statystyki zostają jak dziś (Task 2).
- Adres IPv6 jako `src.ip`: serwer go przyjmuje i nie odrzuca raportu (Task 4).
- Agent v1 (bez `event`) po aktualizacji serwera nadal jest przyjmowany; v2 z błędnym `event` daje 400; nieznany `event.type` jest zapisany (Task 4).
- `--dev` podane dwa razy, w środku listy argumentów albo razem z `--id`: parser odrzuca duplikat i przyjmuje pozostałe pary; bez `--dev` stderr jest pusty (Task 6).

---

### Task 1: Plik `VERSION` i wersja w agencie

**Files:**
- Create: `VERSION` (treść: `0.2.0\n`)
- Modify: `agent/Makefile`, `agent/include/config.h`
- Create: `agent/tests/version_test.c`

**Interfaces:**
- Produces: makro `HP_VERSION` (string) widoczne w `config.h`; build bierze je z `../VERSION`.

- [ ] **Step 1: Napisz test** `agent/tests/version_test.c`: `main` sprawdza `assert(sizeof(HP_VERSION) > 1)` i `assert(!strcmp(HP_VERSION, <zawartość ../VERSION bez nowej linii>))`, czytając plik `../VERSION` względem katalogu `agent/`.
- [ ] **Step 2: Uruchom** `cd agent && make build/version_test` — oczekiwane: błąd kompilacji (`HP_VERSION` niezdefiniowane).
- [ ] **Step 3: Zaimplementuj.** W `Makefile`: `VERSION_STR := $(shell tr -d '\n' < ../VERSION)` i `CPPFLAGS += -DHP_VERSION='"$(VERSION_STR)"'`. W `config.h`: `#ifndef HP_VERSION` / `#define HP_VERSION "unknown"` / `#endif`. Dodaj `version` do `TESTS` w `Makefile`.
- [ ] **Step 4: Uruchom** `cd agent && make build/version_test && build/version_test` — oczekiwane: kod wyjścia 0.
- [ ] **Step 5: Commit**

```bash
git add VERSION agent/Makefile agent/include/config.h agent/tests/version_test.c
git commit -m "Wersjonowanie: plik VERSION i makro HP_VERSION w agencie"
```

### Task 2: Moduł `event` w agencie (czysta logika, bez zmiany raportów)

**Files:**
- Create: `agent/include/event.h`, `agent/src/event.c`, `agent/tests/event_test.c`
- Modify: `agent/Makefile` (dodaj `src/event.c` do `SOURCES` i `event` do `TESTS`)

**Interfaces:**
- Produces (`event.h`):
  - `struct hp_event { const char *category, *type, *severity, *outcome, *service, *action; char src_ip[INET6_ADDRSTRLEN]; int src_port; char dst_ip[INET6_ADDRSTRLEN]; int dst_port; char user[129]; };` — pusty napis lub `-1` oznacza brak danych (zapis jako `null`).
  - `const char *hp_classify(const char *operation, const unsigned char *content, size_t size);` — przeniesiona logika klasyfikacji z `hp_report_simple`: zwraca `authentication_failure|authentication_success|samba_audit|heartbeat|unknown`.
  - `void hp_event_from_log(struct hp_event *e, const char *source, const char *operation, const unsigned char *content, size_t size);` — wypełnia `e` z klasyfikacji i pierwszej linii uwierzytelniania.
  - `void hp_event_write(FILE *out, const struct hp_event *e);` — zapisuje `,"event":{...}` (z początkowym przecinkiem), stringi przez `hp_json_string`.

- [ ] **Step 1: Napisz test** `agent/tests/event_test.c` (wzorzec jak `heartbeat_test.c`, same `assert`). Przypadki z dokładnymi wartościami:
  - `"Failed password for invalid user bob from 203.0.113.9 port 4242 ssh2"` → `type=="auth.failure"`, `outcome=="failure"`, `service=="ssh"`, `src_ip=="203.0.113.9"`, `src_port==4242`, `user=="bob"`, `severity=="medium"`.
  - `"Accepted password for finance from 198.51.100.7 port 5000 ssh2"` → `auth.success`, `high`, `user=="finance"`.
  - `"Failed password for invalid user a b from 203.0.113.9 port 1 ssh2"` → `user=="a"` (pierwszy token; Review Focus).
  - użytkownik 300 znaków `x` → `strlen(user)==128`.
  - dwie linie (porażka, potem sukces) → `type=="auth.failure"` (pierwsza linia uwierzytelniania).
  - `"smbd_audit: bob|203.0.113.9|pc01|finance|openat|ok|x"` (prefiks `%u|%I|%m|%S` z `samba_structure/setup-honeypot.sh:131`) → `type=="samba.audit"`, `service=="smb"`, `user=="bob"`, `src_ip=="203.0.113.9"`, `severity=="low"`.
  - linia Samby z `NT_STATUS_LOGON_FAILURE` i `user [bob]` → `auth.failure`, `service=="smb"`, `user=="bob"`. **Wykonawca sprawdza format linii na prawdziwym logu Samby (`log level auth:3`) i dopasowuje test; nie zgaduje.**
  - IPv6 `"Failed password for root from 2001:db8::1 port 22 ssh2"` → `src_ip=="2001:db8::1"`.
  - `operation=="heartbeat"`, brak treści → `system.heartbeat`, `info`, wszystkie pola brakujące.
  - `hp_event_write` dla użytkownika `a"b|c` zwraca poprawny JSON (przeparsuj `cJSON_Parse` i porównaj `user.name`), a dla braku danych `"src":null`.
- [ ] **Step 2: Uruchom** `cd agent && make build/event_test` — oczekiwane: błąd (brak `event.h`).
- [ ] **Step 3: Zaimplementuj** `event.c`. Użyj istniejącego `hp_extract_ips` (`network.h`) dla `src_ip`; port z tokenu `port N` (ssh); użytkownik z `for [invalid user ]NAME` (ssh), pierwszego pola przed `|` po `smbd_audit` (Samba audit) lub `user [NAME]` (Samba auth). Tylko pierwsza linia uwierzytelniania. Dodaj `src/event.c` do `SOURCES` i `event` do `TESTS`.
- [ ] **Step 4: Uruchom** `cd agent && make build/event_test && build/event_test` — oczekiwane: kod 0.
- [ ] **Step 5: Commit**

```bash
git add agent/include/event.h agent/src/event.c agent/tests/event_test.c agent/Makefile
git commit -m "Agent: modul event (klasyfikacja i wyciaganie IP/portu/uzytkownika z logow)"
```

### Task 3: Agent emituje schema v2 z blokiem `event`

**Files:**
- Modify: `agent/src/snapshot.c` (`report_begin` ~linia 387, `hp_report_simple`, `hp_report_connection`, rename ~linia 487, zmiana pliku ~linia 682), `agent/src/heartbeat.c` bez zmian (idzie przez `hp_report_simple`)
- Modify: testy asserujące `schema_version`/kształt (znajdź: `grep -rn schema_version agent/tests`), `server/examples/*.json`
- Test: `agent/tests/snapshot_test.c` (dopisz asercje) oraz `agent/tests/event_test.c`

**Interfaces:**
- Consumes: `hp_classify`, `hp_event_from_log`, `hp_event_write` z Task 2; `HP_VERSION` z Task 1.
- Produces: każdy raport zaczyna się `{"schema_version":2,"agent_version":"<HP_VERSION>","report_id":...` i zawiera `,"event":{...}`.

- [ ] **Step 1: Napisz testy.** W `snapshot_test.c` po każdym istniejącym scenariuszu raportu sparsuj plik z `pending/` przez `cJSON_Parse` i dodaj asercje: `schema_version==2`, `agent_version==HP_VERSION`, `event.type` zgodny z tabelą katalogu (`file.change` z `event.action=="create"` dla utworzenia pliku, `file.change`/`rename` dla zmiany nazwy, `net.connection` z `src.ip`==peer, `dst.port`==local_port i `service=="ssh"` gdy `local_port==22`, `system.heartbeat`, `system.observation_gap`, `system.source_unavailable`), `event.severity` zgodny z katalogiem.
- [ ] **Step 2: Uruchom** `cd agent && make build/snapshot_test && build/snapshot_test` — oczekiwane: FAIL (brak `event`, `schema_version==1`).
- [ ] **Step 3: Zaimplementuj.** `report_begin`: `"schema_version":2,"agent_version":` + `HP_VERSION`. `hp_report_simple`: użyj `hp_classify` zamiast wbudowanych `memmem`, wypełnij `hp_event` przez `hp_event_from_log` (a dla `source_unavailable`/`observation_gap` ustaw `system.*` na podstawie `operation`) i wywołaj `hp_event_write`. `hp_report_connection`: `net.connection`, `category network`, `src` z peera, `dst` z lokalnego adresu, `service` z portu (22→`ssh`, 139/445→`smb`, inaczej `null`). Zmiana pliku i rename: `file.change`, `category file`, `event.action` = zgłaszana operacja. Wszędzie `severity` z katalogu.
- [ ] **Step 4: Zaktualizuj wszystkie testy i przykłady, które zakładają v1** (`grep -rn '"schema_version":1\|schema_version.*1' agent/tests server/examples`); przeregeneruj `server/examples/report-*.json` z prawdziwego wyjścia agenta (uruchom odpowiedni test z zapisem raportu do pliku i skopiuj), tak by pliki w `examples/` były v2.
- [ ] **Step 5: Uruchom** `cd agent && make check` — oczekiwane: wszystkie testy PASS, kod 0.
- [ ] **Step 6: Commit**

```bash
git add agent server/examples
git commit -m "Agent: schema_version 2, agent_version i blok event we wszystkich raportach"
```

### Task 4: Serwer — walidacja `event`, użycie `event` w statystykach, JUnit

**Files:**
- Modify: `server/pom.xml` (zależności testowe `org.junit.jupiter:junit-jupiter` i `com.networknt:json-schema-validator`, plugin `maven-surefire-plugin`)
- Modify: `server/src/main/java/pl/honeypot/server/api/ReportHandler.java` (linie ~44-47 walidacja `schema_version`), `server/src/main/java/pl/honeypot/server/store/ReportStore.java` (`index`, ~linie 176-222)
- Create: `server/src/main/java/pl/honeypot/server/api/EventValidator.java`
- Create: `server/src/test/java/pl/honeypot/server/api/EventValidatorTest.java`, `server/src/test/java/pl/honeypot/server/store/ReportStoreEventTest.java`

**Interfaces:**
- Produces: `final class EventValidator { static void validate(JsonNode event) throws BadRequestResponse }` — sprawdza enumy `severity`/`outcome`, że `category` i `type` pasują do `[a-z0-9_.]{1,64}`, że `src.ip` i `dst.ip` są poprawnymi adresami IPv4/IPv6 albo `null`, porty 1–65535 albo `null`, `user.name` ≤ 256 znaków.
- Produces: `ReportStore.Stats` dostaje pole `by_event_type` (`Map<String,Long>`, limit 200 kluczy jak `by_operation`, nowe wartości pod `other`) oraz licznik `unknown_event_types`.
- `ReportHandler`: `schema_version` ∈ {1,2}; dla 2 wymagany `event`, walidowany `EventValidator`. v1 nie ma `event`.

- [ ] **Step 1: Napisz testy JUnit (czerwone):**
  - `EventValidatorTest`: poprawny blok przechodzi; `severity:"bogus"` → `BadRequestResponse`; `src.ip:"999.1.1.1"` → wyjątek; `src.ip:"2001:db8::1"` przechodzi (IPv6); `src.port:0` → wyjątek; `user.name` 300 znaków → wyjątek; pola `null` przechodzą.
  - `ReportStoreEventTest`: (a) v1 bez `event` i z `authentication_failure` oraz `network_context.endpoints[0].ip` nadal zlicza atakującego (fallback); (b) v2 z `event.src.ip` zlicza atakującego po `event.src.ip` nawet gdy `network_context` jest puste; (c) v2 z `event.type:"future.thing"` jest zapisany i zwiększa `unknown_event_types`; (d) `by_event_type` zawiera `auth.failure` po jednym takim raporcie.
- [ ] **Step 2: Uruchom** `cd server && mvn -q test` — oczekiwane: błąd kompilacji/FAIL (brak klas i zależności).
- [ ] **Step 3: Zaimplementuj** zależności w `pom.xml`, `EventValidator`, zmianę walidacji `schema_version` w `ReportHandler` oraz w `ReportStore.index`: gdy `event.src.ip` jest ustawione i `event.type` to `auth.failure`, użyj go jako IP (zamiast `firstEndpoint`); gdy `event.type` to `net.connection`, zostaw obecną logikę z `connection.peer`. Logika potwierdzonego logowania (`SSH_ACCEPTED` na `content`) zostaje bez zmian, bo jedna porcja logu może mieć kilka linii.
- [ ] **Step 4: Uruchom** `cd server && mvn -q test` — oczekiwane: PASS.
- [ ] **Step 5: Commit**

```bash
git add server
git commit -m "Serwer: przyjmuje schema v1 i v2, waliduje blok event, statystyka by_event_type"
```

### Task 5: JSON Schema i test przykładów; `/api/version`

**Files:**
- Create: `docs/schema/event-v2.schema.json`
- Create: `server/src/test/java/pl/honeypot/server/SchemaExamplesTest.java`, `server/src/test/java/pl/honeypot/server/VersionTest.java`
- Create: `server/src/main/java/pl/honeypot/server/api/VersionHandler.java`
- Modify: `server/src/main/java/pl/honeypot/server/Main.java` (rejestracja `GET /api/version`), `server/pom.xml` (wersja `0.2.0`, manifest `Implementation-Version` w pluginie shade)

**Interfaces:**
- Produces: `GET /api/version` → `{"server_version":"<z manifestu lub pom>","schema_versions":[1,2]}`.
- Consumes: przykłady v2 z Task 3 (`server/examples/report-*.json`).

- [ ] **Step 1: Napisz testy.**
  - `SchemaExamplesTest`: dla każdego pliku `server/examples/report-*.json` waliduj kopertę i `event` względem `docs/schema/event-v2.schema.json` (biblioteka `com.networknt`); asercja, że znaleziono ≥ 3 pliki.
  - `VersionTest`: `assertEquals(Files.readString(Path.of("../VERSION")).trim(), <wersja z pom.xml>)` (pilnuje, by `VERSION` i `pom.xml` się nie rozjechały), oraz test handlera: odpowiedź zawiera `schema_versions` `[1,2]`.
- [ ] **Step 2: Uruchom** `cd server && mvn -q test` — oczekiwane: FAIL (brak schematu i handlera).
- [ ] **Step 3: Zaimplementuj** schemat (enumy i wzorce jak w Global Constraints, `event` wymagany w v2, pola `src/dst/user/service` nullable), `VersionHandler`, rejestrację trasy i zmianę wersji w `pom.xml` na `0.2.0`.
- [ ] **Step 4: Uruchom** `cd server && mvn -q test` — oczekiwane: PASS.
- [ ] **Step 5: Commit**

```bash
git add docs/schema server
git commit -m "Schemat JSON v2, test przykladow i endpoint /api/version"
```

### Task 6: Tryb `--dev`

**Files:**
- Modify: `agent/include/config.h` (pole `int dev` w `struct hp_options`, deklaracja `extern int hp_dev;` i `void hp_dev_log(const char *fmt, ...);`), `agent/src/config.c` (`hp_parse_args` ~linie 63-82, definicja `hp_dev` i `hp_dev_log`), `agent/src/main.c` (`main` ~linie 170-186), `agent/src/port.c` (`hp_send_pending` ~linia 27), `agent/Makefile` (test CLI w `check`)
- Test: `agent/tests/config_test.c` (dopisz), nowy test w `check`

**Interfaces:**
- Produces: `hp_parse_args` przyjmuje opcjonalne samodzielne `--dev` w dowolnym miejscu; duplikat `--dev` zwraca `-1`. `hp_dev_log` pisze na stderr tylko gdy `hp_dev != 0`.
- Zachowanie: z `--dev` agent **nie** przekierowuje stdout/stderr na `/dev/null` i wypisuje: błędy zapisu/wysyłki oraz jedną linię na raport `report_id=<id> type=<event.type> http=<kod>`.

- [ ] **Step 1: Napisz testy** w `config_test.c`: `hp_parse_args` z `{"x","--dev"}` → `options.dev==1`; `{"x","--id","a","--dev","--port","443"}` → sukces, `id=="a"`; `{"x","--dev","--dev"}` → `!=0`; `{"x","--id","a"}` → `options.dev==0`; `{"x","--dev","--ip"}` → `!=0` (brak wartości). Do `check` w `Makefile` dodaj: `build/honeypot --dev --id x --ip bad --port 443 2>&1 | grep -q usage` oraz kontrolę, że bez `--dev` komunikat użycia nadal idzie na stderr przed przekierowaniem (zachowanie dzisiejsze, kod 2).
- [ ] **Step 2: Uruchom** `cd agent && make build/config_test && build/config_test` — oczekiwane: FAIL (parser odrzuca `--dev`).
- [ ] **Step 3: Zaimplementuj.** Zmień pętlę parsera tak, by `--dev` zużywał jeden argument, a pozostałe flagi dwa; usuń warunek `!(argc & 1)`; zachowaj walidację duplikatów (`seen`). W `main`: wykonaj `freopen` na `/dev/null` tylko gdy `!options.dev`; ustaw `hp_dev = options.dev`; przy `--dev` pomiń też nadpisywanie `argv[0]`. Dodaj wywołania `hp_dev_log` przy porażce zapisu raportu i po każdej próbie wysyłki w `hp_send_pending`.
- [ ] **Step 4: Uruchom** `cd agent && make check` — oczekiwane: wszystkie testy PASS, w tym istniejące testy CLI z kodem 2.
- [ ] **Step 5: Commit**

```bash
git add agent
git commit -m "Agent: tryb --dev (stderr, bledy i linia na raport)"
```

### Task 7: Dokumentacja

**Files:**
- Modify: `server/docs/api.md` (koperta v2, blok `event`, katalog typów, `GET /api/version`, `by_event_type`), `docs/DOKUMENTACJA-TECHNICZNA.md` (sekcje protokołu i agenta), `agent/README.md` (`--dev`), `README.md` (wersja i link do `docs/schema/event-v2.schema.json`)

- [ ] **Step 1:** Zaktualizuj dokumenty zgodnie z Global Constraints, w tym tabelę mapowania do ECS ze spec (sekcja 5.2) i opis, że `src.mac` jest `null` w etapie 1.
- [ ] **Step 2:** Uruchom `cd agent && make check && cd ../server && mvn -q test` — oczekiwane: oba zielone.
- [ ] **Step 3: Commit**

```bash
git add server/docs/api.md docs agent/README.md README.md
git commit -m "Dokumentacja: schema v2, wersjonowanie i tryb --dev"
```

## Self-review

- **Pokrycie spec:** blok `event` (T2, T3), katalog i severity (T2, T3), wersjonowanie (T1, T5), walidacja serwera i fallback v1 (T4), `/api/version` (T5), JSON Schema i testy przykładów (T5), `--dev` (T6), dokumentacja (T7), nieznany typ zapisywany (T4). Dashboard celowo pominięty (tylko „jeśli tanie"; spec §6).
- **Spójność nazw:** `hp_classify`, `hp_event_from_log`, `hp_event_write`, `struct hp_event`, `EventValidator.validate`, `hp_dev`, `hp_dev_log`, `HP_VERSION` są używane identycznie we wszystkich zadaniach.
- **Znane ograniczenie:** porcja logu z wieloma liniami uwierzytelniania daje jeden blok `event` (pierwsza linia); potwierdzone logowania liczy dalej regex `SSH_ACCEPTED` po `content`.
- **Do sprawdzenia przy wykonaniu:** format linii Samby `auth:3` (T2), wszystkie testy zakładające `schema_version 1` (T3 krok 4).
