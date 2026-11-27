# Honeypot: serwer plików z monitoringiem. Dokumentacja techniczna

**Stan na 20 listopada 2026.** Dokument opisuje cały system na podstawie kodu z repozytorium: agenta `sys-auditd` (C),
kolektor `sysmon-collector` (Java 21), dashboard (JS), skrypty instalacyjne oraz konfigurację wabika (Samba, SSH).
Fragmenty kodu są wycięte wprost ze źródeł, z podaniem pliku i numerów linii (numeracja odpowiada stanowi repozytorium z tego dnia).

## Spis treści

1. [Cel, zakres i model zagrożeń](#1-cel-zakres-i-model-zagrożeń)
2. [Architektura](#2-architektura)
3. [Struktura repozytorium](#3-struktura-repozytorium)
4. [Agent `sys-auditd`](#4-agent-sys-auditd)
5. [Protokół agent → serwer](#5-protokół-agent--serwer)
6. [Serwer `sysmon-collector`](#6-serwer-sysmon-collector)
7. [Wykrywanie atakujących](#7-wykrywanie-atakujących)
8. [Dashboard](#8-dashboard)
9. [Wabik: persona, Samba, SSH](#9-wabik-persona-samba-ssh)
10. [Instalacja, usługi i operacje](#10-instalacja-usługi-i-operacje)
11. [Model bezpieczeństwa](#11-model-bezpieczeństwa)
12. [Testy](#12-testy)
13. [Znane ograniczenia i luki](#13-znane-ograniczenia-i-luki)
14. [Parametry i limity](#14-parametry-i-limity)
15. [Słownik operacji i klasyfikacji](#15-słownik-operacji-i-klasyfikacji)
16. [Rozwiązywanie problemów](#16-rozwiązywanie-problemów)

---

## 1. Cel, zakres i model zagrożeń

### 1.1 Cel

Maszyna AlmaLinux 9.8 udaje serwer plików działu finansów małej firmy (Samba + SSH). Nikt uprawniony nie ma powodu się z nią łączyć,
więc każdy kontakt z jej usługami jest zdarzeniem wartym zapisania. System **niczego nie blokuje i nie odpowiada na atak**. Zbiera dowody:

- jakie pliki w udziałach zostały utworzone, zmienione, przeniesione, usunięte (z pełną treścią i diffem),
- jakie próby logowania (udane i nieudane) padły w logach Samby i SSH,
- kto (jaki adres IP, a w tej samej sieci L2 także MAC) łączył się z usługami TCP,
- czy agent nadal żyje (heartbeat) oraz kiedy sam przestał coś widzieć (`observation_gap`).

### 1.2 Model zagrożeń

| Założenie | Konsekwencja w projekcie |
|---|---|
| Atakujący może mieć konto Samby (z okruszka) i zapisywać w udziałach | agent trzyma kopię każdego pliku i raportuje diff oraz skróty SHA-256 |
| Atakujący kontroluje nazwy plików i treść logów (np. nazwa użytkownika w próbie logowania) | każdy tekst z zewnątrz jest escapowany w JSON i w dashboardzie; z linii logu liczy się tylko pierwszy adres IP (rozdz. 4.8, 7.2) |
| Atakujący może podstawić symlink pod udział | wszystkie odczyty idą przez `openat2(RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS)` (rozdz. 4.3) |
| Atakujący może zabić agenta lub zrestartować maszynę | brak heartbeatów po 90 s daje `offline`; po starcie agent porównuje udziały z kopiami (`delete_during_downtime`) |
| Atakujący z rootem może skasować lokalne dane | kopia `events.jsonl` poza maszynę (`scripts/sync-events.sh`, rozdz. 10.6). To jedyne zabezpieczenie przed rootem |
| Maszyna stoi w odizolowanej sieci | kolektor słucha tylko na `127.0.0.1`, dashboard przez tunel SSH |

Czego system **nie** robi: nie identyfikuje sprawcy plików (pole `analysis.actor` agenta jest `null` lub nieobecne), nie blokuje,
nie kontratakuje, nie chroni przed użytkownikiem z uprawnieniami roota na honeypocie.

---

## 2. Architektura

### 2.1 Komponenty i przepływ danych

```
atakujący ──SMB (445/139)/SSH (22)──► Samba, sshd
                                        │ pliki w /srv/samba/*     logi: /var/log/samba/*, /var/log/secure, /var/log/messages
                                        ▼
                         ┌──────────────────────────────────────────────┐
                         │ AGENT sys-auditd (C, root, jeden proces)     │
                         │  wątek główny: inotify + poll logów +        │
                         │                netlink SOCK_DIAG + heartbeat │
                         │       raport JSON ─► pending/<id>.json       │
                         │  wątek sender_loop: pending ─► HTTPS POST    │
                         └──────────────────────┬───────────────────────┘
                                                │ https://127.0.0.1:8443/events
                                                ▼
                         ┌──────────────────────────────────────────────┐
                         │ KOLEKTOR sysmon-collector (Java 21, Javalin) │
                         │  walidacja ─► dedup (report_id) ─► fsync     │
                         │  /var/lib/sysmon/events.jsonl                │
                         │  /api/{agents,events,stats,attackers}        │
                         │  statyczny dashboard (ten sam origin)        │
                         └──────────────────────┬───────────────────────┘
                                                │ ssh -L 8443:127.0.0.1:8443
                                                ▼
                                       przeglądarka operatora
```

Wdrożenie jest **jednomaszynowe**: Samba, agent, kolektor i dashboard działają na tej samej maszynie. Skutki:

- agent łączy się z kolektorem przez loopback, więc kolektor musi filtrować własne połączenie agenta (rozdz. 6.4),
- port 8443 nie jest otwierany w firewallu,
- jedyny ruch wychodzący z maszyny to opcjonalny `rsync` z `sync-events.sh`.

### 2.2 Ścieżki i dane na dysku

| Ścieżka | Właściciel | Zawartość |
|---|---|---|
| `/usr/local/sbin/sys-auditd` | root, 0700 | binarka agenta |
| `/etc/systemd/system/sys-auditd.service` (+ `.service.d/override.conf`) | root, 0600 | jednostka agenta i parametry `--id/--ip/--port` |
| `/var/lib/sys-auditd/snapshots/` | root, 0700 | kopie plików (nazwa = SHA-256 ścieżki), `*.path`, `*.stat`, znaczniki `root-*` |
| `/var/lib/sys-auditd/pending/` | root, 0700 | kolejka raportów `<64 hex>.json` i `*.json.rejected` |
| `/opt/sysmon/collector.jar`, `/opt/sysmon/dashboard/` | root | kolektor i statyczny dashboard |
| `/etc/sysmon/collector.properties`, `/etc/sysmon/collector.p12` | root:sysmon 0640 / sysmon 0600 | konfiguracja i keystore TLS |
| `/var/lib/sysmon/events.jsonl` | sysmon, 0600 | dziennik zdarzeń (JSON Lines) |
| `/etc/pki/ca-trust/source/anchors/sysmon-ca.crt` | root | CA kolektora zaufane w systemie (agent weryfikuje TLS) |

### 2.3 Gwarancje

1. **Raport trafia na dysk przed zmianą stanu odniesienia.** Awaria agenta może dać duplikat, nigdy dziurę. Realizują to `hp_snapshot_event` i `report_end` (rozdz. 4.6, 4.12).
2. **Serwer odpowiada 2xx dopiero po `fsync` zapisu**, więc agent kasuje raport z kolejki dopiero po trwałym zapisie (rozdz. 6.5).
3. **Dostawa jest typu at-least-once**, duplikaty zdejmuje serwer po `report_id` (64 znaki hex z `RAND_bytes`).
4. **Luki w obserwacji są zgłaszane jawnie** raportami `observation_gap` i `source_unavailable` zamiast cichego pominięcia.

---

## 3. Struktura repozytorium

| Ścieżka | Zawartość |
|---|---|
| `agent/src`, `agent/include` | źródła agenta w C (12 plików `.c`, ok. 2 900 linii razem z nagłówkami) |
| `agent/tests` | testy jednostkowe i integracyjne (C + Python), techniką `ld --wrap` |
| `agent/third_party/cJSON` | biblioteka JSON używana tylko w testach |
| `agent/packaging/sys-auditd.service` | jednostka systemd agenta |
| `agent/Makefile` | build, `make check`, `make release`, `make install` |
| `server/src/main/java/pl/honeypot/server` | kolektor: `Main`, `ServerConfig`, `api/*`, `store/*` |
| `server/config/server.properties` | konfiguracja deweloperska |
| `server/scripts/gen-certs.sh` | lokalne CA i certyfikat serwera, keystore PKCS12 |
| `server/deploy/honeypot-server.service` | wzorcowa jednostka systemd (instalator generuje własną) |
| `dashboard/` | `index.html`, `app.js`, `style.css` (statyczne, serwowane przez kolektor) |
| `scripts/` | instalatory usług, `setup-realism.sh`, `sync-events.sh` |
| `samba_structure/` | **obowiązująca** persona „Dział Finansów": `honeypot.conf.example`, `setup-honeypot.sh` |
| `docs/` | dokumentacja (ten plik, instrukcja wdrożenia, opisy historyczne, PDF) |

> Obowiązuje „Dział Finansów" (`samba_structure/`, opis w `docs/WDROZENIE-OD-ZERA.md`). Nie wolno mieszać ich na jednej maszynie.
> Ten dokument opisuje wariant obowiązujący.


---

## 4. Agent `sys-auditd`

Jednoprocesowy demon w C11 (Linux 5.6+ ze względu na `openat2`, `renameat2` i `getrandom`). Zależności linkowane: `libcurl`, `libcrypto` (OpenSSL), `libtdb`, `pthread`, `libm`.

### 4.1 Wiersz poleceń i budowanie

```
sys-auditd [--id AGENT_ID] [--ip DESTINATION_IP] [--port PORT]
```

Każda flaga może wystąpić najwyżej raz, nieznany argument kończy program kodem 2. Wartości domyślne pochodzą z `agent/include/config.h`
(`AGENT_ID "alma10-01"`, `DEST_IP "127.0.0.1"`, `DEST_PORT 443`, `HEARTBEAT_INTERVAL 60`), więc **instalator zawsze podaje je jawnie**:
kolektor słucha na 8443, a nie na 443.


*`agent/src/config.c`, linie 63–82*

```c
int hp_parse_args(int argc, char *const argv[], struct hp_options *options) {
  const char *id = AGENT_ID, *ip = DEST_IP, *port;
  char default_port[32];
  unsigned seen = 0;
  snprintf(default_port, sizeof(default_port), "%lld", (long long)DEST_PORT);
  port = default_port;
  if (argc < 1 || !(argc & 1)) return -1;
  for (int i = 1; i < argc; i += 2) {
    unsigned flag;
    if (!strcmp(argv[i], "--id")) { flag = 1; id = argv[i + 1]; }
    else if (!strcmp(argv[i], "--ip")) { flag = 2; ip = argv[i + 1]; }
    else if (!strcmp(argv[i], "--port")) { flag = 4; port = argv[i + 1]; }
    else return -1;
    if (seen & flag) return -1;
    seen |= flag;
  }
  if (hp_validate_args(id, ip, port)) return -1;
  *options = (struct hp_options){ id, ip, (unsigned short)strtoul(port, NULL, 10) };
  return 0;
}
```

Budowanie (`agent/Makefile`): `-std=c11 -Wall -Wextra -Werror` oraz utwardzanie `-fstack-protector-strong -fPIE -fvisibility=hidden`,
`_FORTIFY_SOURCE=2` (GCC 11 z AlmaLinux 9 nie wspiera 3; `FORTIFY_LEVEL=3` na nowszych kompilatorach), linkowanie `-pie -Wl,-z,relro,-z,now,-z,noexecstack`.
Cele: `make` (build deweloperski), `make check` (testy), `make release` (binarka bez symboli + osobny plik `.debug`), `make install` (do `/usr/local/sbin`).

### 4.2 Start, wątki i pętla główna (`main.c`)

`main` ustawia `umask(0077)`, przekierowuje stdout i stderr do `/dev/null`, zmienia nazwę procesu na `sys-auditd` (`prctl(PR_SET_NAME)` oraz nadpisanie
`argv[0]`, żeby parametry nie były widoczne w `ps`) i instaluje obsługę SIGINT/SIGTERM przez flagę `atomic_int`.


*`agent/src/main.c`, linie 170–186*

```c
int main(int argc, char **argv) {
  struct hp_options options;
  if (hp_parse_args(argc, argv, &options)) {
    fprintf(stderr, "usage: sys-auditd [--id AGENT_ID] [--ip DESTINATION_IP] [--port PORT]\n");
    return 2;
  }
  umask(0077);
  if (!freopen("/dev/null", "w", stdout) || !freopen("/dev/null", "w", stderr)) return 1;
  if (prctl(PR_SET_NAME, "sys-auditd", 0, 0, 0)) return 1;
  size_t available = strlen(argv[0]);
  memset(argv[0], 0, available);
  memcpy(argv[0], "sys-auditd", available < 10 ? available : 10);
  struct sigaction action = { .sa_handler = stop_signal };
  if (sigemptyset(&action.sa_mask) || sigaction(SIGINT, &action, NULL) ||
      sigaction(SIGTERM, &action, NULL)) return 1;
  return hp_run(options.id, options.ip, options.port);
}
```

`hp_run` inicjuje kolejno: katalog stanu `/var/lib/sys-auditd`, libcurl, monitor inotify, wykrywanie źródeł, wątek wysyłający, a potem wchodzi w pętlę.
Struktura wątków:

- **wątek główny**: obserwacja i tworzenie raportów, iteracja co najwyżej 1 s,
- **wątek `sender_loop`**: wysyłka z `pending/`; po przebiegu bez dostarczenia czeka 5 s (50 × 100 ms).


*`agent/src/main.c`, linie 29–37*

```c
static void *sender_loop(void *arg) {
  struct sender_args *s = arg;
  while (!stopping) {
    int sent = hp_send_pending(s->store, s->ip, s->port);
    if (sent > 0) continue;
    for (int i = 0; i < 50 && !stopping; i++) usleep(100000);
  }
  return NULL;
}
```

Jedna iteracja pętli głównej:


*`agent/src/main.c`, linie 99–109*

```c
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) {
      result = 1; stopping = 1; break;
    }
    if (hp_heartbeat_tick(&store, now.tv_sec + now.tv_nsec / 1e9, &heartbeat_deadline))
      gap_pending = 1;
    if (hp_monitor_poll(&monitor, 1000)) gap_pending = 1;
    int connection_result = hp_connections_poll(&connections, &store, now.tv_sec + now.tv_nsec / 1e9);
    if (connection_result && !network_failed &&
        hp_report_simple(&store, "network", "observation_gap", "", "tcp_observation_failed", NULL, 0)) gap_pending = 1;
    network_failed = !!connection_result;
```

Znaczenie kolejnych kroków:

1. **Heartbeat** (`hp_heartbeat_tick`): co około 60 s raport `system/heartbeat`.
2. **Monitor** (`hp_monitor_poll(&monitor, 1000)`): czeka do 1 s na zdarzenia inotify (`poll`), potem czyta nowe linie logów.
3. **TCP** (`hp_connections_poll`): zapytanie do jądra o gniazda. Błąd jest zgłaszany **raz** (flaga `network_failed`), nie przy każdej iteracji.
4. **`gap_pending`**: jeśli którykolwiek krok się nie powiódł, agent próbuje zapisać raport `monitor/observation_gap`. Dopóki zapis się nie uda, flaga zostaje.
5. **Co 60 s** ponowne wykrycie źródeł (`hp_discover_sources`); przy zmianie zestawu budowany jest nowy monitor, do którego przenoszone są offsety logów
   (nowy udział nie wymaga restartu, a logi nie są czytane od nowa).

Zamknięcie: po `SIGTERM` pętla się kończy, `pthread_join` czeka na wątek wysyłający (do 45 s, `TimeoutStopSec` w jednostce systemd).

### 4.3 Bezpieczne operacje plikowe (`io.c`)

Wszystkie ścieżki spod udziałów są otwierane względem deskryptora katalogu bazowego przez `openat2`, co uniemożliwia wyjście poza udział
(symlinki, `..`, dowiązania `/proc/*/fd`). Wyklucza to również podmianę ścieżki między sprawdzeniem a użyciem (TOCTOU).


*`agent/src/io.c`, linie 13–17*

```c
int hp_open_beneath(int root, const char *path, int flags, mode_t mode) {
  struct open_how how = { .flags = (uint64_t)(flags | O_CLOEXEC | O_NOFOLLOW), .mode = mode,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS };
  return (int)syscall(SYS_openat2, root, path, &how, sizeof(how));
}
```

Pliki robocze agenta (kolejka, kopie, metadane) przechodzą dodatkową kontrolę: zwykły plik, właściciel = bieżący euid, brak praw dla grupy i innych, dokładnie jedno dowiązanie.
Katalog roboczy jest sprawdzany podobnie (`hp_private_directory`). Jeśli ktoś podmieni plik w kolejce, agent go odrzuci.


*`agent/src/io.c`, linie 29–36*

```c
int hp_private_file(int root, const char *path, int flags, mode_t mode) {
  int fd = hp_open_beneath(root, path, flags | O_NONBLOCK, mode);
  if (fd < 0) return -1;
  struct stat st;
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
      (st.st_mode & 077) || st.st_nlink != 1) { close(fd); errno = EACCES; return -1; }
  return fd;
}
```

`hp_read_file` czyta plik w całości i porównuje `fstat` sprzed i po odczycie (rozmiar, mtime i ctime z dokładnością do nanosekund). Zmiana w trakcie daje `EAGAIN`.
Bufor jest zerowany przez `explicit_bzero` przed `free`.

### 4.4 Wykrywanie źródeł (`config.c`)

Agent nie ma własnej listy katalogów. `hp_discover_sources` składa listę z trzech części:

1. **Udziały i log Samby** z `/etc/samba/smb.conf` (`hp_discover_config`): własny parser sekcji INI z obsługą `include`, `path`, `available`, `printable`, `log file`.
   Udział `[homes]` jest rozwijany na katalogi domowe użytkowników z bazy kont Samby (`resolve_homes`, `getpwnam_r`).
2. **Logi systemowe**: `/var/log/messages`, `/var/log/secure`, `/var/log/cron`, `/var/log/maillog`, `/var/log/boot.log`. Brakujący plik daje źródło
   o statusie `missing_log`, a nie ciche pominięcie.
3. **Cały katalog `/var/log/samba/`**: każdy zwykły plik poza archiwami (`.gz .xz .bz2 .zst .zip`) i `.old`. Dzięki temu agent czyta także `audit.log` z `full_audit`.


*`agent/src/config.c`, linie 432–462*

```c
int hp_discover_sources(struct hp_sources *out) {
  if (hp_discover_config("/etc/samba/smb.conf", out)) return -1;
  static const char *logs[] = { "/var/log/messages", "/var/log/secure", "/var/log/cron", "/var/log/maillog", "/var/log/boot.log" };
  for (size_t i = 0; i < sizeof(logs) / sizeof(*logs); i++) {
    struct stat st;
    int missing = lstat(logs[i], &st) || !S_ISREG(st.st_mode);
    if (add_source(out, missing ? HP_SOURCE_STATUS : HP_LOG, "system_log", logs[i], missing ? "missing_log" : NULL)) return -1;
  }
  int fd = hp_open_absolute("/var/log/samba", O_RDONLY | O_DIRECTORY);
  DIR *dir = fd < 0 ? NULL : fdopendir(fd);
  if (!dir) { if (fd >= 0) close(fd); return add_source(out, HP_SOURCE_STATUS, "samba_logs", "/var/log/samba", "missing_log_directory"); }
  int result = 0;
  struct dirent *ent;
  errno = 0;
  while ((ent = readdir(dir))) {
    if (ent->d_name[0] == '.' || log_archive(ent->d_name)) continue;
    char path[4096];
    if (snprintf(path, sizeof(path), "/var/log/samba/%s", ent->d_name) >= (int)sizeof(path)) { result = -1; break; }
    struct stat st;
    if (out->count >= 4096) break;
    if (fstatat(fd, ent->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      if (errno == ENOENT) { errno = 0; continue; }
      result = -1; break;
    }
    if (S_ISREG(st.st_mode) && add_source(out, HP_LOG, "samba_log", path, NULL)) { result = -1; break; }
    errno = 0;
  }
  if (errno) result = -1;
  if (closedir(dir)) result = -1;
  return result;
}
```

Konta Samby czytane są natywnie z `passdb.tdb` (`libtdb`) albo z tekstowego `smbpasswd`, bez uruchamiania `pdbedit`. Plik otwierany jest przez własny deskryptor,
z blokadą odczytu `F_RDLCK`, z limitem 2 s i limitem liczby kluczy (`ACCOUNT_LIMIT`). Nazwa pliku przekazywana do `tdb_open` to `/proc/self/fd/N`, a nie ścieżka
kontrolowana przez kogokolwiek.


*`agent/src/config.c`, linie 238–252*

```c
  struct tdb_context *db = tdb_open(descriptor, 0, TDB_NOMMAP, O_RDONLY | O_CLOEXEC | O_NONBLOCK, 0);
  if (!db) { close(fd); return -1; }
  int result = -1;
  /* libtdb's lock-all API rejects O_RDONLY; this descriptor holds the fcntl read lock. */
  if (tdb_get_flags(db) & TDB_MUTEX_LOCKING) goto done;
  TDB_DATA version_key = { (unsigned char *)"INFO/version", sizeof("INFO/version") };
  TDB_DATA version = tdb_fetch(db, version_key);
  int compatible = version.dptr && version.dsize == 4 && version.dptr[0] == 4 && !version.dptr[1] && !version.dptr[2] && !version.dptr[3];
  if (version.dptr) { explicit_bzero(version.dptr, version.dsize); free(version.dptr); }
  if (!compatible) goto done;
  result = 0;
  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start)) { result = -1; goto done; }
  size_t visited = 0;
  TDB_DATA key = tdb_firstkey(db);
```

Czego agent nie umie zinterpretować (niedostępny log, błąd składni konfiguracji), zgłasza raportem `source_unavailable` z polem `error`.

### 4.5 Obserwacja plików: inotify (`monitor.c`)

Każdy udział jest obserwowany rekurencyjnie z maską:


*`agent/src/monitor.c`, linie 18–18*

```c
#define WATCH_MASK (IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF)
```

Katalog bazowy udziału jest otwierany przez `openat2` z `RESOLVE_BENEATH`, a `refresh_roots` sprawdza co iterację, czy to nadal ten sam katalog (`st_dev`/`st_ino`).
Podmiana lub usunięcie katalogu udziału daje `observation_gap` (`share_root_replaced_or_removed`) i ponowne zbudowanie obserwacji z rekoncyliacją.

Mapowanie zdarzeń inotify na operacje (fragment pętli obsługi):


*`agent/src/monitor.c`, linie 457–472*

```c
        if (event->mask & IN_CREATE) {
          if (remember_create(m, watch->root, rel)) failed = -1;
          continue;
        }
        if (event->mask & IN_DELETE) {
          if (created_match(m, watch->root, rel, 1))
            failed |= hp_report_simple(m->store, "share", "create_delete", rel, "contents_unavailable", NULL, 0);
          else failed |= hp_snapshot_event(m->store, root->fd, root->path, rel, "delete");
        } else if ((event->mask & IN_ATTRIB) && created_match(m, watch->root, rel, 0)) {
          continue;
        } else if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO | IN_ATTRIB)) {
          int created = created_match(m, watch->root, rel, 0);
          int result = hp_snapshot_event(m->store, root->fd, root->path, rel,
                                         event->mask & IN_MOVED_TO ? "create" :
                                         event->mask & IN_ATTRIB ? "metadata" :
                                         created ? "create" : "modify");
```

| Zdarzenie inotify | Operacja w raporcie |
|---|---|
| `IN_CLOSE_WRITE` (plik utworzony wcześniej) | `create` |
| `IN_CLOSE_WRITE` (plik istniał) | `modify` |
| `IN_MOVED_TO` bez pary `IN_MOVED_FROM` | `create` |
| `IN_MOVED_FROM` + `IN_MOVED_TO` o tym samym `cookie` | `rename` (z `previous_path`) |
| `IN_MOVED_TO` na istniejący plik | `rename_overwrite` (diff nadpisanego pliku) + `delete` starego miejsca |
| `IN_ATTRIB` | `metadata` (raport tylko, gdy zmieniły się tryb, uid, gid lub mtime) |
| `IN_DELETE` | `delete` (raport z całą ostatnią treścią) |
| `IN_DELETE` pliku utworzonego i usuniętego przed zamknięciem | `create_delete` (treść niedostępna) |
| `IN_Q_OVERFLOW` | `observation_gap` `inotify_overflow` |

Pamiętane są najwyżej **128** oczekujących utworzeń (`created`) i **128** oczekujących przeniesień (`moves`); przepełnienie daje `observation_gap`
(`create_queue_capacity`, `rename_cookie_capacity`). Czytane jest jedno `read()` na `poll`, żeby klient tworzący pliki szybciej niż agent nie zagłodził pętli.

### 4.6 Migawki, hashe i raport zmiany pliku (`snapshot.c`)

Dla każdego pliku agent trzyma w `snapshots/` pełną kopię pod nazwą `SHA-256(pełna ścieżka)`, plik `<hash>.path` z pełną ścieżką i `<hash>.stat`
z metadanymi (uid, gid, tryb, mtime, SHA-256 treści). Znacznik `root-<hash>` oznacza, że pierwszy skan danego udziału już się odbył.

Funkcja `capture()` kopiuje plik blokami po 64 KiB i do trzech razy powtarza próbę, jeśli w trakcie zmieniły się metadane pliku (`dev`, `ino`, rozmiar, mtime, ctime)
albo ścieżka wskazuje już na inny plik. Plik większy niż 64 MiB nie jest kopiowany. Po trzech nieudanych próbach raport dostaje błąd `unstable_capture`.


*`agent/src/snapshot.c`, linie 306–341*

```c
static int capture(int root, const char *relative, int dst, struct stat *result) {
  unsigned char buf[BLOCK];
  for (int attempt = 0; attempt < 3; attempt++) {
    int src = open_rooted(root, relative);
    if (src < 0) return -1;
    struct stat before, after;
    if (fstat(src, &before) || !S_ISREG(before.st_mode) || ftruncate(dst, 0) || lseek(dst, 0, SEEK_SET) < 0) { close(src); return -1; }
    if (before.st_size > CAPTURE_MAX) { close(src); errno = EFBIG; return -1; }
    long long copied = 0;
    int okay = 1;
    for (;;) {
      ssize_t n = read(src, buf, sizeof(buf));
      if (n < 0 && errno == EINTR) continue;
      if (n < 0) { okay = 0; break; }
      if (!n) break;
      copied += n;
      if (copied > CAPTURE_MAX) { okay = 0; errno = EFBIG; break; }   /* file grew while copying */
      if (hp_write_all(dst, buf, (size_t)n)) okay = 0;
      explicit_bzero(buf, sizeof(buf));
      if (!okay) break;
    }
    explicit_bzero(buf, sizeof(buf));
    if (fstat(src, &after)) okay = 0;
    close(src);
    if (!okay) return -1;
    int current = open_rooted(root, relative);
    struct stat at_path;
    if (current >= 0 && fstat(current, &at_path) == 0 &&
        same_stat(&before, &after) && same_stat(&after, &at_path)) {
      close(current); *result = after; return hp_sync(dst);
    }
    if (current >= 0) close(current);
  }
  errno = EAGAIN;
  return -1;
}
```

`hp_snapshot_event` jest centralną funkcją dla zdarzeń plikowych. Kolejność działań jest istotna, bo realizuje gwarancję „raport przed stanem":

1. wyznacza klucz (SHA-256 ścieżki) i otwiera starą kopię, jeśli istnieje (`old_fd`),
2. kopiuje obecny plik do pliku tymczasowego (`capture`), liczy SHA-256 obu wersji,
3. ignoruje zmiany bez znaczenia (ten sam rozmiar, hash i metadane), a ścieżki spod katalogu stanu agenta w ogóle pomija,
4. buduje raport: metadane, `evidence`, `content_changes` (diff tekstowy lub bloki binarne),
5. **`report_end`** (zapis i `fsync` raportu),
6. **dopiero potem** podmienia kopię (`renameat`) i zapisuje `.stat`, a przy usunięciu kasuje kopię.


*`agent/src/snapshot.c`, linie 671–707*

```c
  const char *reported_operation = !strcmp(operation, "baseline") ? "downtime_change" : operation;
  FILE *out = report_begin(s, "share", reported_operation, full, report);
  if (!out) goto fail;
  fprintf(out, ",\"metadata\":{\"old_size\":%lld,\"new_size\":%lld,\"old_mode\":",
          (long long)old_st.st_size, (long long)new_st.st_size);
  if (have_old_obs) fprintf(out, "%u", (unsigned)old_obs.mode); else fputs("null", out);
  fprintf(out, ",\"new_mode\":%u,\"old_uid\":", (unsigned)new_obs.mode);
  if (have_old_obs) fprintf(out, "%u", (unsigned)old_obs.uid); else fputs("null", out);
  fprintf(out, ",\"new_uid\":%u,\"old_gid\":", (unsigned)new_obs.uid);
  if (have_old_obs) fprintf(out, "%u", (unsigned)old_obs.gid); else fputs("null", out);
  fprintf(out, ",\"new_gid\":%u,\"mtime_sec\":%lld},", (unsigned)new_obs.gid, (long long)new_obs.mtime_sec);
  fputs("\"analysis\":{\"classification\":\"file_change\",\"actor\":null},\"evidence\":", out);
  write_evidence(out, s, full, NULL);
  fputs(",\"content_changes\":{", out);
  fputs("\"old_sha256\":", out);
  if (old_fd >= 0) hp_json_string(out, (unsigned char *)old_hash, strlen(old_hash)); else fputs("null", out);
  fputs(",\"new_sha256\":", out);
  if (new_fd >= 0) hp_json_string(out, (unsigned char *)new_hash, strlen(new_hash)); else fputs("null", out);
  int okay = hp_write_text_diff(out, old_fd, new_fd);
  if (okay == 1) {
    fputs(",\"format\":\"blocks64k\",\"blocks\":", out);
    okay = write_blocks(out, old_fd, new_fd);
  }
  if (okay || ferror(out)) {
    report_abort(s, out, report);
    hp_report_simple(s, "share", operation, full, "diff_failed", NULL, 0);
    goto fail;
  }
  fputs("},\"complete\":", out);
  int complete = (old_fd >= 0 || !strcmp(operation, "create")) &&
                 (old_fd < 0 || have_old_obs);
  fputs(complete && !okay ? "true" : "false", out);
  fputs(",\"error\":", out);
  if (okay) fputs("\"diff_failed\"", out);
  else if (!complete) fputs(old_fd >= 0 ? "\"missing_metadata_baseline\"" : "\"missing_baseline\"", out);
  else fputs("null", out);
  if (report_end(s, out, report)) goto fail;
```

Operacja `baseline` jest wewnętrzna: pierwszy skan udziału tylko zapamiętuje stan (bez raportów). Przy kolejnym starcie ten sam skan porównuje pliki z kopiami,
a różnice raportuje jako **`downtime_change`** (zmiana w czasie, gdy agent był wyłączony). Pliki usunięte w czasie przestoju wykrywa
`hp_snapshot_reconcile_deleted` (`delete_during_downtime`). Jeżeli katalog udziału jest pusty, kopie zostają, a agent zgłasza jeden `observation_gap` `share_root_empty`
zamiast raportować usunięcie wszystkiego.

Pola `complete` i `error` w raporcie: `complete=false` oznacza, że agent nie ma pełnego punktu odniesienia (`missing_baseline`, `missing_metadata_baseline`)
albo diff się nie powiódł (`diff_failed`).

#### Powiązanie pliku z logiem (`evidence`)

Każda linia logu, którą agent przeczytał, trafia do pierścienia 32 ostatnich linii (`hp_store_record_log`). W raporcie zmiany pliku `evidence[]` zawiera te z nich,
które są młodsze niż 60 s i **zawierają nazwę pliku** (sam człon po ostatnim `/`, także poprzednią nazwę przy `rename`). Dzięki `full_audit` taka linia niesie
użytkownika, adres IP klienta i nazwę udziału, więc raport zmiany pliku dostaje kontekst „kto". Jest to **kontekst, nie dowód** (`context_only: true`).


*`agent/src/snapshot.c`, linie 26–35*

```c
static void write_evidence(FILE *out, const struct hp_store *s, const char *path, const char *previous_path);

struct hp_observed {
  mode_t mode;
  uid_t uid;
  gid_t gid;
  time_t mtime_sec;
  long mtime_nsec;
  char sha[65];
};
```

### 4.7 Diff (`diff.c`)

Dla plików tekstowych (poprawny UTF-8, brak bajtu `0x00`, rozmiar do 1 MiB) `hp_write_text_diff` generuje **unified diff** z kontekstem 3 linii.
Algorytm: pominięcie wspólnego prefiksu i sufiksu linii, a środek porównywany metodą najdłuższego wspólnego podciągu na tablicy programowania dynamicznego
(**nie** jest to algorytm Myersa). Tablica ma najwyżej `HP_LCS_CELLS` = 1 048 576 komórek; przy większych zmianach agent nie oblicza LCS i oznacza cały zakres
jako usunięty i dodany (jeden duży hunk).


*`agent/src/diff.c`, linie 85–105*

```c
  size_t n = a.lines - prefix - suffix, m = b.lines - prefix - suffix;
  size_t columns = m + 1;
  if (n && m && n + 1 <= HP_LCS_CELLS / columns) {
    matrix = calloc((n + 1) * columns, sizeof(*matrix));
    if (!matrix) goto done;
    for (size_t i = n; i-- > 0;) for (size_t j = m; j-- > 0;) {
      uint32_t down = matrix[(i + 1) * columns + j], right = matrix[i * columns + j + 1];
      matrix[i * columns + j] = equal_line(&a, prefix + i, &b, prefix + j)
        ? 1 + matrix[(i + 1) * columns + j + 1] : down > right ? down : right;
    }
    size_t i = 0, j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && equal_line(&a, prefix + i, &b, prefix + j)) { ops[count++] = ' '; i++; j++; }
      else if (i < n && (j == m || matrix[(i + 1) * columns + j] >= matrix[i * columns + j + 1])) {
        ops[count++] = '-'; i++;
      } else { ops[count++] = '+'; j++; }
    }
  } else {
    /* shortcut: bound quadratic LCS work; large edits use a complete replacement hunk. */
    memset(ops + count, '-', n); count += n;
    memset(ops + count, '+', m); count += m;
```

Pliki binarne, niepoprawny UTF-8 lub pliki ponad 1 MiB dostają zamiast tego **diff blokowy**: `hp_write_text_diff` zwraca 1, a `snapshot.c` zapisuje listę bloków
64 KiB, które się zmieniły (`offset`, `old_base64`, `new_base64`), do łącznie 16 MiB na raport (`BLOCKS_MAX`). Przekroczenie daje `diff_failed`.


*`agent/src/snapshot.c`, linie 573–606*

```c
static int write_blocks(FILE *out, int old_fd, int new_fd) {
  unsigned char a[BLOCK], b[BLOCK];
  off_t offset = 0;
  int first = 1;
  long long total = 0;
  if ((old_fd >= 0 && lseek(old_fd, 0, SEEK_SET) < 0) || (new_fd >= 0 && lseek(new_fd, 0, SEEK_SET) < 0)) return -1;
  fputc('[', out);
  for (;;) {
    ssize_t an = read_block(old_fd, a);
    ssize_t bn = read_block(new_fd, b);
    if (an < 0 || bn < 0) {
      explicit_bzero(a, sizeof(a)); explicit_bzero(b, sizeof(b)); return -1;
    }
    if (!an && !bn) break;
    if (an != bn || memcmp(a, b, (size_t)an)) {
      total += an + bn;
      if (total > BLOCKS_MAX) {   /* report would be too large for the server */
        explicit_bzero(a, sizeof(a)); explicit_bzero(b, sizeof(b)); return -1;
      }
      if (!first) fputc(',', out);
      first = 0;
      fprintf(out, "{\"offset\":%lld,\"old_base64\":", (long long)offset);
      hp_json_base64(out, a, (size_t)an);
      fputs(",\"new_base64\":", out);
      hp_json_base64(out, b, (size_t)bn);
      fputc('}', out);
    }
    explicit_bzero(a, sizeof(a));
    explicit_bzero(b, sizeof(b));
    offset += BLOCK;
  }
  fputc(']', out);
  return 0;
}
```

### 4.8 Obserwacja logów i klasyfikacja (`monitor.c`, `snapshot.c`)

Logi są czytane przyrostowo przy każdej iteracji. Zasady:

- przy pierwszym zobaczeniu pliku offset ustawiany jest na jego **koniec**, więc historia sprzed startu agenta jest pomijana,
- **jedna linia logu to jeden raport** `log/append`; linia dłuższa niż 64 KiB jest dzielona (`long_record_segment`),
- niedokończona linia jest buforowana i wysyłana po dojściu znaku nowej linii,
- na plik przypada do 1 MiB odczytu na iterację,
- rotacja (zmiana `st_dev`/`st_ino`) i obcięcie (`st_size < offset` albo zmiana odcisku początku pliku) dają raport `rotation` / `truncation` z błędem `possible_log_gap`;
  niedokończona linia w momencie rotacji jest wysyłana osobno (`partial_record_at_rotation`).


*`agent/src/monitor.c`, linie 165–188*

```c
      if (!log->seen) {
        if (hp_report_simple(m->store, "log", "source_unavailable", log->path, "missing_or_inaccessible_log", NULL, 0))
          failed = 1;
        else log->seen = 1;
      }
      continue;
    }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); failed = 1; continue; }
    if (!log->seen) {
      log->offset = st.st_size;
      log->fingerprint_size = 0;
      log->seen = 1;
    } else if (log->device != st.st_dev || log->inode != st.st_ino) {
      if (log->partial_size &&
          hp_report_simple(m->store, "log", "append", log->path, "partial_record_at_rotation", log->partial, log->partial_size)) {
        close(fd); failed = 1; continue;
      }
      if (log->partial) explicit_bzero(log->partial, log->partial_size);
      log->partial_size = 0;
      if (hp_report_simple(m->store, "log", "rotation", log->path, "possible_log_gap", NULL, 0)) {
        close(fd); failed = 1; continue;
      }
      log->offset = 0; log->fingerprint_size = 0;
```

#### Klasyfikacja linii

Cały „silnik wykrywania" po stronie agenta to szukanie podciągów w treści linii:


*`agent/src/snapshot.c`, linie 426–439*

```c
  const char *classification = "unknown";
  if (content && (memmem(content, content_size, "Failed password", 15) ||
                  memmem(content, content_size, "NT_STATUS_LOGON_FAILURE", 23) ||
                  memmem(content, content_size, "NT_STATUS_WRONG_PASSWORD", 24) ||
                  memmem(content, content_size, "NT_STATUS_NO_SUCH_USER", 22)))
    classification = "authentication_failure";
  else if (content && (memmem(content, content_size, "status [NT_STATUS_OK]", 21) ||
                       memmem(content, content_size, "Accepted password", 17) ||
                       memmem(content, content_size, "Accepted publickey", 18)))
    classification = "authentication_success";
  else if (content && memmem(content, content_size, "smbd_audit", 10))
    classification = "samba_audit";
  else if (!strcmp(operation, "heartbeat"))
    classification = "heartbeat";
```

| Klasyfikacja | Warunek |
|---|---|
| `authentication_failure` | `Failed password`, `NT_STATUS_LOGON_FAILURE`, `NT_STATUS_WRONG_PASSWORD` lub `NT_STATUS_NO_SUCH_USER` |
| `authentication_success` | `status [NT_STATUS_OK]`, `Accepted password` lub `Accepted publickey` |
| `access_denied` | `NT_STATUS_ACCESS_DENIED` poza liniami `smbd_audit` (Samba odmówiła dostępu) |
| `invalid_user` | `Invalid user <nazwa> from <IP>` (sshd: konto nie istnieje) |
| `service_probe` | `Did not receive identification string from`, `banner exchange: Connection from`, `kex_exchange_identification:` (połączenie z portem 22 bez rozmowy po SSH, np. `nmap -sV`) |
| `samba_audit` | `smbd_audit` (linie `full_audit` z syslogu i `audit.log`) |
| `heartbeat` | operacja `heartbeat` |
| `unknown` | wszystko inne |

Kolejność sprawdzania (`hp_classify` w `agent/src/event.c`): linia hooka PAM, `authentication_failure`, `authentication_success`,
`access_denied`, `invalid_user`, `service_probe`, `samba_audit`, `heartbeat`. Linia z hasłem wygrywa więc z `Invalid user` z tej samej próby.
Fragment kodu powyżej pokazuje pierwotną wersję z `snapshot.c`; obecnie klasyfikacja jest w `event.c`.

Odpowiadające typy w bloku `event` (schema v2):

| Klasyfikacja | `event.type` | `event.service` | Uwagi |
|---|---|---|---|
| `authentication_failure` | `auth.failure` | `ssh` / `smb` | serwis z treści linii (`NT_STATUS`/`smbd` → `smb`) |
| `authentication_success` | `auth.success` | `ssh` / `smb` | |
| `access_denied` | `auth.denied` | `smb` | użytkownik z `user [DOMENA]\[nazwa]` |
| `invalid_user` | `auth.invalid_user` | `ssh` | nie liczy się jako nieudane logowanie (linia `Failed password` przychodzi osobno) |
| `service_probe` | `net.probe` | `ssh` | IP brany po **ostatnim** ` from `; linia `kex_exchange_identification` nie ma IP (na Almie 10 adres jest w następnej linii, nie jest jeszcze łączony) |

Adres i port źródłowy przy `Invalid user` i sondzie są brane po ostatnim ` from ` w linii, bo nazwę użytkownika podaje atakujący
i może ona zawierać fałszywe ` from <IP>`.

Raporty „proste" (`hp_report_simple`) mają w `analysis` tylko pole `classification`; raporty zmian plików mają także `"actor": null`.

#### Kontekst sieciowy z linii (`network.c`, `arp.c`)

Dla każdego raportu z treścią agent wyciąga adresy IP (`hp_extract_ips`, najwyżej `HP_NETWORK_MAX` różnych) i zapisuje je w `network_context.endpoints[]`.
**Kolejność ma znaczenie**: w liniach Samby klient jest w `remote host [ipv4:A.B.C.D:port]`, a nazwa użytkownika przed nim jest kontrolowana przez atakującego,
dlatego ten adres jest dodawany jako pierwszy. Serwer używa później tylko `endpoints[0]` (rozdz. 7.2).


*`agent/src/network.c`, linie 56–72*

```c
void hp_extract_ips(const unsigned char *content, size_t size, struct hp_network_context *context) {
  memset(context, 0, sizeof(*context));
  // Samba: the real client is in "remote host [ipv4:A.B.C.D:port]", but the user name before it is attacker-controlled, so add it first
  static const char marker[] = "remote host [";
  const unsigned char *remote = memmem(content, size, marker, sizeof(marker) - 1);
  if (remote) {
    const unsigned char *start = remote + sizeof(marker) - 1, *end = start;
    while (end < content + size && address_char(*end)) end++;
    add_ip_token(start, end - start, context);
  }
  for (size_t i = 0; i < size;) {
    if (!address_char(content[i])) { i++; continue; }
    size_t start = i;
    while (i < size && address_char(content[i])) i++;
    add_ip_token(content + start, i - start, context);
  }
}
```

Adresy mogą występować w formatach `A.B.C.D`, `A.B.C.D:port`, `ipv4:A.B.C.D:port` (Samba), IPv6 i IPv4-mapped IPv6. `hp_write_network_context` zapisuje je z
`mac_status: "not_looked_up"`. Dla **połączeń TCP** i tam, gdzie wywołano `hp_write_endpoint`, adres MAC jest odczytywany z tablicy ARP jądra
(`ioctl(SIOCGARP)`) tylko dla adresów IPv4 z tej samej podsieci co któryś interfejs:


*`agent/src/arp.c`, linie 34–50*

```c
    struct arpreq entry = {0};
    memcpy(&entry.arp_pa, &target, sizeof(target));
    if (snprintf(entry.arp_dev, sizeof(entry.arp_dev), "%s", p->ifa_name) >= (int)sizeof(entry.arp_dev)) {
      failed = 1; continue;
    }
    if (ioctl(fd, SIOCGARP, &entry)) {
      if (errno != ENXIO && errno != ENOENT && errno != ENODEV) failed = 1;
      continue;
    }
    const unsigned char *bytes = (const unsigned char *)entry.arp_ha.sa_data;
    static const unsigned char zero[6];
    if (!(entry.arp_flags & ATF_COM) || entry.arp_ha.sa_family != ARPHRD_ETHER ||
        (bytes[0] & 1) || !memcmp(bytes, zero, sizeof(zero))) continue;
    if (device[0] && strcmp(device, p->ifa_name)) { status = "ambiguous_interfaces"; break; }
    snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    snprintf(device, IF_NAMESIZE, "%s", p->ifa_name);
    status = "resolved";
```

Możliwe wartości `mac_status`: `resolved`, `not_in_local_arp_cache`, `ambiguous_interfaces`, `ipv6_no_arp`, `invalid_ip`, `lookup_error`, `not_looked_up`.
MAC jest widoczny tylko w obrębie jednej sieci L2; dla klienta zza routera jest `null`.

#### 4.8a Hasła z prób SSH i skany portów (0.3.0)

- **`auth.attempt`.** `scripts/hp-pam-log` (wywoływany z `pam_exec.so expose_authtok` w `/etc/pam.d/sshd`) zapisuje przez `logger`
  linię `hp-pam: u=<base64 użytkownik> h=<rhost> p=<base64 hasło>` do `/var/log/secure`. Wpięcie w PAM ma uruchamiać hook
  **tylko po nieudanym `pam_unix`**, więc hasło udanego logowania nie trafia do logu. Instalator robi to tylko przy
  `HP_PAM_HOOK=yes` (niezweryfikowane na Almie). Agent parsuje linię
  w `event.c` (`parse_pam`): znacznik programu musi być 5. polem linii syslog (nazwa użytkownika w linii `sshd` jest kontrolowana
  przez atakującego, więc podrobiona linia `hp-pam:` nie tworzy zdarzenia), base64 dekodowany ściśle, hasło obcinane do 256 bajtów.
- **`net.scan`.** `firewall-cmd --set-log-denied=all` zapisuje odrzucone pakiety do `/var/log/messages`. W `poll_logs` (`monitor.c`)
  linie z logu o nazwie `messages` trafiają najpierw do `hp_scan_feed` (`scan.c`): linia zapory (5. pole `kernel:`, `PROTO=TCP`,
  `SRC=`, `DST=`, `DPT=`) jest **konsumowana i nie tworzy osobnego raportu**. Tracker liczy różne porty na źródło (tablica
  1024 źródeł, wypieranie najstarszego); po 10 portach w 10 s powstaje jedno `net.scan`, a źródło jest wyciszane do końca okna
  (`hp_scan_ack` po udanym zapisie raportu, więc nieudany zapis jest ponawiany). Linie jądra z `SRC=`/`DST=`/`PROTO=` innego protokołu niż TCP (UDP, ICMP, broadcasty) są konsumowane i nie liczą się do skanu, żeby
  `--set-log-denied=all` nie zalewał serwera raportami. Skutek uboczny: pojedyncze odrzucone pakiety poniżej progu (i cały ruch
  nie-TCP) nie zostawiają śladu. Wpięcie hooka w PAM robi `scripts/hp-pam-wire` (kopia z bieżącego pliku, weryfikacja przed
  zapisem); zastępuje podstawkę `password-auth`, więc znikają m.in. `pam_sss` i `pam_faildelay` (sonda B9). Próg i okno to stałe w `scan.h` (bez konfiguracji w czasie działania); stan trackera
  zeruje się przy zmianie źródeł logów (nowy monitor w `main.c`).

### 4.9 Połączenia TCP (`connections.c`)

Co iterację (około 1 s) agent wysyła do jądra zapytanie netlink `NETLINK_SOCK_DIAG` / `SOCK_DIAG_BY_FAMILY` osobno dla `AF_INET` i `AF_INET6`
(najwyżej `HP_SOCKET_LIMIT` = 65 536 gniazd) i dostaje listę gniazd TCP. Połączenie `ESTABLISHED` jest raportowane **raz**, jeśli na tym samym porcie lokalnym
i w tej samej rodzinie adresów istnieje gniazdo `LISTEN` (na adresie wildcard albo na tym samym adresie). To znaczy: raportowane są połączenia do **każdej**
usługi nasłuchującej na maszynie, nie tylko 22/139/445. Także własne połączenie agenta do kolektora (rozdz. 6.4) i tunel SSH operatora.


*`agent/src/connections.c`, linie 38–49*

```c
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
```

*`agent/src/connections.c`, linie 69–77*

```c
    if (socket->state != TCP_ESTABLISHED) continue;
    int known = observer->count && bsearch(socket, observer->seen, observer->count, sizeof(*observer->seen), socket_compare);
    if (!known && !has_listener(socket, sockets, count)) continue;
    char local[INET6_ADDRSTRLEN], peer[INET6_ADDRSTRLEN];
    int report_failed = !known && (socket_ip(socket, socket->local, local) || socket_ip(socket, socket->peer, peer) ||
                   hp_report_connection(store, local, socket->local_port, peer, socket->peer_port));
    explicit_bzero(local, sizeof(local)); explicit_bzero(peer, sizeof(peer));
    if (report_failed) { failed = 1; continue; }
    next[next_count++] = *socket;
```

Zbiór już zaraportowanych gniazd (`observer->seen`) jest sortowany po cookie gniazda z jądra i przeszukiwany przez `bsearch`; gniazdo znika ze zbioru, gdy
połączenie się zakończy. Raport ma `source: network`, `operation: tcp_connection_observed`, `classification: tcp_connection`
i `connection.peer` z IP oraz MAC klienta.

### 4.10 Heartbeat (`heartbeat.c`)

Raport `system/heartbeat` wysyłany jest co `HEARTBEAT_INTERVAL` = 60 s z losowym rozrzutem ±15% z `getrandom()`. Pierwsze wywołanie tylko ustawia termin (nie wysyła).
Kolektor uznaje agenta za `online`, jeśli ostatni raport dotarł w ciągu 90 s.


*`agent/src/heartbeat.c`, linie 9–19*

```c
int hp_heartbeat_tick(struct hp_store *store, double now, double *deadline) {
  if (*deadline && now < *deadline) return 0;
  uint32_t random;
  ssize_t n;
  do { n = getrandom(&random, sizeof(random), 0); } while (n < 0 && errno == EINTR);
  if (n != sizeof(random)) return -1;
  if (*deadline && hp_report_simple(store, "system", "heartbeat", "", NULL, NULL, 0))
    return -1;
  *deadline = now + HEARTBEAT_INTERVAL * (.85 + .30 * (random / (double)UINT32_MAX));
  return 0;
}
```

### 4.11 Raport i kolejka (`snapshot.c`, `protocol.c`)

Raport powstaje w pliku tymczasowym `.<id>.tmp` w `pending/` (`O_CREAT|O_EXCL`, tryb 0600) i jest zapisywany strumieniowo. `report_end` dopisuje `}`,
robi `fflush`, `fsync` pliku, **atomowy `renameat2(..., RENAME_NOREPLACE)`** na `<id>.json` i `fsync` katalogu. Kolejka nigdy nie zawiera połowicznego raportu.


*`agent/src/snapshot.c`, linie 396–410*

```c
static int report_end(struct hp_store *s, FILE *out, const char *filename) {
  char tmp[80];
  snprintf(tmp, sizeof(tmp), ".%.64s.tmp", filename);
  int fd = fileno(out);
  if (ferror(out) || fputc('}', out) == EOF || fflush(out) || hp_sync(fd)) {
    fclose(out); explicit_bzero(s->report_buffer, sizeof(s->report_buffer));
    unlinkat(s->pending_fd, tmp, 0); return -1;
  }
  int close_failed = fclose(out);
  explicit_bzero(s->report_buffer, sizeof(s->report_buffer));
  if (close_failed || renameat2(s->pending_fd, tmp, s->pending_fd, filename, RENAME_NOREPLACE) || hp_sync(s->pending_fd)) {
    unlinkat(s->pending_fd, tmp, 0); return -1;
  }
  return 0;
}
```

`protocol.c` dostarcza serializację: `hp_valid_utf8` (ścisła walidacja sekwencji UTF-8), `hp_json_escaped`, `hp_json_base64` (`EVP_EncodeBlock`, porcje 3072 bajtów),
`hp_report_id` (32 bajty z `RAND_bytes` jako 64 znaki hex), `hp_utc_time` (`gmtime_r`, format `YYYY-MM-DDTHH:MM:SSZ`). Ścieżki i treści, które nie są poprawnym UTF-8,
trafiają do pól `*_base64`, a pole tekstowe ma wtedy wartość `null`.


*`agent/src/protocol.c`, linie 55–68*

```c
int hp_report_id(char out[65]) {
  static const char hex[] = "0123456789abcdef";
  unsigned char bytes[32];
  if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
    explicit_bzero(bytes, sizeof(bytes)); explicit_bzero(out, 65); return -1;
  }
  for (size_t i = 0; i < sizeof(bytes); i++) {
    out[i * 2] = hex[bytes[i] >> 4];
    out[i * 2 + 1] = hex[bytes[i] & 15];
  }
  out[64] = 0;
  explicit_bzero(bytes, sizeof(bytes));
  return 0;
}
```

Kolejka mieści `PENDING_MAX` = 10 000 raportów; liczbę plików agent szacuje i skanuje katalog najwyżej raz na sekundę. Po przekroczeniu limitu nowe raporty są odrzucane
(serwer niedostępny przez długi czas), a agent zgłasza `observation_gap`.

### 4.12 Wysyłka (`port.c`)

Wątek wysyłający przegląda `pending/`, bierze pliki o nazwie `<64 hex>.json`, otwiera je przez `hp_private_file` i wysyła `POST` przez libcurl
(`https://IP:PORT/events`, dla IPv6 w nawiasach). Weryfikacja TLS jest **zawsze włączona**, przekierowania i proxy wyłączone, timeouty 5 s na połączenie i 30 s całkowity.


*`agent/src/port.c`, linie 66–73*

```c
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_PROXY, "") != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK) {
```

Reakcja na odpowiedź:


*`agent/src/port.c`, linie 78–81*

```c
    if (result == CURLE_OK && curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK) {
      acknowledged = status >= 200 && status < 300;
      rejected = status >= 300 && status < 500 && status != 408 && status != 429;
      retry_later = status >= 500 || status == 408 || status == 429;
```

*`agent/src/port.c`, linie 89–103*

```c
    if (rejected) {
      // Park it under a name the queue filter ignores and go on with the next
      // report; otherwise this one is retried first, forever, and blocks the rest.
      char parked[96];
      if (snprintf(parked, sizeof(parked), "%s.rejected", ent->d_name) < (int)sizeof(parked) &&
          !renameat(store->pending_fd, ent->d_name, store->pending_fd, parked)) continue;
    }
    if (acknowledged) {
      if (unlinkat(store->pending_fd, ent->d_name, 0) || hp_sync(store->pending_fd)) delivered = -1;
      else delivered = 1;
    }
    // No HTTP answer (connection or TLS error) stops the round as before; a 5xx/408/429 answer
    // moves on, and only 3 failures in a row end the round. Files are never parked for this.
    if (retry_later && delivered == 0 && ++failures < 3) continue;
    break;
```

| Odpowiedź | Skutek |
|---|---|
| 2xx | `unlinkat` raportu i `fsync` katalogu |
| 3xx, 4xx (poza 408 i 429) | plik zmienia nazwę na `<id>.json.rejected` i jest pomijany; reszta kolejki idzie dalej |
| 5xx, 408, 429 | raport zostaje; po 3 takich odpowiedziach z rzędu przebieg się kończy |
| brak odpowiedzi (błąd połączenia, TLS) | przebieg się kończy, kolejna próba po 5 s |

Pliki `.rejected` są odkładane na stałe (agent ich nie ponawia i nie czyści) i nie liczą się do limitu kolejki. Powód: bez parkowania jeden zły raport byłby
ponawiany w nieskończoność jako pierwszy i blokowałby resztę.

### 4.13 Mechanizmy ochronne w agencie

- **Brak `fork`/`exec`.** W kodzie agenta nie ma `fork`, `exec*`, `system` ani `popen`; konfigurację Samby, bazę kont, ARP i gniazda czyta się przez API jądra i biblioteki.
- **Ścieżki:** `openat2` z `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` (rozdz. 4.3).
- **Uprawnienia:** `umask(0077)`, katalogi 0700, pliki 0600, `hp_private_file` odrzuca pliki cudze, czytelne dla innych lub z dodatkowymi dowiązaniami.
- **Zerowanie pamięci:** bufory z treścią plików, logów, kont, adresów i hashy są zerowane przez `explicit_bzero` (kilkadziesiąt miejsc), żeby nie trafiły do swapa ani zrzutu pamięci.
- **TLS:** `CURLOPT_SSL_VERIFYPEER=1`, `CURLOPT_SSL_VERIFYHOST=2`, bez opcji wyłączenia. Adres docelowy musi być w SAN certyfikatu kolektora.
- **Maskowanie procesu:** nazwa procesu i `argv[0]` to `sys-auditd`. Utrudnia to odczytanie parametrów w `ps`, ale nie chroni przed rootem.

### 4.14 Jednostka systemd (`agent/packaging/sys-auditd.service`)


*`agent/packaging/sys-auditd.service`, linie 1–37*

```ini
[Unit]
Description=System audit state monitor
Wants=network-online.target
After=network-online.target smb.service rsyslog.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/sbin/sys-auditd
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
Restart=on-failure
RestartSec=5s
TimeoutStopSec=45s
StateDirectory=sys-auditd
StateDirectoryMode=0700
UMask=0077
ProtectProc=invisible
ProcSubset=pid
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
LimitCORE=0
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
```

Agent działa jako root, ale z ograniczeniem uprawnień do `CAP_DAC_READ_SEARCH` (czytanie plików niezależnie od praw), `NoNewPrivileges`, `ProtectSystem=strict`
(zapis tylko do `StateDirectory=/var/lib/sys-auditd`), bez zrzutów pamięci (`LimitCORE=0`) i bez stdout/stderr. `Restart=on-failure` z 5 s przerwy.
Parametry `--id/--ip/--port` instalator dopisuje w `/etc/systemd/system/sys-auditd.service.d/override.conf` (rozdz. 10.3).


---

## 5. Protokół agent → serwer

Transport: HTTPS (TLS 1.2 lub 1.3), `POST /events`, `Content-Type: application/json`, treść do 64 MB. Ten sam odbiornik jest dostępny jako `POST /api/events`;
agent ma ścieżkę `/events` zapisaną na stałe w `port.c`. Pełna specyfikacja API: `server/docs/api.md`.

### 5.1 Koperta

| Pole | Typ | Opis |
|---|---|---|
| `schema_version` | int | `1` lub `2` (v2 dodaje `agent_version` i blok `event`, patrz `server/docs/api.md`) |
| `report_id` | string | 64 znaki hex (małe litery); unikalny, transmisja bywa ponawiana |
| `agent_id` | string | `[A-Za-z0-9._-]`, 1–64 znaków |
| `observed_at` | string | czas zdarzenia UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `source` | string | `share`, `log`, `network`, `system`, `monitor`, `source` |
| `operation` | string | `[a-z0-9_]`, 1–64 znaków (słownik w rozdz. 15) |
| `path` | string lub `null` | ścieżka; `null` + `path_base64`, gdy nazwa nie jest poprawnym UTF-8 |
| `metadata` | object | rozmiary, tryb, uid/gid, mtime (zmiany plików) lub `{}` |
| `analysis` | object | `classification` oraz (dla zmian plików i połączeń) `actor: null` |
| `evidence` | array | linie logów z ostatnich 60 s powiązane z plikiem (zmiany plików, rename) |
| `content_changes` | object lub null | `old_sha256`, `new_sha256`, `format` (`unified` lub `blocks64k`), `diff`/`blocks` |
| `network_context` | object | `endpoints[]` z IP (i MAC) wyciągniętymi z treści linii logu |
| `content` / `content_base64` | string | treść linii logu (raporty `log`) |
| `connection` | object | tylko `tcp_connection_observed` |
| `complete`, `error` | bool, string | `complete=false` i przyczyna, gdy agent nie ma pełnych danych |

### 5.2 Przykład: modyfikacja pliku

Przykład ilustracyjny (wartości wymyślone, układ pól zgodny z `hp_snapshot_event`):

```json
{
  "schema_version": 1,
  "report_id": "a8f3d1b2e4c567890123456789abcdef0123456789abcdef0123456789abcdef",
  "agent_id": "fs-finanse",
  "observed_at": "2026-11-20T17:04:00Z",
  "source": "share",
  "operation": "modify",
  "path": "/srv/samba/Finanse/Budzet/budzet_2024_projekt.csv",
  "metadata": { "old_size": 128, "new_size": 142, "old_mode": 432, "new_mode": 432,
                "old_uid": 0, "new_uid": 0, "old_gid": 1002, "new_gid": 1002, "mtime_sec": 1795194240 },
  "analysis": { "classification": "file_change", "actor": null },
  "evidence": [
    { "source": "/var/log/samba/audit.log", "context_only": true,
      "content": "Nov 20 17:03:58 fs-finanse smbd_audit[2211]: a.kowalska|10.0.0.77|pc-ksiegowosc|Finanse|pwrite|ok|Budzet/budzet_2024_projekt.csv",
      "network_context": { "endpoints": [ { "ip": "10.0.0.77", "mac": null, "interface": null,
                           "mac_status": "not_looked_up", "mac_source": "none", "context_only": true } ],
                           "truncated": false } } ],
  "content_changes": { "old_sha256": "e3b0c4...", "new_sha256": "f2ca1b...", "format": "unified",
                       "diff": "--- old\n+++ new\n@@ -2,1 +2,1 @@\n-Wynagrodzenia;1200000;980000\n+Wynagrodzenia;1200000;990000\n" },
  "complete": true,
  "error": null
}
```

### 5.3 Przykład: połączenie TCP

Format zapisu pochodzi z `hp_report_connection` (`snapshot.c`):


*`agent/src/snapshot.c`, linie 460–474*

```c
int hp_report_connection(struct hp_store *s, const char *local_ip, unsigned short local_port,
                          const char *peer_ip, unsigned short peer_port) {
  char filename[80];
  FILE *out = report_begin(s, "network", "tcp_connection_observed", "", filename);
  if (!out) return -1;
  fputs(",\"metadata\":{},\"analysis\":{\"classification\":\"tcp_connection\",\"actor\":null},"
        "\"evidence\":[],\"content_changes\":null,\"complete\":true,\"error\":null,\"connection\":{"
        "\"protocol\":\"tcp\",\"state\":\"ESTABLISHED\",\"direction\":\"inbound_listener_match\","
        "\"observation_method\":\"inet_diag_poll\",\"local_ip\":", out);
  hp_json_string(out, (const unsigned char *)local_ip, strlen(local_ip));
  fprintf(out, ",\"local_port\":%hu,\"peer_port\":%hu,\"peer\":", local_port, peer_port);
  hp_write_endpoint(out, peer_ip);
  fputc('}', out);
  return report_end(s, out, filename);
}
```

```json
{
  "schema_version": 1, "report_id": "b9e4f2a1...", "agent_id": "fs-finanse",
  "observed_at": "2026-11-20T17:05:12Z", "source": "network",
  "operation": "tcp_connection_observed", "path": "",
  "metadata": {}, "analysis": { "classification": "tcp_connection", "actor": null },
  "evidence": [], "content_changes": null, "complete": true, "error": null,
  "connection": {
    "protocol": "tcp", "state": "ESTABLISHED",
    "direction": "inbound_listener_match", "observation_method": "inet_diag_poll",
    "local_ip": "10.0.0.5", "local_port": 445, "peer_port": 52134,
    "peer": { "ip": "10.0.0.77", "mac": "00:11:22:33:44:55", "interface": "enp0s8",
              "mac_status": "resolved", "context_only": true }
  }
}
```

### 5.4 Przykład: linia logu (nieudane logowanie)

```json
{
  "schema_version": 1, "report_id": "c1d2...", "agent_id": "fs-finanse",
  "observed_at": "2026-11-20T17:06:40Z", "source": "log", "operation": "append",
  "path": "/var/log/secure",
  "metadata": {}, "analysis": { "classification": "authentication_failure" },
  "network_context": { "endpoints": [ { "ip": "10.0.0.99", "mac": null, "interface": null,
                       "mac_status": "not_looked_up", "mac_source": "none", "context_only": true } ], "truncated": false },
  "evidence": [], "content_changes": null, "complete": true, "error": null,
  "content": "Nov 20 17:06:40 fs-finanse sshd[4121]: Failed password for backup_srv from 10.0.0.99 port 50212 ssh2\n"
}
```

### 5.5 Odpowiedzi serwera

| Kod | Treść | Zachowanie agenta |
|---|---|---|
| `201` | `{"event_id":N,"report_id":"..."}` | zapisany (na dysku, `fsync`), agent kasuje z kolejki |
| `200` | `{"report_id":"...","duplicate":true}` | ten `report_id` już był, agent kasuje |
| `200` | `{"report_id":"...","ignored":true}` | własne połączenie agenta z kolektorem na loopbacku; nie zapisano, agent kasuje |
| `400` | błąd | zły JSON lub zła koperta albo ponad 1000 różnych `agent_id`; agent parkuje raport jako `.rejected` |
| `413` | błąd | raport ponad 64 MB; jak wyżej |
| `5xx` | błąd | chwilowy problem; agent ponawia |

---

## 6. Serwer `sysmon-collector`

Java 21, Javalin (Jetty), Jackson, Maven (`server/pom.xml`). Pakiet `pl.honeypot.server`: `Main`, `ServerConfig`, `api/*` (handlery), `store/*` (`JsonlLog`, `ReportStore`).
Artefakt: `target/honeypot-server.jar`.

### 6.1 Konfiguracja (`ServerConfig`)

Plik `.properties` jako pierwszy argument (domyślnie `config/server.properties`).

| Klucz | Domyślnie | Znaczenie |
|---|---|---|
| `server.bind` | `127.0.0.1` | adres nasłuchu |
| `server.port` | `8443` | port HTTPS |
| `server.keystore` | **wymagany** | PKCS12 z certyfikatem i kluczem; plik musi istnieć |
| `server.keystore.password` | **wymagane, niepuste** | hasło keystore |
| `data.dir` | `data` | katalog `events.jsonl` (tworzony przy starcie) |
| `dashboard.dir` | `../dashboard` | katalog statycznego dashboardu; pusty lub nieistniejący = nie serwuj |
| `detection.confirm.accounts` | `backup_srv` | konta-przynęty; udane logowanie = `confirmed`, każda próba = `bait` |
| `detection.breadcrumb.marker` | `kopia_zapasowa.sh` | fragment treści logu oznaczający odczyt okruszka |
| `alert.enabled` | `false` | alarmy e-mail (rozdz. 7.6) |
| `alert.smtp.host` | **wymagany przy `alert.enabled=true`** | serwer SMTP (laboratorium: przekaźnik na hoście, `192.168.56.1`) |
| `alert.smtp.port` | `25` | |
| `alert.smtp.starttls` | `false` | `true` = wymagaj STARTTLS |
| `alert.smtp.user`, `alert.smtp.password` | puste | logowanie do serwera SMTP; puste = bez logowania |
| `alert.from` | **wymagany przy `alert.enabled=true`** | nadawca |
| `alert.to` | **wymagany przy `alert.enabled=true`** | odbiorcy po przecinku |
| `alert.max_per_hour` | `60` | limit maili na godzinę |

`scripts/install-server-service.sh` przepisuje `collector.properties` przy każdej instalacji, ale zachowuje linie `alert.*`. Gdy istnieje `server/alert.properties` (poza gitem; wzór: `server/alert.properties.example`), instalator wpisuje je do `collector.properties`.
`scripts/install-all.sh` robi całą instalację jedną komendą (pakiety, jar, certyfikaty, serwer, wabik, agent); powtórzone uruchomienie aktualizuje bez ruszania certyfikatów, `alert.*` i wabika.


*`server/src/main/java/pl/honeypot/server/ServerConfig.java`, linie 27–61*

```java
    public static ServerConfig load(Path file) throws IOException {
        Properties p = new Properties();
        try (Reader r = Files.newBufferedReader(file)) {
            p.load(r);
        }

        String keystore = p.getProperty("server.keystore");
        if (keystore == null || keystore.isBlank()) {
            throw new IOException("server.keystore is required (PKCS12 with the TLS cert/key); "
                    + "run scripts/gen-certs.sh to create one");
        }

        String password = p.getProperty("server.keystore.password", "");
        if (password.isEmpty()) {
            throw new IOException("server.keystore.password must not be empty");
        }
        if (!Files.isRegularFile(Path.of(keystore))) {
            throw new IOException("keystore file not found: " + keystore);
        }

        String accs = p.getProperty("detection.confirm.accounts", "backup_srv");
        Set<String> confirmAccounts = Arrays.stream(accs.split(","))
                .map(String::trim).filter(x -> !x.isEmpty()).collect(Collectors.toSet());
        String marker = p.getProperty("detection.breadcrumb.marker", "kopia_zapasowa.sh").trim();

        return new ServerConfig(
                p.getProperty("server.bind", "127.0.0.1"),
                Integer.parseInt(p.getProperty("server.port", "8443")),
                Path.of(p.getProperty("data.dir", "data")),
                Path.of(keystore),
                p.getProperty("server.keystore.password", ""),
                Path.of(p.getProperty("dashboard.dir", "../dashboard")),
                confirmAccounts,
                marker);
    }
```

### 6.2 Start i HTTPS (`Main`)

Serwer składa się z jednego `Javalin` z własnym konektorem Jetty: wyłącznie TLS 1.2 i 1.3 (`SslConnectionFactory`), keystore PKCS12, nasłuch na `bindAddress:port`.
Limit żądania to 64 MB (domyślny 1 MB odrzucałby diffy, a agent ponawiałby taki raport w nieskończoność). Jackson ma podniesiony limit długości pojedynczego stringa do 64 MB
(domyślnie 20 MB), bo raport z diffem binarnym w base64 bywa większy. Pusty `dashboard.dir` oznacza „nie serwuj" (`Path.of("")` byłby katalogiem roboczym i wystawiłby go).


*`server/src/main/java/pl/honeypot/server/Main.java`, linie 42–60*

```java
        Javalin app = Javalin.create(c -> {
            c.showJavalinBanner = false;
            c.jsonMapper(new JavalinJackson(mapper, false));
            // Agent reports can carry file diffs; the 1 MB default would reject them
            // with a 4xx and the agent would retry the same report forever.
            c.http.maxRequestSize = 64L * 1024 * 1024;
            c.jetty.addConnector((server, httpConfig) -> {
                SslContextFactory.Server ssl = new SslContextFactory.Server();
                ssl.setKeyStorePath(cfg.keystore().toAbsolutePath().toString());
                ssl.setKeyStorePassword(cfg.keystorePassword());
                ssl.setKeyStoreType("PKCS12");
                ssl.setIncludeProtocols("TLSv1.2", "TLSv1.3");
                ServerConnector connector = new ServerConnector(server,
                        new SslConnectionFactory(ssl, "http/1.1"),
                        new HttpConnectionFactory(httpConfig));
                connector.setHost(cfg.bindAddress());
                connector.setPort(cfg.port());
                return connector;
            });
```

Trasy:


*`server/src/main/java/pl/honeypot/server/Main.java`, linie 72–80*

```java
        ReportHandler ingest = new ReportHandler(reports, cfg.port());
        app.post("/events", ingest);
        app.post("/api/events", ingest);

        // Server -> operator (read-only views for the dashboard).
        app.get("/api/agents", new AgentsHandler(reports));
        app.get("/api/events", new EventsQueryHandler(reports));
        app.get("/api/stats", new StatsHandler(reports));
        app.get("/api/attackers", new AttackersHandler(reports));
```

### 6.3 Przyjmowanie raportu (`ReportHandler`)

Walidacja koperty: obiekt JSON, `schema_version == 1`, `report_id` = 64 znaki `[0-9a-f]`, `agent_id` = `[A-Za-z0-9._-]{1,64}`, `source` ze zbioru
{`share`, `log`, `network`, `system`, `monitor`, `source`}, `operation` = `[a-z0-9_]{1,64}`, `analysis.classification` = `[A-Za-z0-9_.-]{1,64}`.
Reszta pól jest zapisywana **bez interpretacji**. Błędny JSON daje 400, a inny wyjątek (np. 413 dla zbyt dużego ciała) zachowuje swój status.


*`server/src/main/java/pl/honeypot/server/api/ReportHandler.java`, linie 37–86*

```java
    public void handle(Context ctx) {
        JsonNode body = read(ctx);

        if (!body.isObject()) {
            throw new BadRequestResponse("body must be a JSON object");
        }
        JsonNode schema = body.get("schema_version");
        if (schema == null || !schema.isInt() || schema.asInt() != 1) {
            throw new BadRequestResponse("schema_version must be 1");
        }
        String reportId = str(body, "report_id");
        if (reportId == null || !REPORT_ID.matcher(reportId).matches()) {
            throw new BadRequestResponse("report_id must be 64 lowercase hex chars");
        }
        String agentId = str(body, "agent_id");
        if (agentId == null || !AGENT_ID.matcher(agentId).matches()) {
            throw new BadRequestResponse("agent_id must be 1-64 chars of [A-Za-z0-9._-]");
        }
        String source = str(body, "source");
        if (source != null && !SOURCES.contains(source)) {
            throw new BadRequestResponse("unknown source");
        }
        String operation = str(body, "operation");
        if (operation != null && !OPERATION.matcher(operation).matches()) {
            throw new BadRequestResponse("invalid operation");
        }
        JsonNode analysis = body.get("analysis");
        String classification = analysis != null ? str(analysis, "classification") : null;
        if (classification != null && !CLASSIFICATION.matcher(classification).matches()) {
            throw new BadRequestResponse("invalid classification");
        }

        // Agent and server share a host: the agent sees its own upload connection
        // to our loopback listener and would report it, which uploads another
        // connection, and so on. Acknowledge (so the agent drops it) but don't store.
        if (isOwnUpload(body)) {
            ctx.status(HttpStatus.OK).json(Map.of("report_id", reportId, "ignored", true));
            return;
        }

        ReportStore.InsertResult r = reports.insert(body);
        if (r.rejected()) {
            throw new BadRequestResponse("too many distinct agents");
        }
        if (r.duplicate()) {
            ctx.status(HttpStatus.OK).json(Map.of("report_id", reportId, "duplicate", true));
        } else {
            ctx.status(HttpStatus.CREATED).json(Map.of("event_id", r.eventId(), "report_id", reportId));
        }
    }
```

### 6.4 Filtr własnego uploadu

Agent i kolektor działają na jednej maszynie, więc agent widzi własne połączenie do `127.0.0.1:8443` i zaraportowałby je, co wygenerowałoby kolejne połączenie
i tak w kółko. Kolektor rozpoznaje taki raport (operacja `tcp_connection_observed`, `local_port` równy portowi serwera, oba końce na loopbacku), odpowiada
`200 {"ignored":true}` (żeby agent skasował raport) i niczego nie zapisuje.


*`server/src/main/java/pl/honeypot/server/api/ReportHandler.java`, linie 88–98*

```java
    private boolean isOwnUpload(JsonNode body) {
        if (!"tcp_connection_observed".equals(str(body, "operation"))) {
            return false;
        }
        JsonNode c = body.get("connection");
        if (c == null || !c.path("local_port").canConvertToInt() || c.path("local_port").asInt() != serverPort) {
            return false;
        }
        JsonNode peer = c.get("peer");
        return isLoopback(c.path("local_ip").asText("")) && peer != null && isLoopback(peer.path("ip").asText(""));
    }
```

### 6.5 Trwały dziennik (`JsonlLog`)

`events.jsonl` to **append-only JSON Lines**: jedna linia na raport, UTF-8, tryb 0600 (zawiera treść plików i logów). Do każdego raportu dopisywane są `event_id`
(licznik rosnący, inicjowany przy starcie największą wartością z pliku) i `received_at` (czas serwera, UTC, sekundy).
Zapis jest serializowany blokadą, a odpowiedź 2xx idzie dopiero po `FileChannel.force`. Gdy zapis się nie powiedzie, niedokończona linia jest obcinana (`truncate(before)`),
żeby ponowna wysyłka nie skleiła się z fragmentem.


*`server/src/main/java/pl/honeypot/server/store/JsonlLog.java`, linie 83–124*

```java
    public ObjectNode append(Object record) {
        long id = seq.incrementAndGet();
        ObjectNode node = mapper.valueToTree(record);
        node.put(idField, id);
        node.put("received_at", DateTimeFormatter.ISO_INSTANT
                .format(Instant.now().truncatedTo(ChronoUnit.SECONDS)));

        String line;
        try {
            line = mapper.writeValueAsString(node);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        ByteBuffer bytes = ByteBuffer.wrap((line + "\n").getBytes(StandardCharsets.UTF_8));
        synchronized (lock) {
            // Owner-only: reports contain file contents and log excerpts.
            try (FileChannel ch = FileChannel.open(file,
                    Set.of(StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE),
                    PosixFilePermissions.asFileAttribute(
                            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)))) {
                long before = ch.size();
                try {
                    while (bytes.hasRemaining()) {
                        ch.write(bytes);
                    }
                    ch.force(false);   // 2xx is only sent after the line is on disk
                } catch (IOException e) {
                    // Cut off a partial line, otherwise the retry is glued to it.
                    try {
                        ch.truncate(before);
                    } catch (IOException t) {
                        e.addSuppressed(t);
                    }
                    throw e;
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return node;
    }
```

Po awarii (np. utrata zasilania) ostatnia linia może być urwana. Przy starcie `repairTail` odcina fragment po ostatnim `\n`, bo inaczej następny rekord skleiłby się z nim i oba byłyby nieczytelne.


*`server/src/main/java/pl/honeypot/server/store/JsonlLog.java`, linie 59–79*

```java
    private static void repairTail(Path file) throws IOException {
        if (!Files.exists(file) || Files.size(file) == 0) {
            return;
        }
        try (RandomAccessFile f = new RandomAccessFile(file.toFile(), "rw")) {
            long len = f.length();
            f.seek(len - 1);
            if (f.read() == '\n') {
                return;
            }
            long pos = len - 1;
            while (pos > 0) {
                f.seek(pos - 1);
                if (f.read() == '\n') {
                    break;
                }
                pos--;
            }
            f.setLength(pos);
        }
    }
```

Odczyt `GET /api/events` idzie **od końca pliku** porcjami po 64 KiB (`readNewestFirst`) i zatrzymuje się po `limit` pasujących raportach, więc koszt zapytania
nie zależy od rozmiaru pliku. Uszkodzone linie są pomijane.

### 6.6 Stan w pamięci (`ReportStore`)

Kolektor trzyma w pamięci: zbiór widzianych `report_id` (dedup), stan agentów, liczniki `by_source` / `by_operation` / `by_classification` i tablicę atakujących.
Wszystko jest **odbudowywane z `events.jsonl` przy starcie** (`rebuild`), więc restart nie gubi stanu (cena: pełne przeczytanie pliku przy starcie).

#### Deduplikacja i kolejność zapisu


*`server/src/main/java/pl/honeypot/server/store/ReportStore.java`, linie 154–173*

```java
    public InsertResult insert(JsonNode report) {
        String reportId = text(report, "report_id");
        synchronized (lock) {
            if (reportId != null && seen.contains(reportId)) {
                return new InsertResult(-1, true, false);
            }
            String agentId = text(report, "agent_id");
            if (agentId != null && !agents.containsKey(agentId) && agents.size() >= MAX_AGENTS) {
                return new InsertResult(-1, false, true);
            }
            // Write first: if the append fails nothing is remembered, so the
            // agent's retry is stored instead of being answered as a duplicate.
            var stamped = log.append(report);
            if (reportId != null) {
                seen.add(reportId);
            }
            index(stamped);   // liveness uses the server's received_at, not the agent's
            return new InsertResult(stamped.get("event_id").asLong(), false, false);
        }
    }
```

Kolejność jest istotna: najpierw `log.append`, dopiero potem `seen.add(reportId)`. Gdy zapis na dysk się nie powiedzie, `report_id` nie jest zapamiętany, więc ponowna
wysyłka zostanie zapisana, a nie uznana za duplikat. Limit **1000 różnych `agent_id`** (`MAX_AGENTS`) chroni pamięć przed zalewem wymyślonych identyfikatorów (odpowiedź 400).

#### Indeksowanie raportu

`index` aktualizuje liczniki, stan agenta (czas pierwszego i ostatniego raportu liczony z **`received_at`**, czyli z zegara serwera, nie agenta) i tablicę atakujących.
Liczba różnych kluczy w licznikach `by_operation` i `by_classification` jest ograniczona do 200 (`MAX_KEYS`); nadmiar liczy się pod kluczem `other`.


*`server/src/main/java/pl/honeypot/server/store/ReportStore.java`, linie 176–243*

```java
    private void index(JsonNode n) {
        totalEvents++;
        bump(bySource, text(n, "source"));
        bump(byOperation, capKey(byOperation, text(n, "operation")));
        JsonNode analysis = n.get("analysis");
        String classification = analysis != null ? text(analysis, "classification") : null;
        bump(byClassification, capKey(byClassification, classification));

        Instant parsed = parse(text(n, "received_at"));
        final Instant at = parsed != null ? parsed : Instant.now();
        String operation = text(n, "operation");

        // Attacker from an observed inbound TCP connection (peer = the remote client).
        JsonNode conn = n.get("connection");
        if (conn != null) {
            JsonNode peer = conn.get("peer");
            if (peer != null) {
                JsonNode lp = conn.get("local_port");
                Integer port = lp != null && lp.canConvertToInt() ? lp.asInt() : null;
                recordAttacker(text(peer, "ip"), text(peer, "mac"), at, false, port, operation);
            }
        }
        // Attacker from a failed login (SSH and SMB both land here as authentication_failure).
        // Only the first address counts: the agent puts the real client ("remote host [..]" in Samba,
        // "from IP" in sshd) first, while later ones are this server ("local host [..]") or made-up
        // addresses the attacker typed into the user name.
        if ("authentication_failure".equals(classification)) {
            String ip = firstEndpoint(n);
            if (ip != null) {
                recordAttacker(ip, null, at, true, null, operation);
            }
        }

        // Confirmed login / breadcrumb read parsed from raw log content.
        String content = text(n, "content");
        if (content != null) {
            var m = SSH_ACCEPTED.matcher(content);
            while (m.find()) {
                if (confirmAccounts.contains(m.group(1))) {
                    markAttacker(m.group(2), at, true, false);
                }
            }
            if (!breadcrumbMarker.isEmpty() && content.contains(breadcrumbMarker)) {
                markAttacker(firstEndpoint(n), at, false, true);
            }
        }

        String agentId = text(n, "agent_id");
        if (agentId == null) {
            return;
        }
        AgentState a = agents.computeIfAbsent(agentId, k -> {
            AgentState s = new AgentState();
            s.agentId = k;
            s.firstSeen = at;
            return s;
        });
        if (a.firstSeen == null || at.isBefore(a.firstSeen)) {
            a.firstSeen = at;
        }
        if (a.lastSeen == null || !at.isBefore(a.lastSeen)) {
            a.lastSeen = at;
            a.lastSource = text(n, "source");
            a.lastOperation = operation;
            a.lastClassification = classification;
        }
        a.totalReports++;
    }
```

### 6.7 API odczytu

Wszystkie endpointy `GET /api/*` są tylko do odczytu i **bez uwierzytelniania**; ochroną jest nasłuch na `127.0.0.1`.

| Endpoint | Zwraca |
|---|---|
| `GET /api/agents` | lista agentów: `agent_id`, `status` (`online` gdy ostatni raport nie starszy niż 90 s), `first_seen`, `last_seen`, `total_reports`, `last_source`, `last_operation`, `last_classification` |
| `GET /api/events?agent_id=&source=&limit=` | pełne raporty z `event_id` i `received_at`, od najnowszych; `limit` domyślnie 100, maks. 1000 (większy jest obcinany), `limit < 1` lub nie liczba daje 400 |
| `GET /api/stats` | `total_events`, `total_agents`, `online_agents`, `by_source`, `by_classification`, `by_operation`, `by_event_type`, `by_event_kind` (klucz `typ/serwis`, np. `auth.failure/ssh`, albo sam typ, gdy zdarzenie nie ma serwisu), `unknown_event_types` |
| `GET /api/attackers` | wykryci atakujący (rozdz. 7) |
| `GET /api/version` | `server_version`, obsługiwane `schema_versions` |

`agents()` i `stats()` nie biorą blokady (współbieżna mapa i pola `volatile`), więc nie czekają na `fsync` zapisu.


*`server/src/main/java/pl/honeypot/server/store/ReportStore.java`, linie 389–408*

```java
    public List<AgentView> agents() {
        Instant now = Instant.now();
        List<AgentView> out = new ArrayList<>();
        for (AgentState a : agents.values()) {
            Instant lastSeen = a.lastSeen;
            boolean online = lastSeen != null
                    && Duration.between(lastSeen, now).compareTo(ONLINE_AFTER) <= 0;
            out.add(new AgentView(
                    a.agentId,
                    online ? "online" : "offline",
                    iso(lastSeen),
                    iso(a.firstSeen),
                    a.totalReports,
                    a.lastSource,
                    a.lastOperation,
                    a.lastClassification));
        }
        out.sort((x, y) -> x.agentId().compareTo(y.agentId()));
        return out;
    }
```

### 6.8 TLS i certyfikaty (`server/scripts/gen-certs.sh`)

Agent weryfikuje łańcuch TLS **i** nazwę hosta z SAN certyfikatu, bez możliwości wyłączenia. Skrypt generuje lokalne CA (`ca.crt`), certyfikat serwera z SAN podanym w argumentach
(domyślnie `IP:127.0.0.1`) i keystore PKCS12 (`server-keystore.p12`). Ważność domyślnie 3650 dni (`CERT_DAYS`): po wygaśnięciu agent cicho przestałby raportować,
więc nie stosujemy krótkich terminów. Po wygenerowaniu **`ca.key` jest usuwany** (`KEEP_CA_KEY=yes` go zachowuje), bo CA jest zaufane w całym systemie i jej klucz pozwalałby
wystawić certyfikat na dowolną nazwę.


*`server/scripts/gen-certs.sh`, linie 49–69*

```bash
echo ">> CA"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$DAYS" \
  -subj "/CN=Fleet Monitoring CA" \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

echo ">> server key + CSR"
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=monitoring receiver" \
  -keyout "$OUT/server.key" -out "$OUT/server.csr" 2>/dev/null

echo ">> server cert (SAN: $SAN)"
EXT="$OUT/server.ext"
cat > "$EXT" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF
openssl x509 -req -in "$OUT/server.csr" \
```

Instalator agenta kopiuje `ca.crt` do `/etc/pki/ca-trust/source/anchors/sysmon-ca.crt` i wywołuje `update-ca-trust`.

---

## 7. Wykrywanie atakujących

Logika jest w `ReportStore` i wystawiona przez `GET /api/attackers`. Założenie: na tej maszynie nikt uprawniony nie ma konta ani powodu do kontaktu,
więc **każde zdalne IP** widziane w połączeniach lub nieudanych logowaniach jest wrogie; progi służą do stopniowania. Ruch z `127.0.0.0/8` i `::1` jest pomijany
(agent, tunel dashboardu, własne dostawy). Szczegóły i uzasadnienia: `server/docs/attacker-detection.md`.

### 7.1 Źródła adresów

| Źródło w raporcie | Pole | Liczone jako |
|---|---|---|
| `tcp_connection_observed` | `connection.peer.ip`, `.mac`, `connection.local_port` | połączenie (i port lokalny do wykrywania skanów) |
| `classification: authentication_failure` | `network_context.endpoints[0].ip` | nieudane logowanie |
| treść logu (`content`) | regex `Accepted (password\|publickey) for <konto> from <IPv4>` | udane logowanie SSH; jeśli konto jest w `detection.confirm.accounts` → `confirmed` |
| treść logu zawierająca `detection.breadcrumb.marker` | IP z `endpoints[0]` | flaga `breadcrumb_read` |
| `event.type: auth.denied` | `event.src.ip` | nieudane logowanie (jak `authentication_failure`) |
| `event.type: net.scan` | `event.src.ip` | flaga `scanned` (skan wykryty przez agenta) |
| `event.type: net.probe` | `event.src.ip` | flaga `probed` (nie jest nieudanym logowaniem ani połączeniem) |
| `event.type: auth.invalid_user` | `event.src.ip` | licznik `invalid_users` (nie jest nieudanym logowaniem) |
| `auth.failure`, `auth.invalid_user`, `auth.attempt` z `event.user.name` z `detection.confirm.accounts` | `event.src.ip` | flaga `decoy_attempt` |

Raporty v2 biorą adres z `event.src.ip`; `network_context.endpoints[0]` jest zapasem dla raportów v1.

### 7.2 Dlaczego tylko pierwszy adres

W linii Samby adres klienta jest w `remote host [...]`, ale linia zawiera też adres serwera (`local host [...]`) oraz nazwę użytkownika wpisaną przez atakującego,
która może udawać adres. Agent wstawia prawdziwego klienta jako pierwszy (rozdz. 4.8), a serwer liczy tylko `endpoints[0]`. Liczenie wszystkich zrobiłoby
„atakującego" z samego honeypota i z niewinnych adresów. Tabela jest ograniczona do 10 000 adresów (`MAX_ATTACKERS`).

### 7.3 Poziomy zagrożenia

Dla każdego IP trzymane są liczniki łączne oraz okna przesuwne (znaczniki czasu przycinane przy każdym dopisaniu). Poziom wylicza się przy odczycie względem „teraz":


*`server/src/main/java/pl/honeypot/server/store/ReportStore.java`, linie 32–35*

```java
    private static final Duration FAIL_WINDOW = Duration.ofMinutes(10);
    private static final int FAIL_THRESHOLD = 5;            // brute force
    private static final Duration ENUM_WINDOW = Duration.ofSeconds(60);
    private static final int PORT_SCAN_THRESHOLD = 3;       // distinct local ports from one IP = scan
```

*`server/src/main/java/pl/honeypot/server/store/ReportStore.java`, `threatOf`*

```java
        return s.confirmed ? "confirmed"
                : (s.decoyAttempt || s.breadcrumbRead) ? "bait"
                : fails >= FAIL_THRESHOLD ? "brute_force"
                : (distinctPorts(s, now) >= PORT_SCAN_THRESHOLD || s.scanned) ? "fast_enum"
                : (s.authFailures > 0 || s.probed || s.invalidUsers > 0) ? "suspicious"
                : "contact";
```

| Poziom | Dashboard | Warunek | Znaczenie | Mail |
|---|---|---|---|---|
| `confirmed` | POTWIERDZONY | udane logowanie na konto z `detection.confirm.accounts` | pewny atak: hasło tego konta nie jest do zgadnięcia, leży tylko w okruszku | tak |
| `bait` | PRZYNĘTA | próba logowania na konto-przynętę (także z błędnym hasłem) albo odczyt okruszka | atakujący przeszukał udziały i znalazł przynętę | tak |
| `brute_force` | BRUTE FORCE | ≥ 5 nieudanych logowań (w tym `auth.denied`) z jednego IP w 10 min | zgadywanie haseł | tak |
| `fast_enum` | SKANER | ≥ 3 różne porty lokalne z jednego IP w 60 s albo `net.scan` od agenta | skan portów (zwykły klient Windows dotyka tylko 445/139) | tak |
| `suspicious` | PODEJRZANY | ≥ 1 nieudane logowanie, sonda usługi (`net.probe`) albo nieistniejące konto | warte uwagi | nie |
| `contact` | kontakt | samo połączenie | szum lub wczesny kontakt | nie |

Lista jest sortowana malejąco po poziomie, przy remisie po `last_seen`. Okna liczone są względem chwili zapytania, więc stary atak sprzed godziny ma `failures_10m = 0`
i spada do `suspicious`/`contact`, mimo że `auth_failures` (licznik łączny) pozostaje wysoki.

### 7.4 Odpowiedź

```json
[
  { "ip": "10.13.37.66", "mac": "00:0c:29:ab:cd:ef", "threat": "brute_force",
    "first_seen": "2026-11-11T12:51:25Z", "last_seen": "2026-11-11T12:51:25Z",
    "connections": 0, "auth_failures": 5, "events": 5,
    "failures_10m": 5, "events_1m": 5, "distinct_ports": 1,
    "confirmed": false, "breadcrumb_read": false, "last_operation": "append",
    "probed": false, "invalid_users": 0, "decoy_attempt": false }
]
```

### 7.5 Ograniczenia detekcji

- `breadcrumb_read` działa tylko przy włączonym `full_audit` w Sambie (agent nie widzi odczytów plików).
- Zdarzenia `share` (zapis pliku) nie niosą adresu klienta, więc aktywności na plikach nie da się przypisać do IP w tej tabeli. Powiązanie jest tylko w `evidence[]` raportu zmiany pliku.
- Sonda SSH zapisana jako `kex_exchange_identification:` (Alma 10) nie ma adresu w tej samej linii, więc nie trafia do tabeli atakujących.
- Korelacja „odczyt okruszka → logowanie `backup_srv`" nie jest łączona w jedną historię: oba sygnały są niezależnymi flagami (`breadcrumb_read`, `confirmed`).

### 7.6 Alarmy e-mail

Pakiet `pl.honeypot.server.alert`; włączane kluczem `alert.enabled=true` (rozdz. 6.1). Konfiguracja krok po kroku: `docs/WDROZENIE-OD-ZERA.md`, rozdz. 10a.

- **Kiedy.** Mail zbiorczy co `3600 / alert.max_per_hour` sekund (domyślnie co 60 s), tylko jeśli w tym czasie coś się wydarzyło.
  `ReportStore` po każdym przyjętym raporcie liczy poziom adresów, których raport dotyczył, i dla każdego adresu na poziomie z `ALERT_LEVELS`
  (`fast_enum`, `brute_force`, `bait`, `confirmed`) woła `AlertSink.activity(AlertNotice)`. Adresy `suspicious` i `contact` nie trafiają do maili.
  `AlertNotice.newLevel` oznacza pierwsze wejście adresu na dany poziom (w mailu: „NOWY POZIOM"). Atak trwający dalej trafia do kolejnych maili.
- **Start.** Raporty wczytywane z `events.jsonl` nie trafiają do maili; ustawiają tylko poziom „widziany", więc po restarcie trwający atak
  nie jest drugi raz oznaczany jako „NOWY POZIOM".
- **Wysyłka.** `AlertService`: bufor per IP (maks. 1000 adresów, nadmiar liczony jako „pominięto N") i zegar w wątku `alert-mailer`;
  `activity` tylko dopisuje do bufora w pamięci. Błąd SMTP: wpis `alert: mail not sent ...` w logu usługi, a zawartość bufora idzie
  w następnym mailu (z czasem od początku niewysłanego okresu).
- **Treść.** Temat `[honeypot <agent_id>] <N> atakujących, <M> zdarzeń (<od>–<do>)`; dla każdego adresu (najgroźniejsze pierwsze): poziom,
  „NOWY POZIOM", powód, zdarzenia z okresu zliczone po typie i serwisie z maks. 5 nazwami kont (np. `12× SMB · nieudane logowanie   konta: administrator`),
  liczniki łączne z `/api/attackers`. Bez haseł (`event.credential`) i bez surowej treści logów.
- **SMTP.** `SmtpMailer` (Jakarta Mail, implementacja Eclipse Angus), limity czasu 10 s; STARTTLS i logowanie tylko gdy ustawione.
- **Test.** `java -jar collector.jar --test-alert <plik.properties>` wysyła jeden mail „[honeypot] test alarmu" na podstawie samych kluczy `alert.*`
  (bez keystore); kod wyjścia 0 = wysłano.

---

## 8. Dashboard

Statyczna strona (`dashboard/index.html`, `app.js`, `style.css`, motyw ciemny) serwowana przez kolektor z tego samego origin, więc bez CORS. Dostęp tylko przez tunel SSH:
`ssh -L 8443:127.0.0.1:8443 <użytkownik>@<host>` i `https://127.0.0.1:8443/` (przeglądarka ostrzeże o własnym CA).

### 8.1 Odświeżanie

Co 4 s (przełącznik „odświeżaj co 4 s") `refresh()` pobiera równolegle `/api/stats`, `/api/agents` i `/api/events`. Żądania nie nakładają się (flaga `busy`, timeout 3 s),
a powolny serwer nie powoduje kolejki zapytań. Przy filtrowaniu po stronie przeglądarki pobiera się do 5 razy więcej zdarzeń (maks. 1000), żeby po odfiltrowaniu została pełna lista.


*`dashboard/app.js`, linie 282–329*

```javascript
async function refresh() {
  if (busy) { pending = true; return; }   // a slow server must not pile up requests
  busy = true;
  const source = el("filter-source").value;
  const agent = el("filter-agent").value;
  const limit = Number(el("filter-limit").value) || 100;
  const hideUnknown = el("hide-unknown").checked;
  const hideHeartbeat = el("hide-heartbeat").checked;
  const text = el("filter-text").value.trim().toLowerCase();
  const filtering = hideUnknown || hideHeartbeat || text;
  // Przy filtrowaniu pobieramy więcej, żeby po odfiltrowaniu została pełna lista.
  const fetchLimit = filtering ? Math.min(limit * 5, 1000) : limit;
  const query = new URLSearchParams();
  if (source) query.set("source", source);
  if (agent) query.set("agent_id", agent);
  query.set("limit", fetchLimit);

  try {
    const [stats, agents, events] = await Promise.all([
      api("/api/stats"),
      api("/api/agents"),
      api("/api/events?" + query.toString()),
    ]);
    if (!Array.isArray(agents) || !Array.isArray(events)) throw new Error("niepoprawna odpowiedź serwera");
    renderStats(stats);
    renderAgents(agents);
    let shown = events;
    if (filtering) {
      shown = events.filter((r) => {
        if (r.error || r.complete === false) return true;   // luki w obserwacji zawsze widoczne
        const c = r.analysis && r.analysis.classification;
        if (hideHeartbeat && c === "heartbeat") return false;
        if (hideUnknown && (!c || c === "unknown")) return false;
        return !text || haystack(r).includes(text);
      }).slice(0, limit);
    }
    renderEvents(shown, events);
    setConn(true);
    lastOk = new Date().toLocaleTimeString("pl-PL", { hour12: false });
    el("updated").textContent = "zaktualizowano " + lastOk;
  } catch (e) {
    setConn(false);
    el("updated").textContent = (lastOk ? "ostatnie dane z " + lastOk + ", " : "") + String(e.message || e);
  } finally {
    busy = false;
    if (pending) { pending = false; refresh(); }
  }
}
```

### 8.2 Widoki

- **Pasek stanu:** liczba agentów online/wszystkich, liczba zdarzeń, liczba źródeł, sześć najczęstszych rodzajów zdarzeń z `by_event_kind`
  (np. „SSH · nieudane logowanie", bez heartbeat); starszy serwer bez tego pola: sześć najczęstszych klasyfikacji.
- **Agenci:** tabela stanu (`● online` / `○ offline`), czas ostatniego raportu, liczba raportów, ostatnia operacja.
- **Atakujący:** dane z `/api/attackers`: adres IP, ocena jako znaczek (POTWIERDZONY, PRZYNĘTA, BRUTE FORCE: czerwone; SKANER, PODEJRZANY: żółte),
  nieudane logowania (łącznie i w 10 min), sygnały (skan, sonda usługi, nieistniejące konta, próba na konto-przynętę, odczyt przynęty), pierwsze
  i ostatnie wystąpienie; obok niższej niż brute force oceny (albo po wygaśnięciu okna 10 min) stoi dodatkowy znaczek BRUTE FORCE z czasem `last_brute_force`. Adresy z samym połączeniem są tylko zliczone. Kliknięcie IP wpisuje go do wyszukiwarki dziennika.
- **Dziennik zdarzeń:** tabela z filtrami (źródło, agent, limit, szukanie tekstu, „ukryj szum (unknown)" domyślnie włączone, „ukryj heartbeat"), grupowana po dniach.
  Powtórzone identyczne nieudane logowania (ten sam typ, serwis, IP, login i hasło, przerwa do 10 min) składają się w jeden wiersz z licznikiem; linie Samby bez adresu grupują się po pliku logu klienta. Log trzyma każdy raport, grupuje tylko widok.
  Wiersze z błędem lub `complete=false` są widoczne zawsze, nawet przy filtrach (luki w obserwacji nie mogą zniknąć).
- **Szuflada szczegółów:** kliknięcie wiersza otwiera pełny surowy JSON raportu z kolorowaniem składni i przyciskiem „kopiuj".
- **Kolumna „klasyfikacja"** pokazuje etykietę z `event.type` i `event.service` (np. „SMB · odmowa dostępu", „SSH · sonda usługi (np. nmap -sV)");
  raporty v1 bez bloku `event` pokazują `analysis.classification`. W szczegółach jest `konto @ IP:port` i znaczek oceny atakującego przy IP.

### 8.3 Kolorowanie


*`dashboard/app.js`, linie 63–70*

```javascript
function classTone(c) {
  const danger = ["authentication_failure", "file_change", "rename", "delete",
    "delete_during_downtime", "downtime_change"];
  const warn = ["tcp_connection", "samba_audit", "observation_gap", "authentication_success"];
  if (danger.includes(c)) return "danger";
  if (warn.includes(c)) return "warn";
  return "info";
}
```

Raporty z blokiem `event` są kolorowane według `event.type` (`eventTone` w `app.js`): czerwone `auth.failure`, `auth.attempt`, `auth.denied`,
`net.scan`, `net.probe`, `file.change`; żółte `auth.success`, `auth.invalid_user`, `net.connection`, `samba.audit` i zdarzenia systemowe o lukach.
Funkcja `classTone` poniżej obsługuje raporty v1. Kolor zależy wtedy od **klasyfikacji**. Luki obserwacji (`observation_gap`) są *operacją*, a ich klasyfikacja to `unknown`, więc same nie są podświetlone jako ostrzeżenie
(widać je dzięki regule „wiersze z błędem zawsze widoczne").

### 8.4 Bezpieczeństwo dashboardu

Treści pochodzące od atakującego (nazwy plików, linie logów, adresy) trafiają na stronę wyłącznie przez `esc()`; kolorowanie JSON również escapuje każdy fragment,
więc raport nie może wstrzyknąć HTML. Raporty większe niż 200 000 znaków są pokazywane jako zwykły tekst (`HIGHLIGHT_MAX`).


*`dashboard/app.js`, linie 19–23*

```javascript
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
```

*`dashboard/app.js`, linie 229–245*

```javascript
function highlightJson(text) {
  if (text.length > HIGHLIGHT_MAX) return esc(text);
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  let out = "";
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    out += esc(text.slice(last, m.index));
    if (m[1]) {
      out += `<span class="${m[2] ? "j-k" : "j-s"}">${esc(m[1])}</span>${esc(m[2] || "")}`;
    } else {
      out += `<span class="${m[3] ? "j-b" : "j-n"}">${esc(m[0])}</span>`;
    }
    last = re.lastIndex;
  }
  return out + esc(text.slice(last));
}
```


---

## 9. Wabik: persona, Samba, SSH

Obowiązuje wariant „Dział Finansów" (`samba_structure/`). Konfigurację wartości trzyma `honeypot.conf` (poza repozytorium, bo zawiera hasła), a w repo jest tylko
`honeypot.conf.example`. Skrypt `setup-honeypot.sh` uruchamia się jako root na AlmaLinux 9 i jest idempotentny w zakresie kont i plików. Decyzje projektowe
opisuje `samba_structure/ustalenia-konfiguracja.md`.

### 9.1 Tożsamość i konta

| Element | Wartość |
|---|---|
| Hostname | `fs-finanse` (`HP_HOSTNAME`), strefa `Europe/Warsaw`, locale `pl_PL.UTF-8` |
| `svc-admin` | **prawdziwy administrator**: tylko klucz SSH (`Match User`, `AuthenticationMethods publickey`), `wheel`; nigdy nie generuje nieudanych logowań |
| `backup_srv` | konto SSH z powłoką, **przynęta**; jego hasło leży w okruszku w udziale `Archiwum$` |
| `a.kowalska`, `m.nowak`, `k.wisniewska`, `p.zielinski`, `administrator` | konta tylko-Samba (`/sbin/nologin`), członkowie grupy `finanse`; każde udane logowanie to atakujący |

Skrypt waliduje wymagane pola (`HP_SHELL_DECOY_PASS`, `HP_ADMIN_PUBKEY`, hasła każdego konta Samby) i przerywa, jeśli któreś jest puste.

### 9.2 Udziały Samby i `full_audit`

Wszystkie udziały mają `vfs objects = full_audit`, więc odczyty, zapisy, tworzenie, usuwanie i zmiany nazw trafiają do sysloga (`facility local5`), a rsyslog kieruje je do
`/var/log/samba/audit.log`, który agent czyta (rozdz. 4.4). Prefiks `%u|%I|%m|%S` daje w każdej linii: użytkownika, **adres IP klienta**, nazwę maszyny klienta i nazwę udziału.
Dzięki temu `network_context` raportu zawiera IP, a odczyt okruszka jest widoczny.


*`samba_structure/setup-honeypot.sh`, linie 130–135*

```bash
AUDIT_VFS='vfs objects = full_audit
   full_audit:prefix = %u|%I|%m|%S
   full_audit:success = connect disconnect fdopendir mkdirat unlinkat open openat read pread write pwrite renameat
   full_audit:failure = connect
   full_audit:facility = local5
   full_audit:priority = notice'
```

| Udział | Dostęp | Uwagi |
|---|---|---|
| `Wspolny` | gość, tylko odczyt | niegroźne pliki i subtelna wskazówka o ukrytym `Archiwum` |
| `Finanse` | `@finanse`, zapis | faktury, rozliczenia VAT, zestawienia, budżet, umowy (lata 2022–2024, daty `touch -d` rozłożone w czasie) |
| `Archiwum$` | `@finanse`, odczyt, `browseable = no` | ukryty; zawiera okruszek `IT/kopia_zapasowa.sh` |
| `Zarzad` | `@zarzad` (nikt), odczyt | widoczny, ale odmawia dostępu |

Globalnie: `map to guest = Never` (zły login daje `NT_STATUS_LOGON_FAILURE`, a nie cichego gościa), `log level = 1 auth:3 auth_audit:3`, drukarki wyłączone.
Nazwy operacji `full_audit:success` muszą istnieć w danej wersji Samby (`fdopendir mkdirat unlinkat open openat read pread write pwrite renameat`
działają w Samba 4.23 z Almy 9.8); stare nazwy `opendir`, `mkdir`, `unlink`, `rename` powodują `NT_STATUS_UNSUCCESSFUL` przy każdym udziale.

Routing logów do rsyslog:


*`samba_structure/setup-honeypot.sh`, linie 187–195*

```bash
echo ">> [8] rsyslog: full_audit -> $HP_AUDIT_LOG (agent to czyta)"
install -d -m 0755 /var/log/samba
[ -f "$HP_AUDIT_LOG" ] || install -m 0600 /dev/null "$HP_AUDIT_LOG"
command -v restorecon >/dev/null 2>&1 && restorecon "$HP_AUDIT_LOG" || true
cat > /etc/rsyslog.d/40-samba-audit.conf <<EOF
local5.*   -$HP_AUDIT_LOG
& stop
EOF
systemctl restart rsyslog || true
```

### 9.3 Okruszek (breadcrumb)

Hasło konta `backup_srv` leży w `Archiwum$/IT/kopia_zapasowa.sh` jako zmienna `PASS=`, razem z celem `scp` na nieistniejący host `nas-arch01`.
Atak „okruszkiem" przebiega tak: napastnik zdobywa konto persony, otwiera plik (widoczne w `full_audit`, serwer ustawia `breadcrumb_read`), loguje się przez SSH
jako `backup_srv` (serwer ustawia `confirmed`). Dom `backup_srv` zawiera `.bash_history` i `.ssh/known_hosts` z hostami `db-fin01` i `nas-arch01`, `.viminfo`, `.lesshst`, `Pobrane/`.


*`samba_structure/setup-honeypot.sh`, linie 93–96*

```bash
echo ">> [6] Okruszek: poświadczenia backup_srv w Archiwum\$"
# UWAGA reachability: Archiwum wymaga @finanse — okruszek osiagalny po zdobyciu konta persony.
mk "$BASE/Archiwum/IT/kopia_zapasowa.sh" 240 "root:$HP_SMB_GROUP" "#!/bin/sh\n# Nocna kopia udzialow na serwer archiwum.\nUSER=$HP_SHELL_DECOY_USER\nPASS=$HP_SHELL_DECOY_PASS\nsshpass -p \"\$PASS\" scp -r /srv/samba/Finanse \$USER@$HP_FAKE_BACKUP_HOST:/backup/\n"
mk "$BASE/Archiwum/IT/README.txt" 240 "root:$HP_SMB_GROUP" 'Skrypty kopii zapasowych. Nie zmieniac bez zgody dzialu IT.'
```

> **Dostępność okruszka:** `Archiwum$` wymaga członkostwa w `@finanse`, więc okruszek jest osiągalny dopiero po zdobyciu konta persony. To świadoma, odnotowana w ustaleniach cecha;
> przeniesienie kopii do `Wspolny` zmieniłoby scenariusz ataku.

### 9.4 SSH, firewall, SELinux, auditd

- **sshd** (`/etc/ssh/sshd_config.d/10-honeypot.conf`): logowanie hasłem włączone (przynęta i telemetria nieudanych prób), `PermitRootLogin no`, `LogLevel VERBOSE`,
  baner przed logowaniem, MOTD z notką działu IT; `svc-admin` tylko kluczem. Linie `Failed password` / `Accepted ...` trafiają do `/var/log/secure`, który agent czyta.
- **auditd:** reguły `execve` dla `auid>=1000` (klucz `hp_cmd`), plugin `syslog` przekazuje je do `/var/log/messages` (best-effort). Pozwala to zobaczyć komendy wykonywane przez
  `backup_srv`, który ma prawdziwą powłokę.
- **Firewall:** tylko `ssh` (port odczytany z `sshd -T`) i `samba` (+ `3702/udp` dla `wsdd`), pozostałe usługi usuwane ze strefy.
- **SELinux:** `samba_share_t` na `/srv/samba`, `samba_export_all_rw/ro`, jawna etykieta `var_log_t` dla `audit.log`, żeby `rsyslog` mógł pisać do katalogu Samby.
- **WS-Discovery (`wsdd`):** wabik jest widoczny w „Sieci" Windows; szum Windows (np. porty 3702, 445, 139) nie może być liczony jako skan, stąd próg `fast_enum` na różnych portach.

### 9.5 „Oznaki życia"

Maszyna ma wyglądać na używaną, ale **bez fałszywych alarmów**:

- świeżość plików ustawiana jest **raz przy instalacji** (`touch -d`); cron nie rusza monitorowanych udziałów,
- historia logowań to wyłącznie **udane** logowania kont z powłoką, zasiane przed startem agenta: linie `Accepted publickey` w `/var/log/secure` (klasyfikowane jako
  `authentication_success`, nigdy atak) oraz rekordy `wtmp` (agent ich nie czyta),
- agent jest na czas zasiewania zatrzymywany, żeby nie zgłosić tych linii,
- nigdy nie są zasiewane fałszywe nieudane logowania,
- zrotowane logi (`messages-YYYYMMDD`) mają puste ciało i stare daty.

### 9.6 `setup-realism.sh`

Usuwa oznaki wabika widoczne dla kogoś, kto wpisze `ps`, `free`, `ip a`: wyłącza środowisko graficzne (`multi-user.target`), ukrywa procesy innych użytkowników
(`hidepid=2` na `/proc`, więc zwykły użytkownik nie zobaczy `sys-auditd` ani Javy kolektora), obniża `vm.swappiness`, wyłącza adresowanie IPv6 zdradzające MAC karty
(`stable-privacy`). MAC, DMI, rozmiary dysku i pamięci trzeba ustawić ręcznie w hiperwizorze.

## Dodatek: powiązane dokumenty

| Dokument | Zawartość |
|---|---|
| `README.md` | skrót i spis katalogów |
| `docs/WDROZENIE-OD-ZERA.md` | pełna instrukcja wdrożenia „Dział Finansów" krok po kroku |
| `docs/PRZEGLAD.md` | jak to działa w skrócie |
| `server/docs/api.md`, `server/docs/attacker-detection.md` | API i wykrywanie atakujących |
| `samba_structure/ustalenia-konfiguracja.md` | decyzje projektowe persony |
