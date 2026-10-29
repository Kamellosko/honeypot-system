# Jak działa nasz system wykrywania — opis techniczny

Stan na 2026-10-23, na podstawie kodu w repozytorium (agent C, serwer Java, dashboard JS, skrypty).
Wszystko poniżej wynika z czytania kodu; tam, gdzie nie sprawdziłem tego na żywej maszynie, jest to
oznaczone jako **[do weryfikacji]**. Lista luk i ryzyk jest w rozdziale 13.

---

## 1. Obraz całości

System **nie blokuje i nie analizuje ataków** — rejestruje dowody. Honeypot to zwykła maszyna z Sambą
(AlmaLinux 9.8, hostname `fs01`), udająca serwer plików firmy. Obok Samby działa agent, który
obserwuje trzy rzeczy: **pliki w udziałach**, **logi** i **połączenia TCP**. Każde zdarzenie
zamienia w raport JSON, zapisuje go trwale na dysku, a potem wysyła HTTPS-em do kolektora.

```
 atakujący ──SMB/SSH──►  H = fs01 (AlmaLinux 9.8)
                        ┌────────────────────────────────────────────────────────────┐
                        │ smbd/nmbd ─► /srv/samba/{Dokumenty,Faktury,Kadry}          │
                        │           └► /var/log/samba/*  (auth:3 auth_audit:3)       │
                        │                                                            │
                        │ sys-auditd (agent C, root)                                 │
                        │   ├─ inotify na udziałach ─┐                               │
                        │   ├─ tail logów (poll)     ├─► raport JSON ─► pending/*.json│
                        │   └─ netlink SOCK_DIAG ────┘        (fsync, atomowo)      │
                        │   wątek wysyłający: pending ─► HTTPS POST /events          │
                        │                                   │ 127.0.0.1:8443         │
                        │ sysmon-collector (Java, user sysmon)◄┘                     │
                        │   ├─ dedup po report_id ─► /var/lib/sysmon/events.jsonl    │
                        │   └─ /api/v1/{agents,events,stats} + dashboard (statyczny) │
                        └────────────────────────────────────────────────────────────┘
        dashboard: tylko przez tunel SSH (ssh -L 8443:127.0.0.1:8443)
        kopia dowodów poza maszynę: sync-events.sh (rsync po SSH, cron)
```

**Topologia faktycznie wdrażana przez skrypty: jedna maszyna.** `install-server-service.sh` ustawia
`server.bind=127.0.0.1` i nie otwiera portu w firewallu, a `install-agent-service.sh` domyślnie celuje
w `127.0.0.1:8443`. Opis trzech maszyn (M1/M2/M3) w `server/README.md` jest starszy i nie pokrywa się
z tym, co instalują skrypty. Dlatego `sync-events.sh` kopiuje `/var/lib/sysmon/events.jsonl` z tej samej
maszyny — to jedyna kopia poza H.

### Podział odpowiedzialności
| Warstwa | Co robi | Czego **nie** robi |
|---|---|---|
| Samba (`setup-samba-honeypot.sh`) | Wabik: udziały, konta, pliki, logi uwierzytelniania | Nie ma audytu operacji na plikach (brak `vfs_full_audit`) |
| Agent (C) | Wykrywa zdarzenia, robi migawki i diffy, kolejkuje i wysyła | Nie ocenia, kto jest atakującym (`actor` zawsze `null`) |
| Serwer (Java) | Waliduje, deduplikuje, dopisuje do logu, udostępnia API | Nie koreluje zdarzeń, nie uwierzytelnia agentów |
| Dashboard (JS) | Odświeża co 4 s, koloruje, pokazuje surowy JSON | Nie koreluje, nie alarmuje |

---

## 2. Maszyna-wabik (co widzi atakujący)

Źródło: `scripts/setup-samba-honeypot.sh`, `scripts/setup-persona.sh`.

- **Udziały** w `/srv/samba`: `Dokumenty` (grupa `pracownicy`), `Faktury` (`ksiegowosc`), `Kadry` (`kadry`),
  katalogi `2770` z setgid. `valid users = @grupa`, brak `guest ok` — bez konta nie wejdzie się do żadnego udziału.
- **Konta**: z zmiennej `SMB_USERS` (`login:haslo:grupy`), `useradd -M -s /sbin/nologin`, hasło tylko w `smbpasswd`.
  Hasła słabe, ale wiarygodne — są poza repozytorium.
- **Pliki-przynęty** z datami modyfikacji rozłożonymi na ~2 lata (`touch -d "N days ago"`), m.in.
  `Dokumenty/Stare/hasla_stare.csv` (fałszywe dane dostępowe — główna przynęta), `Faktury/*.csv`, `Kadry/*.csv`.
- **SELinux**: `samba_share_t` na `/srv/samba`, `samba_export_all_rw=on`.
- **Firewall**: tylko usługa `samba`. SSH jest osobno (baner/MOTD z `setup-persona.sh`).
- **`smb.conf` (ważne dla agenta)**: `map to guest = Never`, `log level = 1 auth:3 auth_audit:3`,
  `log file = /var/log/samba/log.smbd`, `max log size = 5000`.
- **Persona**: hostname `fs01.firma.local`, backup w cronie (niedziela 02:00 — tworzy `/var/backups/fs-*.tgz`),
  logrotate dla logów Samby.

Świadomie **nie ma** `guest ok`, udziału `public` ani konta `decoy` — skrypt je usuwa (`CLEANUP_OLD=yes`).

---

## 3. Agent `sys-auditd` — start i pętla główna

Źródło: `agent/src/main.c`.

### 3.1 Uruchomienie
- Argumenty: `--id`, `--ip`, `--port` (każdy najwyżej raz; walidacja: ID 1–128 znaków ASCII drukowalnych, IP przez `inet_pton`, port 1–65535).
- `umask 0077`, stdout/stderr → `/dev/null`, nazwa procesu zmieniona na `sys-auditd` (`prctl(PR_SET_NAME)` + nadpisanie `argv[0]`).
- Stan w `/var/lib/sys-auditd` (0700, root): `snapshots/` i `pending/`. Ścieżki otwierane przez `openat2` z
  `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, więc symlink w udziale nie przekieruje agenta poza udział.
- Jednostka systemd (`sys-auditd.service`): `User=root`, ale `CapabilityBoundingSet=CAP_DAC_READ_SEARCH` (czyta wszystko, nic więcej),
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`,
  `Restart=on-failure` co 5 s, start po `smb.service` i `rsyslog.service`.

### 3.2 Wątki
- **Wątek główny** — obserwacja (poniżej) i **wytwarzanie** raportów.
- **Wątek wysyłający** (`sender_loop`) — tylko **czyta** zatwierdzone pliki z `pending/` i wysyła. Gdy nic nie wysłał,
  śpi 5 s; gdy wysłał, od razu bierze następny.

### 3.3 Pętla (jedna iteracja ≈ ≤1 s)
```
1. heartbeat_tick            – co 60 s ±15 %
2. hp_monitor_poll(1000 ms)  – (a) refresh_roots (b) poll() na inotify (c) poll_logs (d) obsługa zdarzeń inotify
                               (e) domknięcie kolejek rename/create po ≥1 s
3. hp_connections_poll       – co 1 s, netlink SOCK_DIAG
4. gdy coś padło             – raport observation_gap (z ponawianiem do skutku)
5. co 60 s                   – ponowne wykrycie źródeł (smb.conf, logi) i przebudowa monitora, jeśli się zmieniły
```
Zdarzenia inotify budzą pętlę natychmiast, więc opóźnienie wykrycia zmiany pliku to ułamek sekundy
(poza oknem 1 s na `create`, opisanym niżej).

---

## 4. Wykrywanie źródeł (skąd agent wie, co obserwować)

Źródło: `agent/src/config.c`. Agent **nie ma listy ścieżek w konfiguracji** — czyta `/etc/samba/smb.conf` sam
i powtarza to co 60 s. Dlatego po zmianie udziałów nie trzeba restartować agenta.

1. **Własny parser `smb.conf`**: sekcje, `path`/`directory`, `available`, `printable`/`print ok`, wartości domyślne z `[global]`,
   `include =` (tylko ścieżki bezwzględne, głębokość ≤16), ciągłość linii `\`. Pomija drukarki i udziały `available = no`.
   Limity: plik 1 MiB (suma z include 4 MiB), 4096 udziałów.
2. **Odrzuca to, czego nie umie** — zamiast zgadywać, zgłasza raport `source/source_unavailable` z powodem:
   ścieżki z `%`, `$`, `{}`, rejestr/`config backend`, `usershare`, `copy =`, include dynamiczne.
3. **`[homes]`**: czyta konta z `passdb.tdb` (tdbsam v4, przez `libtdb`, z blokadą odczytu i limitem 2 s) albo `smbpasswd`,
   rozwiązuje katalogi domowe przez `getpwnam_r`, obsługuje `%H %U %u %S`.
4. **Logi Samby**: wzorzec z `log file =` zamieniany na glob (`%m` → `*`), plus **wszystkie** zwykłe pliki z `/var/log/samba/`
   (pomija archiwa `.gz .xz .bz2 .zst .zip`). Limit 4096 źródeł.
5. **Logi systemowe**: `/var/log/messages`, `/var/log/secure`, `/var/log/cron`, `/var/log/maillog`, `/var/log/boot.log`.
   Brakujący plik → raport `source_unavailable` (`missing_log`), nie błąd krytyczny.

Ścieżka udziału musi istnieć jako katalog i **nie może przechodzić przez symlinki** (`openat2`), inaczej udział
jest zgłoszony jako `missing_or_inaccessible_share`.

---

## 5. Obserwacja plików w udziałach

Źródło: `agent/src/monitor.c`, `agent/src/snapshot.c`.

### 5.1 Mechanizm
- **inotify**, rekursywnie: dla każdego katalogu osobny watch (`watch_tree`), maska
  `CLOSE_WRITE | CREATE | DELETE | MOVED_FROM | MOVED_TO | ATTRIB | DELETE_SELF | MOVE_SELF`.
  Nowe podkatalogi dostają watch w locie i są od razu przeskanowane (pliki w nich → `create`).
- Watch zakładany przez `/proc/self/fd/N` otwartego deskryptora katalogu (nie przez nazwę), żeby podmiana katalogu na symlink nic nie dała.
- Katalog stanu agenta jest wyłączony z obserwacji (agent nie widzi własnych zapisów).
- Co iterację `refresh_roots` sprawdza (dev+inode), czy korzeń udziału nie został podmieniony/usunięty:
  `observation_gap: share_root_replaced_or_removed`, potem pełne ponowne przeskanowanie.
- Przepełnienie kolejki inotify (`IN_Q_OVERFLOW`) → raport `observation_gap: inotify_overflow` i ponowne przeskanowanie wszystkich udziałów.

### 5.2 Migawki (stan referencyjny)
Dla każdego pliku w udziale agent trzyma w `/var/lib/sys-auditd/snapshots/`:

| Plik | Zawartość |
|---|---|
| `<sha256(pełna ścieżka)>` | **pełna kopia** pliku z ostatniego znanego stanu |
| `<klucz>.path` | pełna ścieżka (potrzebna do wykrywania usunięć i rename) |
| `<klucz>.stat` | binarnie: mode, uid, gid, mtime(s/ns), sha256 treści |
| `root-<sha256(korzeń)>` | znacznik „ten udział był już raz zeskanowany" |

Konsekwencja: **miejsce na dysku ≈ rozmiar wszystkich udziałów**. Plik większy niż 64 MiB nie jest kopiowany
(`capture_failed`, zdarzenie zgłoszone jako niekompletne).

### 5.3 Pierwszy start vs kolejne
- **Pierwsze skanowanie udziału** (brak znacznika `root-…`): operacja `baseline` — kopiuje pliki i zapisuje stan,
  **nie wysyła żadnych raportów**. Znacznik zakładany dopiero po bezbłędnym skanie.
- **Kolejny start** (znacznik jest): każdy plik jest porównywany z migawką (operacja `reconcile`). Różnica →
  raport; brak różnicy → cisza. Pliki, których już nie ma → `delete_during_downtime`.
  Plik nowy w czasie przestoju nie ma migawki → raport z `complete:false`, `error:"missing_baseline"`.
- Tak agent wykrywa zmiany zrobione, gdy był wyłączony (np. atakujący ubił usługę).

### 5.4 Zdarzenia i ich obsługa

| Zdarzenie na dysku | inotify | Operacja w raporcie | Uwagi |
|---|---|---|---|
| Nowy plik | `CREATE` (+`CLOSE_WRITE`) | `create` | `CREATE` jest **odkładany na ≥1 s**; jeśli w tym czasie przyjdzie `CLOSE_WRITE`, raport idzie od razu z gotową treścią |
| Plik utworzony i skasowany w <1 s | `CREATE`, `DELETE` | `create_delete` (`contents_unavailable`) | treści nie udało się zapisać — zostaje tylko ślad |
| Zapis do istniejącego | `CLOSE_WRITE` | `modify` | raport tylko gdy zmienił się hash **lub** metadane |
| chmod/chown/touch | `ATTRIB` | `metadata` | raport tylko gdy metadane różne od zapisanych |
| Usunięcie | `DELETE` | `delete` | w raporcie jest **cała dawna treść** (diff z samych linii `-`) |
| Zmiana nazwy w obrębie udziału | `MOVED_FROM`+`MOVED_TO` (ten sam cookie) | `rename` (+`previous_path`) | migawki i ścieżki są przenoszone, dla katalogu rekurencyjnie |
| Rename nadpisujący istniejący plik | j.w., cel istniał | `rename_overwrite` + `delete` + `rename` | zachowany diff nadpisanej treści |
| Przeniesienie **poza** udział | `MOVED_FROM` bez pary po ≥1 s | `delete` | okno parowania cookie: 128 wpisów |
| Przeniesienie **do** udziału z zewnątrz | `MOVED_TO` bez pary | `create` | |
| Skasowanie po przestoju | skan przy starcie | `delete_during_downtime` | |

Pełne odczyty (`IN_ACCESS`/`IN_OPEN`) **nie są obserwowane** — samo przeczytanie lub skopiowanie pliku przez SMB
nie zostawia zdarzenia plikowego (patrz 13.1 pkt 2).

### 5.5 Przechwytywanie pliku (`capture`)
Plik jest czytany z `openat2`, kopiowany blokami po 64 KiB do pliku tymczasowego. Spójność sprawdzana trzykrotnie:
`stat` przed, `stat` po i `stat` pod ścieżką muszą być **identyczne** (dev, inode, rozmiar, mtime, ctime). Plik zmieniający się
w trakcie kopiowania po 3 próbach daje raport `error:"unstable_capture"`. To chroni przed zapisaniem połowy pliku jako „stanu".

### 5.6 Co jest w raporcie o zmianie pliku
- `metadata`: `old_size`, `new_size`, `old/new_mode`, `old/new_uid`, `old/new_gid`, `mtime_sec`.
- `content_changes`: `old_sha256`, `new_sha256` oraz jeden z dwóch formatów treści:
  - **`unified`** — gdy oba pliki są tekstem UTF-8 bez bajtów NUL i ≤1 MiB. Diff liczony algorytmem LCS na liniach,
    z kontekstem 3 linii, hunki sklejane gdy przerwa ≤6 linii. Wspólny prefiks i sufiks są odcinane przed LCS.
    Budżet: macierz LCS ≤1 048 576 komórek; większa zmiana → jeden hunk „wszystko usunięte, wszystko dodane".
  - **`blocks64k`** — dla binariów i dużych plików: tylko **zmienione bloki 64 KiB** (`offset`, `old_base64`, `new_base64`),
    łącznie do 16 MiB. Powyżej → `diff_failed` (raport niekompletny, bez treści).
- `evidence` — fragmenty logów powiązane z plikiem (5.7).
- `complete` / `error` — czy agent ma pewność co do raportu (np. `missing_baseline`, `missing_metadata_baseline`, `diff_failed`).

### 5.7 Powiązanie pliku z logiem („evidence")
Każda linia logu trafia (po zgłoszeniu) do **pierścienia 32 ostatnich linii**. Przy raporcie o pliku agent szuka w nim
linii z **ostatnich 60 s**, które zawierają **nazwę pliku** (sama nazwa bazowa, także poprzednia przy rename).
Pasujące linie są dołączane jako `evidence[]` z `context_only:true` i listą adresów IP znalezionych w tekście.
`analysis.actor` jest zawsze `null` — agent niczego nie przypisuje, tylko dokłada kontekst. **Uwaga:** przy obecnym
`smb.conf` w logach Samby nie ma nazw plików, więc to powiązanie praktycznie się nie uruchamia (13.1 pkt 2).

### 5.8 Gwarancja „nie zgubić"
Kolejność w `hp_snapshot_event`:
```
1. kopia nowej treści → plik tymczasowy w snapshots/
2. porównanie hash + metadane  → jeśli bez zmian: cisza, koniec
3. zapis raportu: pending/.<id>.tmp → fsync → renameat2(NOREPLACE) → fsync katalogu
4. DOPIERO POTEM: migawka (rename tmp→klucz), .path, .stat, fsync
```
Raport trafia na dysk **przed** aktualizacją stanu referencyjnego. Awaria między krokami 3 i 4 daje najwyżej
**duplikat** (ta sama zmiana wykryta znowu), nigdy utratę zmiany.

---

## 6. Obserwacja logów

Źródło: `agent/src/monitor.c` (`poll_logs`), `agent/src/snapshot.c` (`hp_report_simple`).

- **Brak inotify** — logi są odpytywane przy każdej iteracji pętli (`open` → `fstat` → `read` od zapamiętanego offsetu).
- **Pierwsze zobaczenie pliku na starcie agenta**: offset = koniec pliku. **Historia sprzed startu agenta jest pomijana.**
  Plik wykryty później (np. nowy `log.<klient>` przy odświeżeniu 60 s) jest czytany **od początku**.
- **Jedna linia = jeden raport** (`source:"log"`, `operation:"append"`, treść linii w `content` lub `content_base64`).
  Linia dłuższa niż 64 KiB jest ucinana na segmenty (`long_record_segment`). Niedokończona linia czeka w buforze do `\n`.
  Limit odczytu: 1 MiB na plik na iterację.
- **Rotacja** (zmiana dev/inode) → `rotation` / `possible_log_gap`, offset od 0; niedokończony fragment wysyłany jako `partial_record_at_rotation`.
  **Obcięcie** (`size < offset`) → `truncation` / `possible_log_gap`.
- Plik zniknął → `source_unavailable` (jednorazowo).

### 6.1 Klasyfikacja linii (cały „silnik wykrywania" na logach)
`hp_report_simple` robi tylko dopasowanie podciągów w treści linii:

| Podciąg w linii | `analysis.classification` |
|---|---|
| `Failed password` (sshd, `/var/log/secure`) **lub** `NT_STATUS_LOGON_FAILURE` (Samba) | `authentication_failure` |
| `smbd_audit:` (syslog z `vfs_full_audit`) | `samba_audit` |
| cokolwiek innego | `unknown` |

Nie ma reguł typu „5 błędów w minutę", nie ma progów ani korelacji — każda linia jest osobnym zdarzeniem,
a ocena wolumenu i wzorców to praca analityka na dashboardzie.

### 6.2 Kontekst sieciowy z linii (`network_context`)
`hp_extract_ips` dzieli linię na tokeny złożone z `[A-Za-z0-9.:_%-]` i próbuje każdy sparsować jako IPv4, IPv6
(także `::ffff:a.b.c.d`) albo `IPv4:port`. Dla każdego znalezionego IP (do `HP_NETWORK_MAX`, bez duplikatów)
agent robi **lookup MAC w lokalnej tablicy ARP** (`SIOCGARP`, tylko interfejsy w tej samej podsieci).
Status: `resolved`, `not_in_local_arp_cache`, `ambiguous_interfaces`, `ipv6_no_arp`, `lookup_error`.
MAC to **kontekst, nie dowód** (`context_only:true`) — dla klienta zza routera zobaczymy MAC bramy albo nic.

**Znane ograniczenie (sprawdzone testem):** token w formacie Samby `ipv4:192.168.1.5:49152` ma dwa dwukropki,
więc nie jest rozpoznawany — z takiej linii wychodzi **0 adresów** (13.1 pkt 1).

---

## 7. Obserwacja połączeń TCP

Źródło: `agent/src/connections.c`.

- Co **1 s** agent otwiera gniazdo `AF_NETLINK / NETLINK_SOCK_DIAG`, pyta jądro o wszystkie gniazda TCP w stanach
  `LISTEN` i `ESTABLISHED` (osobno IPv4 i IPv6), z limitem 2 s i 65 536 gniazd. Nie używa libpcap ani `/proc/net/tcp`.
- Zbiór sortowany po (stan, port lokalny). Dla każdego `ESTABLISHED` sprawdza, czy **istnieje gniazdo `LISTEN` na tym samym
  porcie lokalnym** (adres wildcard albo ten sam) — tylko wtedy to połączenie *przychodzące do naszej usługi*
  (`direction: inbound_listener_match`).
- Połączenie jest raportowane **raz**: tożsamość = cookie gniazda jądra + adresy + porty. Zestaw „już widzianych" jest
  zapamiętywany między iteracjami; zniknięcie połączenia czyści wpis.
- Raport: `source:"network"`, `operation:"tcp_connection_observed"`, `classification:"tcp_connection"`,
  `connection{local_ip, local_port, peer_port, peer{ip, mac, interface, mac_status}}`, `observation_method:"inet_diag_poll"`.
- IPv4 w gnieździe IPv6 (`::ffff:`) jest sprowadzane do zwykłego IPv4.

Porty, które w ten sposób zostaną objęte, to wszystkie z `LISTEN`: 445/139 (Samba), 22 (SSH) **i 8443 (nasz kolektor)**.
Połączenie agenta do własnego kolektora na loopbacku zostałoby raportowane w kółko, dlatego serwer ma
filtr `isOwnUpload` (rozdział 10): odpowiada 200 `ignored:true` i nie zapisuje.

Co to oznacza w praktyce:
- Dobrze widać **każdego klienta SMB/SSH, który utrzymał połączenie ≥~1 s**, razem z jego adresem IP.
- **Nie widać** skanów SYN (`nmap -sS`) — nie dochodzą do `ESTABLISHED`. Krótkie `connect()` scan (`-sT`) zwykle też umyka między próbkami.
- Przy starcie agenta zgłaszane są także **już istniejące** połączenia (np. nasza własna sesja SSH).

---

## 8. Heartbeat i raporty o własnej kondycji

- **Heartbeat** (`system/heartbeat`): co 60 s ±15 % (losowy jitter z `getrandom`, 51–69 s). Pierwszy po ~minucie od startu.
  Serwer uznaje agenta za `online`, jeśli ostatni raport (dowolny) przyszedł w ciągu **90 s**.
- **`observation_gap`** — agent sam zgłasza, że przestał widzieć. Powody (pole `error`): `inotify_overflow`,
  `share_root_replaced_or_removed`, `tcp_observation_failed`, `monitor_or_spool_failure`, `source_discovery_failed`,
  `rename_cookie_capacity`, `create_queue_capacity`, `path_too_long`, `rename_*_failed`, `reconcile_access_failed`.
  Raport o luce jest ponawiany w każdej iteracji, aż uda się go zapisać.
- **`source_unavailable`** — źródła, których nie da się obserwować (brak logu, nieobsługiwana konfiguracja, brak udziału).
- Brak heartbeatów dłużej niż 90 s to najprostszy sygnał, że ktoś ubił agenta lub maszynę.

---

## 9. Kolejka i wysyłanie (agent → serwer)

Źródło: `agent/src/port.c`, `agent/src/snapshot.c` (`report_begin`/`report_end`).

### 9.1 Zapis raportu
Nazwa pliku = `<64 hex losowych bajtów z RAND_bytes>.json` (`report_id`). Zapis: `.<id>.json.tmp` (0600) → `fsync` →
`renameat2(RENAME_NOREPLACE)` → `fsync` katalogu. Odczytujący wątek widzi tylko gotowe pliki o nazwie dokładnie
`<64 hex>.json`. Limit kolejki: **10 000** raportów; powyżej raporty są odrzucane (a agent zgłasza `observation_gap`).

### 9.2 Wysyłka
- Wątek wysyłający przechodzi `pending/` przez `readdir` (**kolejność nieokreślona**, nie chronologiczna), wysyła **jeden raport
  na jedno połączenie** (nowy handle libcurl, nowy handshake TLS), `POST https://<ip>:<port>/events`, `Content-Type: application/json`.
- TLS: `SSL_VERIFYPEER=1`, `SSL_VERIFYHOST=2`, brak proxy, brak przekierowań; timeout połączenia 5 s, całości 30 s.
  Weryfikacji nie da się wyłączyć. Zaufanie do CA: magazyn systemowy (`install-agent-service.sh` kopiuje `ca.crt` do
  `/etc/pki/ca-trust/source/anchors/sysmon-ca.crt` i robi `update-ca-trust`); SAN certyfikatu **musi zawierać adres, pod który łączy się agent** (`127.0.0.1`).
- Interpretacja odpowiedzi:

| Odpowiedź | Co robi agent |
|---|---|
| 2xx | usuwa plik z `pending/` + `fsync` — dostarczone |
| 3xx/4xx (poza 408, 429) | „serwer odrzucił na stałe" → plik zmieniony na `<id>.json.rejected`, wysyłka idzie dalej |
| 5xx, 408, 429, błąd sieci/TLS | zostawia plik, ponawia po ~5 s |

Skutki: awaria serwera nie gubi danych (kolejka rośnie do 10 000); dostawa to *at-least-once*, a duplikaty zdejmuje serwer.

---

## 10. Serwer (kolektor)

Źródło: `server/src/main/java/pl/honeypot/server/*`.

- **Javalin + Jetty**, wyłącznie HTTPS (TLS 1.2/1.3, keystore PKCS12 z `gen-certs.sh`), bind `127.0.0.1:8443`,
  maks. rozmiar żądania 32 MiB (domyślny 1 MB odrzucałby diffy, a agent ponawiałby je w nieskończoność).
- **`POST /events`** (`ReportHandler`) — walidacja koperty: `schema_version == 1`, `report_id` = 64 znaki `[0-9a-f]`,
  `agent_id` = `[A-Za-z0-9._-]{1,64}`, `source` ∈ {share, log, network, system, monitor, source}, `operation` = `[a-z0-9_]{1,64}`.
  Błąd → 400 (agent zaparkuje raport jako `.rejected`). Reszta pól jest przechowywana **bez interpretacji**.
- **Filtr własnego uploadu**: `tcp_connection_observed` z `local_port == port serwera` i obydwoma końcami na loopbacku → 200 `ignored`, bez zapisu.
- **Deduplikacja**: zbiór `report_id` w pamięci (odbudowywany z pliku przy starcie). Nowy → zapis + `201 {event_id, report_id}`;
  powtórka → `200 {duplicate:true}`.
- **Trwałość** (`JsonlLog`): jedna linia JSON na raport w `events.jsonl` (0600), dopisanie `event_id` (licznik) i `received_at`,
  `FileChannel.force` **przed** odpowiedzią 2xx. Po awarii przy starcie obcinany jest niedokończony ostatni wiersz.
  Zapis jest pierwszy, dopiero potem raport trafia do zbioru „widziane" — nieudany zapis nie zamieni ponowienia w „duplikat".
- **Liczniki w pamięci** (`ReportStore`): stan agentów (first/last seen, ostatnie source/operation/classification, liczba raportów),
  zliczenia `by_source`, `by_operation`, `by_classification`. „online" = ostatni raport < 90 s temu **wg czasu serwera** (`received_at`).
- **API odczytu** (bez uwierzytelniania): `GET /api/v1/agents`, `GET /api/v1/events?agent_id=&source=&limit=` (od najnowszych
  wg kolejności zapisu), `GET /api/v1/stats`. Dashboard jest serwowany z tego samego origin (`dashboard.dir`).

---

## 11. Dashboard

Źródło: `dashboard/app.js`.
- Co 4 s (przełącznik „auto") pobiera równolegle `stats`, `agents`, `events`; nie nakłada żądań (flaga `busy`), timeout 3 s.
- Karty agentów (ONLINE/OFFLINE, ostatni raport, liczba raportów), tabela zdarzeń z filtrami (źródło, agent, limit),
  kliknięcie wiersza otwiera panel z **pełnym surowym JSON-em** raportu.
- Kolorowanie wg `classification`: czerwone — `authentication_failure`, `file_change`, `rename`, …; żółte — `tcp_connection`,
  `samba_audit`; reszta neutralna. Kolumna „stan": ✓ lub ✗ z powodem z `error`.
- Treści pochodzące od atakującego (nazwy plików, linie logów) przechodzą przez `esc()` — brak wstrzyknięcia HTML do panelu.
- Połączenie z kolektorem: `https://127.0.0.1:8443/` przez tunel SSH.

---

## 12. Kompletny przepływ — trzy scenariusze

**A. Atakujący zgaduje hasło do SMB**
1. Połączenie TCP na 445 → ≤1 s później `network/tcp_connection_observed` z IP klienta (i MAC, jeśli ten sam L2).
2. `smbd` zapisuje błąd logowania w `/var/log/samba/log.smbd` (`auth_audit:3`).
3. Agent czyta nową linię, robi raport `log/append`; jeśli linia zawiera `NT_STATUS_LOGON_FAILURE` → `authentication_failure`.
4. Raport w `pending/` → POST → `events.jsonl` → dashboard (czerwony wiersz).

**B. Atakujący ma konto i podmienia `Faktury/2024/FV_2024_003.csv`**
1. SMB zapisuje plik → inotify `CLOSE_WRITE` → agent kopiuje, liczy SHA-256, porównuje z migawką.
2. Raport `share/modify`, `file_change`, `unified` diff (stare vs nowe linie), `old_sha256 ≠ new_sha256`, rozmiary, uid/gid właściciela.
3. Migawka zaktualizowana **po** zatwierdzeniu raportu.
4. Kto to zrobił: z samego raportu **nie wynika** — dopasowujemy po czasie do `tcp_connection_observed` / logowań (patrz 13).

**C. Atakujący zabija agenta, kasuje plik i restartuje agenta/maszynę**
1. Heartbeat milknie → po 90 s agent „offline" na dashboardzie.
2. Po restarcie agent porównuje udział z migawkami → `delete_during_downtime` / `reconcile` (z `missing_baseline` dla nowych plików).
3. Dowody sprzed ubicia agenta są już w `events.jsonl`; jego kopię poza maszynę robi cron z `sync-events.sh`.
   Atakujący z rootem na H może jednak skasować lokalny `events.jsonl` — dlatego kopia zdalna jest ważna.

---

## 13. Luki, ryzyka i rzeczy do sprawdzenia

Posortowane wg wpływu na to, co system ma dostarczyć (dowody + kto/kiedy).

### 13.1 Wysoki wpływ
1. **Adres IP z logów Samby nie jest wyciągany [sprawdzone testem].** Samba zapisuje klienta jako `ipv4:A.B.C.D:port`;
   token ma dwa dwukropki i `hp_extract_ips` go odrzuca. Na przykładowej linii w tym formacie: 0 adresów; w linii sshd
   (`from 192.168.1.5 port …`) i w `A.B.C.D:port`: 1 adres. Skutek: raporty `authentication_failure` z Samby mają puste `network_context`
   (nie ma IP ani MAC w samym raporcie). IP trzeba dopasować ręcznie po czasie z raportem `tcp_connection_observed`.
   Test jednostkowy (`network_test.c`) tego formatu nie obejmuje. Format linii podałem z pamięci o Sambie **[do weryfikacji na żywym logu z H]**.
2. **Brak audytu operacji na plikach w Sambie.** `smb.conf` z naszego skryptu nie ma `vfs objects = full_audit`, a poziom logów `1 auth:3 auth_audit:3`
   nie loguje otwarć ani nazw plików. Skutki: (a) `evidence[]` przy zmianach plików będzie puste (szuka nazwy pliku w ostatnich 60 s logów);
   (b) klasyfikacja `samba_audit` nigdy się nie włączy; (c) odczyt/pobranie pliku (wykradanie `hasla_stare.csv`) w ogóle nie zostawia śladu —
   agent nie obserwuje `IN_OPEN`/`IN_ACCESS`, a Samba tego nie loguje. Agent jest już gotowy na `smbd_audit:` w syslogu
   (`/var/log/messages` jest monitorowany); brakuje tylko konfiguracji po stronie Samby.
3. **Czy `NT_STATUS_LOGON_FAILURE` w ogóle pojawia się w logu [do weryfikacji].** Klasyfikacja `authentication_failure` zależy od tego dokładnego
   ciągu. Z pamięci o Sambie wpisy `auth_audit` dla złego hasła/nieznanego użytkownika mogą nosić `NT_STATUS_WRONG_PASSWORD` / `NT_STATUS_NO_SUCH_USER`.
   Test z `NOTATKA-samba.md` pkt 4 (`smbclient … -U jkowalski%zle`) rozstrzyga to jednoznacznie — po nim należy zajrzeć w
   `/var/log/samba/log.smbd` i w raport na dashboardzie. Jeśli ciągu nie ma, trzeba rozszerzyć listę w `hp_report_simple` (`snapshot.c`).

### 13.2 Średni wpływ
4. **TCP przez próbkowanie 1 s**: brak skanów SYN, krótkie połączenia mogą umknąć; długie sesje raportowane tylko raz.
5. **Historia logów sprzed startu agenta jest pomijana** (offset na końcu przy pierwszym zobaczeniu pliku).
6. **Serwer bez uwierzytelniania**: każdy, kto dotrze do `127.0.0.1:8443` (czyli atakujący z shellem na H), może wstrzyknąć fałszywe raporty
   i czytać wszystko przez API (raporty zawierają treść plików i logów). Zewnętrznie chroni tylko bind na loopback i brak reguły w firewallu.
   Projekt (`projekt_honeypot.md`) przewiduje token / mTLS, ale nie jest to zaimplementowane.
7. **Skalowanie serwera**: każde zapytanie `GET /api/v1/events` czyta i parsuje **cały** `events.jsonl`; dashboard robi to co 4 s.
   Przy dużym ruchu logów (jedna linia = jeden raport) plik szybko rośnie. Zbiór `report_id` też rośnie w pamięci bez limitu.
8. **Niezgodność walidacji ID**: agent dopuszcza `--id` do 128 znaków ASCII, serwer tylko `[A-Za-z0-9._-]{1,64}`. Inny ID → 400 → wszystkie raporty
   lądują jako `.rejected`. Domyślne `fs01`/`alma10-01` są poprawne.
9. **Wydajność wysyłki**: nowy handshake TLS na każdy raport, kolejność `readdir`. Przy zalewie linii logu kolejka może narastać do limitu 10 000.
   Dodatkowo `hp_store_pending_count` liczy pliki zawierające `.json` w nazwie — także `*.json.rejected` i pliki tymczasowe — a `.rejected`
   nigdy nie są czyszczone, więc potrafią w końcu zająć limit kolejki.
10. **Nieobecność wykrywania wzorców**: żadnej korelacji ani progów (np. N prób logowania z jednego IP) — klasyfikacja jest tylko podciągowa.

### 13.3 Niskie / porządkowe
11. Dashboard koloruje klasyfikacje `observation_gap`, `delete`, `downtime_change`, ale agent emituje je jako **operacje**, a klasyfikacja bywa `unknown` —
    luki obserwacji nie są podświetlone jako ostrzeżenia.
12. W kodzie baseline na ponownym starcie daje operację `reconcile` (nie `downtime_change`, jak opisuje `server/docs/api.md`); `downtime_change`
    wystąpi tylko, gdy migawka istnieje, ale brak znacznika `root-…`.
13. `NOTATKA-samba.md` każe mieć `log file = /var/log/samba/log.%m`, a skrypt zapisuje `log.smbd`. Agent obsługuje oba warianty
    (czyta cały `/var/log/samba/`), ale notatka i skrypt powinny mówić to samo.
14. Brakuje plików, do których odnoszą się dokumenty: `INSTALL.md`, `REALIZM.md`, `agent/README-technical.md`.
15. W `server/certs/` leżą klucze prywatne (`ca.key`, `server.key`) — przed realnym wdrożeniem wygenerować nowe poza repozytorium.
16. README agenta mówi o AlmaLinux 10, skrypty o 9.8 (stąd `FORTIFY_LEVEL=2` w `install-agent-service.sh`). Wymaga jednorazowego sprawdzenia, że agent
    buduje się na 9.8 (`openat2`, `libtdb-devel`).

---

## 14. Parametry i limity w jednym miejscu

| Parametr | Wartość | Gdzie |
|---|---|---|
| Heartbeat | 60 s ±15 % | `config.h`, `heartbeat.c` |
| Próbkowanie TCP | 1 s | `connections.c` |
| Odświeżenie źródeł (smb.conf, logi) | 60 s | `main.c` |
| Ponowienie niedokończonego skanu udziału | 60 s | `monitor.c` |
| Okno `create`/parowania `rename` | 1 s, 128 wpisów | `monitor.c` |
| Pierścień dowodów z logów | 32 linie, 60 s | `snapshot.c` |
| Maks. kolejka raportów | 10 000 | `snapshot.c` |
| Maks. kopiowany plik | 64 MiB | `snapshot.c` |
| Diff tekstowy | ≤1 MiB, LCS ≤1 048 576 komórek | `diff.c` |
| Zmienione bloki binarne w raporcie | ≤16 MiB (bloki 64 KiB) | `snapshot.c` |
| Segment linii logu | 64 KiB; odczyt ≤1 MiB/plik/iterację | `monitor.c` |
| Timeouty HTTPS | 5 s połączenie / 30 s całość | `port.c` |
| Próg „online" na serwerze | 90 s | `ReportStore.java` |
| Maks. żądanie na serwerze | 32 MiB | `Main.java` |
| Odświeżanie dashboardu | 4 s | `app.js` |

## 15. Jak to sprawdzić na maszynie H

```sh
systemctl status sys-auditd sysmon-collector smb nmb          # wszystko active
ls /var/lib/sys-auditd/pending | wc -l                          # kolejka (powinna być ~0)
ls /var/lib/sys-auditd/pending | grep -c rejected               # raporty odrzucone na stałe (powinno być 0)
tail -n 3 /var/lib/sysmon/events.jsonl | jq -c '{event_id,source,operation,analysis,error}'
curl --cacert server/certs/ca.crt https://127.0.0.1:8443/api/v1/stats
curl --cacert server/certs/ca.crt https://127.0.0.1:8443/api/v1/agents
# test jednego scenariusza z zewnątrz:
smbclient //<IP_H>/Dokumenty -U jkowalski%zle -c ls            # → sprawdź w log.smbd i w raporcie (13.1 pkt 1 i 3)
smbclient //<IP_H>/Dokumenty -U jkowalski%'<haslo>' -c 'put x.txt'   # → share/create
```
