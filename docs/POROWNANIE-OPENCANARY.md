# Porównanie: nasz honeypot vs OpenCanary (Thinkst)

Stan na 2026-11-20. OpenCanary: wersja **0.9.10**, commit `08bebdf` (klon w `../opencanary/`, obok tego repozytorium).
Nasz system: gałąź `main`, commit `281007f` + zmiany robocze.

> **Metoda i zastrzeżenia.** Analiza wynika z **czytania kodu i dokumentacji** obu projektów. OpenCanary **nie został uruchomiony**
> (zainstalowałem tylko źródła do porównania), więc opisy zachowania w runtime (np. wygląd odpowiedzi modułów) pochodzą z kodu,
> a nie z obserwacji. Liczby linii to `wc -l` na plikach źródłowych, bez testów i bibliotek zewnętrznych.
> To porównanie dwóch **różnych filozofii**, a nie wyścig „kto lepszy": w wielu miejscach wygrywa jeden, w innych drugi.

---

## 1. Streszczenie (TL;DR)

| | **OpenCanary** | **Nasz honeypot** |
|---|---|---|
| Idea | **Emulacja** wielu protokołów w jednym demonie; alarm przy *jakimkolwiek* dotknięciu | **Prawdziwa** maszyna (sshd + Samba) udająca serwer plików Działu Finansów; agent zbiera **dowody** |
| Język | Python 3.10+ (Twisted) | C (agent) + Java 21 (serwer) + JS (dashboard) |
| Szerokość | ~20 protokołów (FTP, HTTP(S), SSH, Telnet, SMB, MySQL, MSSQL, Redis, MongoDB, RDP, VNC, SNMP, SIP, NTP, TFTP, Git, proxy, LLMNR, TCP-banner, skan portów) | 2 usługi: SSH + SMB (+ rejestrowanie TCP na 22/139/445) |
| Głębia interakcji | płytka: loguje próbę (login/hasło/komenda), zwykle odrzuca | **głęboka**: atakujący dostaje prawdziwe pliki i (po okruszku) prawdziwą powłokę; widzimy zmiany plików z diffem |
| Wdrożenie | `pip install` / Docker, 1 plik JSON | skrypty + C + Java + certyfikaty + persona (instrukcja ~400 linii) |
| Alerty | gotowe: e-mail, Slack, Teams, webhook, syslog, hpfeeds, SMS (przez correlator) | e-mail (SMTP) przy wejściu IP na poziom skaner / brute force / przynęta / potwierdzony; dashboard odświeżany co 4 s |
| Skala | wiele kanarków, wspólna konsola (Thinkst Canary — komercyjnie) | 1 maszyna, 1 kolektor lokalny |
| Dojrzałość | wieloletni projekt, CI, testy integracyjne na moduł, PyPI, Docker | młody projekt, bardzo gruntowne testy agenta (C), niewdrożony produkcyjnie |
| Licencja | BSD | brak pliku LICENSE w repo |

**Wniosek w jednym zdaniu:** OpenCanary to **czujka alarmowa** (tania, szeroka, „ktoś dotknął — krzyczymy"),
a nasz system to **czarna skrzynka lotnicza** (wąska, droga we wdrożeniu, „zapisz dokładnie co zrobił i co zmienił").
Najlepszy układ prawdopodobnie łączy oba (rozdz. 9).

---

## 2. Architektura

### 2.1 OpenCanary

Jeden proces (`opencanaryd`) na **Twisted** (reaktor zdarzeń). Z `opencanary.conf` (płaski JSON `moduł.opcja`) ładuje
włączone moduły (`config.py`: klucz `*.enabled`), każdy moduł to klasa `CanaryService` z `NAME` i `startYourEngines()`.
Każda usługa nasłuchuje na własnym porcie, a **każdą interakcję** zamienia na zdarzenie przez wspólny `logger`.

```
atakujący ──► [ftp|http|ssh|telnet|mysql|...] (Twisted, port per moduł)
                         │ self.log(logtype=..., logdata=...)
                         ▼
                 PyLogger (logging) ──► handlery: plik / konsola / syslog / SMTP / Slack / Teams / webhook / hpfeeds / socket JSON
```

Moduły „pasywne" (`portscan`, `samba`) nie słuchają same — **czytają logi systemu** (`FileSystemWatcher`):
`portscan` czyta log `iptables` (`/var/log/kern.log`, reguły `canaryfw:`), `samba` czyta `smbd_audit` (`/var/log/samba-audit.log`).

### 2.2 Nasz system

Trzy warstwy: **wabik** (prawdziwa Samba + sshd, `samba_structure/`), **agent** `sys-auditd` (C, ~2,7 tys. linii),
**kolektor** `sysmon-collector` (Java/Javalin, razem z agentem ~3,6 tys. linii) + dashboard JS. Agent obserwuje
pliki (inotify + migawki), logi i połączenia TCP (netlink `SOCK_DIAG`), zapisuje raport JSON na dysk (`fsync`, atomowy `rename`)
i dopiero potem wysyła HTTPS-em; serwer deduplikuje po `report_id` i dopisuje do `events.jsonl`.

### 2.3 Różnica zasadnicza

| Aspekt | OpenCanary | Nasz |
|---|---|---|
| Co jest „usługą" | **kod honeypota** (Python udaje protokół) | **prawdziwe oprogramowanie** (smbd, sshd) |
| Skąd zdarzenia | z samej usługi (in-process) | z **obserwacji z zewnątrz** (inotify, logi, netlink) |
| Model zaufania do zdarzeń | usługa wie, co się dzieje | agent *zgaduje* z logów i plików; stąd `observation_gap`, `source_unavailable` |
| Podatność honeypota na exploity | własny kod emulacji (Twisted, parsery protokołów) | **cała** powierzchnia prawdziwego Samba/sshd |
| Wiarygodność wobec skanera | zależy od jakości emulacji (fingerprinting wykrywa) | maksymalna — to prawdziwy serwer |

---

## 3. Pokrycie usług i protokołów

OpenCanary (moduły w `opencanary/modules/`): FTP, HTTP (skórki `nasLogin`, `basicLogin`), HTTPS, HTTP-proxy (skórka squid),
SSH, Telnet, SMB (przez audyt prawdziwej Samby), MySQL, MSSQL, Redis, MongoDB, RDP, VNC, SNMP, SIP, NTP (monlist), TFTP,
Git, LLMNR, **tcpbanner** (dowolny port z bannerem, do 10 instancji), **portscan** (SYN, nmap NULL/XMAS/FIN/OS), plus `example0/1`
jako szablony modułów użytkownika (`LOG_USER_0..9`).

Nasz system: **tylko SSH (22) i SMB (445/139)**.

| Kryterium | OpenCanary | Nasz |
|---|---|---|
| Liczba protokołów | ~20 | 2 |
| Dodanie nowego protokołu | napisać klasę `CanaryService` (~50–150 linii; szablony w repo) | napisać usługę + rozszerzyć `config.c`/klasyfikację w agencie (C) |
| Skan portów | **tak** (iptables: SYN, NULL/XMAS/FIN, nmap OS) | **tak od 0.3.0** (`net.scan`: log zapory `firewalld`, próg 10 portów w 10 s; SYN/NULL/XMAS/FIN; **do potwierdzenia na Almie**). Wcześniej netlink nie widział skanów SYN (`dzialanie-systemu.md` 13.2/4) |
| Wykrycie ruchu bocznego (LLMNR/NBNS/SMB) | LLMNR, SMB | SMB; NetBIOS + wsdd jako „szum" do odfiltrowania |

**Ocena:** pod względem szerokości OpenCanary wygrywa bezdyskusyjnie. Dla atakującego w sieci wewnętrznej to ważne:
różni atakujący sięgają po różne porty (3389, 1433, 6379, 21, 23…), a my mamy dwa.

---

## 4. Głębia interakcji — co widzi atakujący, co zapisujemy

### 4.1 SSH — kluczowy przykład

**OpenCanary (`ssh.py`, Twisted Conch):** loguje próbę (`LOG_SSH_LOGIN_ATTEMPT`): `USERNAME`, `PASSWORD`, wersja
lokalna i zdalna. Domyślnie `portal.login` kończy się odrzuceniem; po (opcjonalnym) trafieniu w `honeycreds` istnieje awatar,
ale `openShell`, `execCommand` i `getPty` są **puste** (`return`/`None`). Czyli atakujący nigdy nie dostaje działającej powłoki,
nie zobaczymy jego komend. Wersja banera konfigurowalna (`ssh.version`; domyślnie bardzo stara `OpenSSH_5.1p1 Debian-4`, co samo jest sygnałem).

**Nasz:** prawdziwy `sshd` z `LogLevel VERBOSE`, hasła włączone, banner + MOTD, konto-przynęta `backup_srv` z prawdziwą powłoką
(hasło w okruszku), `auditd → syslog` rejestruje **komendy**. Udane logowanie na `backup_srv` = poziom `confirmed`.

| | OpenCanary | Nasz |
|---|---|---|
| Loguje login/hasło | **tak, każdą próbę** (pełne hasło) | od 0.3.0 hook PAM (`auth.attempt`, tylko nieudane próby SSH; **niezweryfikowany na Almie**, domyślnie wyłączony). `sshd` sam haseł nie loguje; SMB: tylko nazwa użytkownika |
| Komendy po zalogowaniu | nie (brak powłoki) | tak (auditd) |
| Ryzyko dla maszyny | niskie (brak powłoki) | **realne**: `backup_srv` ma prawdziwy shell, potrzebny hardening i egress (otwarty punkt w `ustalenia-konfiguracja.md`) |
| Informacja o atakującym | dane uwierzytelniające, wersja klienta SSH | cały przebieg ataku po wejściu |

Uwaga: zbieranie **haseł z prób** (słowniki, kampanie botnetów) to realna wartość OpenCanary, której nasz system **nie ma**.
Z kolei „co zrobił po wejściu" to coś, czego OpenCanary nie da w ogóle.

### 4.2 SMB / pliki

**OpenCanary (`samba.py`):** nie emuluje SMB! Wymaga **prawdziwej Samby** z `vfs objects = full_audit` i parsuje wiersze
`smbd_audit` rozdzielone `|` (użytkownik, IP klienta, share, wersja SMB, akcja, status, ścieżka) do zdarzenia `LOG_SMB_FILE_OPEN` (5000).
Czyli w warstwie SMB OpenCanary robi **to samo, co my**, tylko prościej: jedno zdarzenie z linii audytu, **bez** migawek plików i diffów.
Parser jest kruchy (indeksuje `data[0..12]` na sztywno; linia z inną liczbą pól rzuci wyjątek w `handleLines`).

**Nasz:** inotify + pełne kopie plików (SHA-256, do 64 MiB) + diff (unified dla tekstu, bloki 64 KiB dla binariów)
+ `full_audit` (odczyty/pobrania) + logi uwierzytelniania. Przy usunięciu raport zawiera całą zawartość pliku.
Wykrywa też zmiany z czasu przestoju agenta (`reconcile`/`delete_during_downtime`).

**Ocena:** tu jesteśmy **wyraźnie głębsi**. Odpowiedź na „co dokładnie zmienił/skasował/zaszyfrował" (ransomware, sabotaż)
mamy, OpenCanary nie.

### 4.3 Pozostałe usługi (OpenCanary)

HTTP/HTTPS: strona logowania NAS-a, loguje `POST` z loginem i hasłem; MySQL/MSSQL/Redis/Mongo/Telnet/FTP/VNC/RDP: banner,
rejestracja prób logowania lub komend (Redis loguje komendy `LOG_REDIS_COMMAND`). Nic z tego nie wykonuje realnej pracy — to „wejście, które dzwoni".

---

## 5. Model zdarzeń i logowanie

**OpenCanary** ma **ustandaryzowany, numerowany schemat**: ~44 typy (`LOG_FTP_LOGIN_ATTEMPT=2000`, `LOG_SSH_LOGIN_ATTEMPT=4002`,
`LOG_PORT_SYN=5001`, …). Każde zdarzenie to JSON: `node_id`, `local_time`, `utc_time`, `src_host`, `src_port`, `dst_host`, `dst_port`,
`logtype`, `logdata{…}`. Dobre do SIEM (stabilne pola, stabilne kody).

**Nasz:** koperta `schema_version=1`, `report_id` (64 hex), `agent_id`, `source`, `operation`, `classification`, `network_context`,
treść bez interpretacji (diffy, linie logów). Bogatsza, ale **mniej znormalizowana**: klasyfikacja to wyszukiwanie podciągów
(`Failed password`, `NT_STATUS_LOGON_FAILURE`, `smbd_audit`), reszta to `unknown`. `actor` zawsze `null`.

| | OpenCanary | Nasz |
|---|---|---|
| Schemat | stały, numerowane typy, płaskie `logdata` | koperta + zmienna treść per źródło |
| Znacznik czasu | `utc_time` (+ `local_time`) | `received_at` na serwerze + czas w raporcie |
| Trwałość | zależna od handlera (plik/`logging`); przy sieci brak gwarancji dostarczenia (socket JSON ma ponowienia, reszta „best effort") | **at-least-once**: raport na dysk z `fsync`, kolejka 10 000, ponawianie, dedup po `report_id`, serwer odpowiada 2xx dopiero po `force` |
| Integralność | brak | atomowy zapis, wykrywanie luk obserwacji (`observation_gap`, `possible_log_gap`) |
| Deduplikacja | nie | tak |

**Ocena:** pod względem **niezawodności dowodu** nasz transport jest znacznie solidniejszy. Pod względem **ergonomii dla SIEM**
OpenCanary (stały schemat, gotowe typy) jest lepszy; u nas SIEM-owi trzeba by dopisać mapowanie.

---

## 6. Alertowanie i analiza

### 6.1 OpenCanary

Alerty przez standardowe handlery `logging` w konfiguracji logger-a: **SMTP (e-mail)**, **Slack** (`SlackHandler`), **Microsoft Teams**
(`TeamsHandler`, z `facts()`), **webhook** (`WebhookHandler` z mapowaniem pól `map_string`), **syslog** (`syslog_rfc`),
**hpfeeds** (współdzielenie telemetrii), **socket JSON** (do korelatora). Dodatkowo `ip.ignorelist` i `logtype.ignorelist`
do wyciszania szumu (np. własnego skanera podatności). Osobny projekt **opencanary-correlator** (SMS Twilio, e-mail, Slack)
agreguje zdarzenia (np. `scans.network_portscan_horizon`).

### 6.2 Nasz system

Serwer **stopniuje** atakujących w `/api/attackers` (`contact` → `suspicious` → `fast_enum` → `brute_force` → `bait` → `confirmed`)
z progami (≥5 nieudanych logowań/10 min, ≥3 porty/60 s, `net.scan` od agenta) i **okruszkiem** (odczyt `kopia_zapasowa.sh` albo próba
na `backup_srv` = `bait`; udane SSH jako `backup_srv` = pewny atak). Przy wejściu IP na `fast_enum` i wyżej serwer wysyła **e-mail**
(SMTP, jeden kanał; limit 60/h, bez maili za szum pojedynczych prób).

| | OpenCanary | Nasz |
|---|---|---|
| Powiadomienia push | **tak, wiele kanałów** | **e-mail** (jeden kanał) |
| Wyciszanie szumu | `ip.ignorelist`, `logtype.ignorelist` | filtr pętli zwrotnej; szum Windows (NetBIOS/wsdd) to otwarty temat |
| Korelacja | zewnętrzny correlator | **wbudowana**, ale prosta (progi + okruszek) |
| Poziom pewności „to na pewno atak" | zakładany z definicji (nikt nie powinien dotykać kanarka) | **jawny**: `confirmed` tylko po okruszku; reszta stopniowana |

**Ocena:** OpenCanary wygrywa liczbą kanałów (Slack, Teams, webhook, SMS). My wygrywamy w „rozumiem, jak groźne to jest"
(stopniowanie, okruszek), a od etapu 3 mamy też ostatni kilometr: alarm e-mail przy groźnych poziomach.

---

## 7. Wdrożenie, utrzymanie, koszty

| | OpenCanary | Nasz |
|---|---|---|
| Instalacja | `pip install opencanary`, `opencanaryd --copyconfig`, edycja JSON; Docker / `docker-compose` | `WDROZENIE-OD-ZERA.md` (~400 linii): klucz SSH, serwer, persona, agent (kompilacja C), certyfikaty, testy |
| Zasoby | „działa na Raspberry Pi" | jedna VM AlmaLinux 9.8; miejsce na dysku ≈ rozmiar udziałów (pełne migawki) |
| Zależności | Twisted, cryptography, Jinja2, passlib… (przypięte w `pyproject.toml`/`uv.lock`), opcjonalnie scapy | libc + cJSON (w repo) po stronie agenta; JDK 21 + Javalin po stronie serwera |
| Aktualizacje | `pip install -U`; **łatwo o dług zależności** (twisted, cryptography, stare `bcrypt==3.2.0`, `simplejson==3.16.0`) | własny kod, brak zewnętrznego upstreamu — łatki robimy sami |
| Wiele maszyn | tak (`device.node_id`, wspólne logi/konsola) | jeden agent ↔ jeden lokalny kolektor; wiele agentów technicznie możliwe (serwer rozpoznaje je z raportów), ale brak uwierzytelniania agentów |
| Portscan | wymaga `iptables` (nie nftables) — **na AlmaLinux 9 to problem** (nftables), do obejścia | netlink, bez iptables |
| Koszt obsługi | niski | średni/wysoki (persona, utrzymanie „życia" maszyny, higiena danych) |

**Ocena:** OpenCanary można postawić w kwadrans; nasz system wymaga godzin i wiedzy. Za to nasz daje realistyczną
„fizyczną" maszynę, której OpenCanary nie stworzy.

---

## 8. Bezpieczeństwo samego honeypota

| Zagadnienie | OpenCanary | Nasz |
|---|---|---|
| Powierzchnia ataku | własna implementacja ~20 protokołów w Pythonie — dużo parserów, historycznie zdarzają się CVE w emulowanych usługach i zależnościach | prawdziwy smbd/sshd (znane, łatane, ale też znane atakującym; możliwy realny exploit i ucieczka) |
| Realna powłoka dla atakującego | **brak** (`openShell` puste) | **jest** (`backup_srv`) → wymaga hardeningu, egress-filteringu, izolacji sieciowej |
| Uprawnienia demona | `--uid=nobody --gid=nogroup` (Docker domyślnie), porty <1024 wymagają capability | agent jako root z `CAP_DAC_READ_SEARCH`, `ProtectSystem=strict`, `NoNewPrivileges`; `openat2 RESOLVE_BENEATH` (symlink nie wyprowadzi poza udział) |
| Ochrona kanału zdarzeń | zależy od handlera | TLS z weryfikacją (zawsze), ale **API bez uwierzytelniania**, chronione tylko bindem na `127.0.0.1`; atakujący z shellem na maszynie może wstrzykiwać raporty (`dzialanie-systemu.md` 13.2/6) |
| Manipulowanie dowodami po przejęciu hosta | zdarzenia lokalne, do wysłania natychmiast do zewnętrznego kolektora | kolektor na tej samej maszynie; kopia poza maszynę dopiero przez `sync-events.sh` (cron) — **okno na kasowanie dowodów** po root-compromise |
| Wykrywalność jako honeypot | stare bannery domyślnie; skórki HTTP; znane odciski emulacji | bardzo trudna do odróżnienia od serwera plików; ryzyko to ślady sztuczności w personie (daty, historia) |

**Ocena:** OpenCanary jest **bezpieczniejszy w eksploatacji** (nic realnego do przejęcia), a nasz **trudniejszy do wykrycia**.
To klasyczny kompromis honeypotów niskiej i wysokiej interakcji.

---

## 9. Testy i jakość kodu

| | OpenCanary | Nasz |
|---|---|---|
| Testy | `test/unit` (6 plików) + `test/integration` (~18 modułów: FTP, SSH, HTTP(S), MySQL, Redis, Mongo, RDP…), CI w GitHub Actions, badge'e | ~25 testów C (agent: diff, snapshot, config, monitor, transport, awarie IO/alokacji, cykl życia) + testy integracyjne HTTPS w Pythonie; serwer Java — **do zweryfikowania** pokrycie testami |
| Charakter testów | „czy usługa odpowiada i loguje" (czarna skrzynka) | rygorystyczne **testy awarii** (zapis, alokacja, transport, wipe) — to rzadkość |
| Rozmiar | ~7,6 tys. linii Pythona (z czego `des.py` 1640 linii to wendorowany DES) | ~3,6 tys. linii (C+Java) |
| Dokumentacja | Sphinx (`docs/`), README, opisy alertów | bardzo szczegółowa po polsku (`DOKUMENTACJA-TECHNICZNA.md` ~2,3 tys. linii), lista znanych luk |

---

## 10. Gdzie który wygrywa

**OpenCanary wygrywa:**
1. Szerokość (≈20 protokołów) i **szybkość wdrożenia**.
2. **Powiadomienia** (e-mail/Slack/Teams/webhook/syslog) i ignore-listy.
3. Stały **schemat zdarzeń** (numerowane typy) — łatwa integracja z SIEM.
4. **Rejestrowanie haseł** z prób (login + hasło) — wiedza o kampaniach.
5. Wykrywanie **skanów portów** (iptables) i skanów nmap.
6. Niskie ryzyko (brak realnej powłoki), niskie wymagania sprzętowe.
7. Społeczność, CI, utrzymywany upstream.

**Nasz system wygrywa:**
1. **Dowody śledcze na plikach**: migawki SHA-256, diffy, treść usuniętych plików, wykrywanie zmian w czasie przestoju.
2. **Niezawodność transportu** (fsync, atomowość, kolejka, dedup, ponawianie, raportowanie luk obserwacji).
3. **Wiarygodność** — prawdziwa Samba/sshd, spójna persona, okruszki.
4. **Głębia po wejściu** (komendy z auditd, prawdziwy shell na przynęcie).
5. **Stopniowanie atakujących** i pewne potwierdzenie przez okruszek.
6. Twarde hardening-i agenta (capability bounding, `openat2`).

**Remis / zależy:** SMB — oba opierają się na prawdziwej Sambie z `full_audit`; nasz dokłada migawki i diffy, OpenCanary
tylko surowe zdarzenie otwarcia.

---

## 11. Luki naszego systemu ujawnione przez porównanie

Uporządkowane wg stosunku zysku do kosztu:

| # | Luka | Jak robi to OpenCanary | Proponowane działanie | Koszt |
|---|---|---|---|---|
| 1 | ~~Brak powiadomień~~ (etap 3: e-mail przy wejściu IP na `fast_enum`/`brute_force`/`bait`/`confirmed`) | handlery Slack/Teams/SMTP/webhook | inne kanały (webhook/Slack) tylko w razie potrzeby | niski |
| 2 | ~~Brak haseł z prób~~ (etap 2, 0.3.0: hook PAM, do sondy na Almie) | loguje `USERNAME`/`PASSWORD` w każdej próbie SSH | rozważyć warstwę przechwytującą (np. `pam`-moduł/`auditd` jest niewystarczający; sshd nie loguje haseł) — albo uruchomić OpenCanary SSH na innym porcie jako kolektor kampanii | średni |
| 3 | ~~Brak wykrywania skanów portów~~ (etap 2, 0.3.0: `net.scan` z logu `firewalld`, do sondy na Almie) | iptables `LOG` + parser (SYN/NULL/XMAS/FIN) | reguły nftables `log prefix` + odczyt logu jądra przez istniejący mechanizm monitorowania logów agenta | niski–średni |
| 4 | **Wąski wachlarz usług** | ~20 modułów | dołożyć OpenCanary jako **tanie czujki** na portach: 21, 23, 80, 1433, 3306, 3389, 6379 (rdz. 12) | niski |
| 5 | **Ignore-listy** | `ip.ignorelist`, `logtype.ignorelist` | lista IP „znane/dozwolone" w `server.properties` (skaner podatności, własne stacje) — pomoże też z szumem Windows | niski |
| 6 | **Niestandaryzowany schemat typów** | numerowane `logtype` | tabela mapowania `source/operation/classification` → kody w dokumentacji API (dla SIEM) | niski |
| 7 | **Kolektor na tej samej maszynie** | zdarzenia wysyłane od razu poza hosta | zdalny kolektor/`syslog` w czasie rzeczywistym zamiast cron-owego `rsync` (okno na kasowanie dowodów) | średni |
| 8 | **API bez uwierzytelniania** | n/d (zależy od handlera) | token/mTLS, jak przewiduje `projekt_honeypot.md` | średni |
| 9 | **Skala (>1 maszyna)** | `node_id`, wspólna konsola | uwierzytelnianie agentów + wspólny kolektor | wysoki |

---

## 12. Rekomendacja: architektura łączona

Dwa systemy się **uzupełniają**, nie wykluczają:

```
                 ┌──────────────────────────── izolowana sieć honeypotów ───────────────────────────┐
 atakujący ─────►│  fs-finanse (nasz):  SSH 22 + SMB 445 + agent sys-auditd + kolektor              │
 (ruch boczny)   │  canary-01 (OpenCanary): 21, 23, 80/443, 1433, 3306, 3389, 6379, skan portów     │
                 └───────────────┬───────────────────────────────────────────────┬──────────────────┘
                                 │ dowody (pliki, diffy, komendy)                │ alarmy (Slack/webhook/syslog)
                                 ▼                                               ▼
                       dashboard + /api/attackers  ◄────── wspólna lista IP atakujących ──────► SIEM / powiadomienia
```

1. **OpenCanary jako „siatka" czujek** na tanim VM/kontenerze (Docker jest gotowy: `Dockerfile.latest`, `docker-compose.yml`),
   pokrywająca porty, których nie obsługujemy; wyłączone SSH/SMB (to zostaje nasze).
2. **Nasz system jako „głęboki wabik"** z dowodami.
3. **Połączenie**: log OpenCanary (JSON) jako dodatkowe źródło do kolektora (nowy `source: opencanary`) albo odwrotnie —
   `/api/attackers` karmi `ip.ignorelist`/powiadomienia. Wspólny „atakujący" = IP widziane w obu systemach (silny sygnał ruchu bocznego).
4. Najtańszy pierwszy krok: **webhook Slack/Teams z poziomu serwera** (luka #1) oraz **OpenCanary z wyłączonym SSH/SMB**
   na osobnej maszynie w tej samej sieci. Nie wymaga zmian w agencie.

### Czego nie robić
- Nie włączać SSH w OpenCanary na tej samej maszynie, co nasz `sshd` (konflikt portu i fałszywe poziomy zagrożenia).
- Nie przenosić naszego agenta w kierunku „emulacji protokołów" — to utrata jego głównej przewagi (dowody z prawdziwego systemu).
- Nie kopiować instalacji `portscan` z OpenCanary 1:1 — wymaga `iptables`, a Alma 9 używa `nftables`.

---

## 13. Otwarte pytania (nie rozstrzygnięte w tej analizie)

- Jak OpenCanary zachowuje się **w runtime** pod AlmaLinux 9 (iptables vs nftables, SELinux) — wymaga próby.
- Czy parser `samba.py` radzi sobie z naszym formatem `full_audit` (`smbd_audit[PID]:`; nasz agent musiał to osobno obsłużyć commitem `f051aa2`) —
  jego regex szuka `smbd_audit.*: ` i zakłada określoną liczbę pól rozdzielonych `|`; **wymaga testu na naszej konfiguracji `full_audit`**.
- Pokrycie testami serwera Java (nie badane w tej analizie).
- Skuteczność wykrycia naszej persony przez skanery typu `nmap`/`smbmap` kontra emulacja OpenCanary — brak pomiaru.

---

## Załącznik A. Mapowanie pojęć

| OpenCanary | Nasz odpowiednik |
|---|---|
| `opencanaryd` | `sys-auditd` + `sysmon-collector` |
| `opencanary.conf` (JSON `moduł.opcja`) | `/etc/samba/smb.conf` (czytany przez agenta) + `server.properties` + `honeypot.conf` |
| `CanaryService` / `startYourEngines()` | brak (usługi to prawdziwe demony) |
| `logtype` (np. 4002) | `source` + `operation` + `classification` |
| `node_id` | `agent_id` |
| `honeycreds` (konta-przynęty) | konto `backup_srv` + okruszek w `kopia_zapasowa.sh` |
| `portscan` | `fast_enum` w `/api/attackers` (inna metoda: porty dotknięte, nie pakiety SYN) |
| `ip.ignorelist` | filtr pętli zwrotnej (brak ogólnej listy) |
| handlery Slack/Teams/SMTP/webhook | brak |
| correlator | `ReportStore` + `/api/attackers` |
| `FileSystemWatcher` (tail logu) | `poll_logs` w `monitor.c` |

## Załącznik B. Źródła

- OpenCanary: `../opencanary/README.md`, `opencanary/modules/{ssh,samba,portscan,__init__}.py`, `opencanary/logger.py`,
  `opencanary/data/settings.json`, `docs/alerts/*`, `docs/starting/correlator.rst`, `pyproject.toml`.
- Nasz system: `README.md`, `docs/PRZEGLAD.md`, `docs/dzialanie-systemu.md` (zwł. rozdz. 13), `samba_structure/ustalenia-konfiguracja.md`,
  `server/docs/attacker-detection.md`.
