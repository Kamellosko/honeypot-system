# Jak działa agent i serwer — w skrócie

Całość działa na jednej maszynie (AlmaLinux). Samba udaje serwer plików firmy, agent to obserwuje,
serwer zbiera raporty, dashboard je pokazuje. System niczego nie blokuje — tylko zapisuje dowody.

```
atakujący ─SMB/SSH─► Samba (/srv/samba/*, logi w /var/log/samba)
                         │ pliki / logi / połączenia
                         ▼
                  AGENT sys-auditd (C, root)
                   raport JSON → /var/lib/sys-auditd/pending/
                         │ HTTPS POST /events (127.0.0.1:8443)
                         ▼
                  SERWER sysmon-collector (Java)
                   dedup → /var/lib/sysmon/events.jsonl
                   API /api/v1/* → DASHBOARD (przeglądarka, tunel SSH)
```

---

## Agent (C) — `agent/`

Jeden proces, dwa wątki:

- **Wątek główny** obserwuje i tworzy raporty. Pętla co ≤1 s.
- **Wątek wysyłający** bierze gotowe raporty z `pending/` i wysyła je do serwera.

### Co robi w jednej iteracji pętli

1. **Heartbeat** co ~60 s: sygnał życia. Brak sygnału oznacza, że ktoś mógł wyłączyć agenta.
2. **Pliki**: czeka na zdarzenia inotify z udziałów.
3. **Logi**: czyta nowe linie z logów Samby, SSH i systemu.
4. **Połączenia**: pyta jądro o gniazda TCP.
5. Co 60 s od nowa wykrywa, co obserwować.

### Skąd wie, co obserwować

Agent sam czyta `/etc/samba/smb.conf` (własny parser) i znajduje udziały oraz logi.
Robi to co 60 s, więc nowy udział nie wymaga restartu. Czego nie umie zinterpretować, zgłasza
raportem `source_unavailable`, zamiast zgadywać.

### Pliki (`monitor.c`, `snapshot.c`)

- Obserwuje je rekursywnie przez **inotify**: tworzenie, zapis, usunięcie, zmiana nazwy, chmod/chown.
- Trzyma **pełną kopię każdego pliku** w `/var/lib/sys-auditd/snapshots/` razem z hashem SHA-256 i metadanymi.
  Miejsce na dysku jest więc mniej więcej równe rozmiarowi udziałów. Plik większy niż 64 MiB nie jest kopiowany.
- Przy zmianie porównuje nowy plik z kopią i robi **diff**:
  - tekst: unified diff, z kontekstem 3 linii;
  - binaria: tylko zmienione bloki 64 KiB w base64.
- Przy usunięciu raport zawiera całą dawną treść pliku.
- Pierwszy skan udziału to tylko zapamiętanie stanu, bez raportów. Przy kolejnym starcie agent porównuje
  pliki z kopiami i wykrywa zmiany zrobione, gdy był wyłączony (`delete_during_downtime`).
- Symlinki w udziale nie przekierują agenta poza udział (`openat2` z `RESOLVE_BENEATH`).

### Logi

- Odpytuje je przy każdej iteracji. Zaczyna od końca pliku, więc historia sprzed startu agenta jest pomijana.
- **Jedna linia logu to jeden raport.**
- Wykrywa rotację i obcięcie plików (`possible_log_gap`).
- Klasyfikacja to zwykłe szukanie tekstu w linii:
  - `Failed password` lub `NT_STATUS_LOGON_FAILURE` daje `authentication_failure`,
  - `smbd_audit:` daje `samba_audit`,
  - wszystko inne to `unknown`.
- Z linii wyciąga adresy IP, a dla IP z tej samej podsieci także MAC z tablicy ARP. To tylko kontekst, nie dowód.

### Połączenia TCP (`connections.c`)

Co 1 s agent pyta jądro przez netlink `SOCK_DIAG` o gniazda `LISTEN` i `ESTABLISHED`.
Połączenie przychodzące do naszej usługi (445, 139, 22) raportuje **raz**, z adresem IP klienta.
Nie widać skanów SYN ani bardzo krótkich połączeń.

### Raport i kolejka (`port.c`)

- Raport to plik JSON w `pending/`. Zapis jest bezpieczny: plik tymczasowy, `fsync`, atomowy `rename`.
  **Raport trafia na dysk przed aktualizacją stanu odniesienia**, więc awaria da najwyżej duplikat, nigdy dziurę.
- Wątek wysyłający robi `POST https://127.0.0.1:8443/events`. Weryfikacja TLS jest zawsze włączona.
- Reakcja na odpowiedź serwera:
  - **2xx**: raport jest kasowany z kolejki.
  - **4xx** (poza 408 i 429): raport dostaje nazwę `.rejected` i nie jest ponawiany.
  - **5xx lub błąd sieci**: raport zostaje i jest ponawiany po ~5 s.
- Kolejka mieści 10 000 raportów.
- Gdy agent czegoś nie widzi (przepełnienie inotify, błąd, zniknięty udział), sam zgłasza `observation_gap`.
- Agent nie ocenia, kto jest sprawcą: pole `actor` jest zawsze `null`.

---

## Serwer (Java 21, Javalin) — `server/`

Tylko HTTPS, nasłuch na `127.0.0.1:8443`. Agentów nie trzeba rejestrować — serwer poznaje ich z raportów.

### `POST /events` (`ReportHandler`)

1. Sprawdza kopertę: `schema_version=1`, `report_id` (64 znaki hex), `agent_id`, `source`, `operation`.
   Zła koperta daje 400, a agent odkłada taki raport jako `.rejected`.
2. Odfiltrowuje połączenie agenta do własnego kolektora (inaczej raportowałby je w kółko).
3. **Deduplikacja** po `report_id` (zbiór w pamięci, odbudowywany z pliku przy starcie).
   Powtórka daje `200 duplicate`, nowy raport daje `201`.
4. Dopisuje linię JSON do `events.jsonl` z dodanymi `event_id` i `received_at`, robi `force` na dysk
   i dopiero wtedy odpowiada 2xx. Dzięki temu agent kasuje raport z kolejki dopiero po trwałym zapisie.

Reszta raportu (diffy, logi, połączenia) jest zapisywana bez interpretacji.

### API odczytu (`/api/v1/*`, bez uwierzytelniania)

| Endpoint | Zwraca |
|---|---|
| `/agents` | stan agentów: pierwszy i ostatni raport, liczba raportów. **Online** = raport nie starszy niż 90 s |
| `/events?agent_id=&source=&limit=` | zdarzenia, od najnowszych |
| `/stats` | liczniki po `source`, `operation` i `classification` |

Serwer serwuje też sam dashboard z katalogu `dashboard/`.

### Dashboard (`dashboard/app.js`)

Co 4 s pobiera `stats`, `agents` i `events`. Pokazuje karty agentów (ONLINE/OFFLINE), tabelę zdarzeń z filtrami
i po kliknięciu pełny surowy JSON raportu. Kolory zależą od klasyfikacji: czerwony dla logowań i zmian plików,
żółty dla połączeń. Dostęp tylko przez tunel SSH.

---

## Przykład: ktoś podmienia plik `Faktury/FV_003.csv`

1. Samba zapisuje plik, a inotify daje `CLOSE_WRITE`.
2. Agent kopiuje plik, liczy SHA-256 i porównuje z zapisaną kopią.
3. Powstaje raport `share/modify` z diffem, starym i nowym hashem oraz metadanymi, który trafia do `pending/`.
4. Dopiero po zapisie raportu agent aktualizuje swoją kopię pliku.
5. Wątek wysyłający wysyła raport do serwera. Serwer deduplikuje go i dopisuje do `events.jsonl`.
6. Wiersz pojawia się na dashboardzie w ciągu kilku sekund.

Kto to zrobił, z samego raportu nie wynika. Trzeba to dopasować po czasie do raportów `tcp_connection_observed` i logowań.

## Znane luki (szczegóły w `NOTATKA-dzialanie-systemu.md`, rozdz. 13)

- Odczyt lub pobranie pliku nie zostawia śladu, bo Samba nie ma włączonego audytu operacji na plikach.
- Adres IP w logach Samby (format `ipv4:A.B.C.D:port`) nie jest wyciągany. IP trzeba dopasować po czasie z raportu o połączeniu.
- Brak korelacji zdarzeń i progów (np. „20 prób logowania z jednego IP"). Ocenia analityk.
- API serwera nie ma uwierzytelniania i chroni je tylko nasłuch na `127.0.0.1`.
