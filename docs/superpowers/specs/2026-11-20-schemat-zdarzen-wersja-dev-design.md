# Etap 1: ujednolicony schemat zdarzeń, wersjonowanie, tryb `--dev`

Data: 2026-11-20. Status: **do akceptacji**. To pierwszy z czterech etapów TODO po 20 listopada
(1 schemat/wersja/dev, 2 hasła i nmap, 3 alerty e-mail, 4 podpisane wydania/autoupdate/instalator/testy/dashboard/hardening).

## 1. Po co

Dziś każdy typ raportu ma inny kształt (`connection{}` tylko dla TCP, `content_changes` tylko dla plików,
`metadata` puste dla logów). IP atakującego i nazwa użytkownika są wyciągane z surowego tekstu logu **dwa razy,
osobno**: agent heurystykami do klasyfikacji (`snapshot.c`, `hp_report_simple`), serwer regexami
(`ReportStore.firstEndpoint`, `SSH_ACCEPTED`). Każdy nowy typ zdarzenia (hasła, nmap, alerty) zwielokrotni ten problem.

Cel: **jeden stały, opisany schematem kształt zdarzenia**, oparty na znanym standardzie, żeby praca z danymi
(serwer, alerty, dashboard, eksport do cudzych narzędzi) była łatwa. Wersjonowanie i `--dev` są potrzebne
autoupdaterowi i programiście (etap 4), więc robimy je od razu.

## 2. Cele, nie-cele, anty-cele

**Cele**
- Każdy raport v2 ma blok `event` o stałych polach i stałym słowniku typów.
- Agent wyciąga IP, port, użytkownika i wynik raz; serwer tylko czyta.
- Schemat opisany plikiem JSON Schema i sprawdzany testem.
- Jedno źródło wersji dla agenta, serwera i protokołu.
- `--dev`: widoczne błędy i raporty na stderr.

**Nie-cele**
- Nie zmieniamy ani nie usuwamy starych pól (`analysis`, `connection`, `content` itd.).
- Nie dodajemy nowych zdarzeń (hasła, nmap, to etap 2) ani alertów (etap 3).
- Nie przepisujemy dashboardu (najwyżej pokazuje `event.type` i `event.severity`, jeśli to tanie).
- Pełna zgodność z ECS nie jest celem. Wzorujemy się na nazwach i dajemy tabelę mapowania do ECS.

**Anty-cele (porażka, nawet gdy działa)**
- Agent v1 przestaje być przyjmowany przez serwer.
- Agent przestaje być ukryty w produkcji (`--dev` nie może zmieniać zachowania bez flagi).
- Raport traci trwałość: zapis na dysk z `fsync` przed wysyłką zostaje bez zmian.

## 3. Ograniczenia (z kodu)

- Pole `source` to tekst (`share|log|network|system|monitor|source`), więc `source.ip` z ECS nie może leżeć na tym samym poziomie. Wszystko idzie do `event`.
- Agent celowo się ukrywa: nadpisuje `argv[0]` i kieruje stdout/stderr na `/dev/null` (`main.c:177`).
- Parser argumentów (`hp_parse_args`) akceptuje tylko pary `--flaga wartość`; `--dev` bez wartości wymaga zmiany.
- Serwer waliduje kopertę i odrzuca (400) złe raporty, a agent przenosi je do `*.rejected`. Walidacja `event` musi być ostrożna, żeby błąd schematu nie gubił zdarzeń.
- Kompilacja agenta ma `-Werror`; `AGENT_ID` itd. są wkompilowane przez `config.h`.

## 4. Podejścia (wybrane: A)

| | Opis | Wady |
|---|---|---|
| **A (wybrane)** | Blok `event` obok starych pól, `schema_version: 2`, serwer przyjmuje v1 i v2 | Agent dalej emituje stare pola, raporty są trochę większe |
| B | Pełne przejście na nazwy ECS, zmiana wszystkich pól | Przepisanie agenta, serwera i dashboardu naraz, brak zysku funkcjonalnego |
| C | Normalizacja tylko na serwerze | Logika rozbita między C i Javę; etap 2 i tak potrzebuje danych z agenta |

## 5. Projekt

### 5.1 Blok `event` (schema_version 2)

```json
"event": {
  "category": "authentication",
  "type": "auth.failure",
  "severity": "medium",
  "outcome": "failure",
  "service": "ssh",
  "src":  { "ip": "192.0.2.50", "port": 51000, "mac": "02:42:ac:11:00:05" },
  "dst":  { "ip": "10.0.0.2",   "port": 22 },
  "user": { "name": "admin" }
}
```

- `src.mac` jest w etapie 1 zawsze `null` (korekta z planu): MAC jest ustalany wewnątrz `hp_write_endpoint` i zostaje w `connection.peer.mac`; nie dublujemy wyszukiwania.
- Pola `src`, `dst`, `user`, `service` mogą być `null`, gdy nie dotyczą zdarzenia lub nie da się ich ustalić.
  Brak danych to `null`, nigdy zgadywanie.
- `outcome`: `success | failure | unknown`. `severity`: `info | low | medium | high`.
- Do koperty dochodzi `agent_version` (tekst wersji z sekcji 5.3).

### 5.2 Katalog typów (wersja 1 katalogu)

| `event.type` | `category` | Źródło w agencie | Domyślna `severity` |
|---|---|---|---|
| `file.change` (create/modify/delete/rename w `event.action`) | `file` | `snapshot.c` | `medium` (agent nie zna znacznika okruszka; podniesienie do `high` to sprawa serwera/etapu 3) |
| `net.connection` | `network` | `network.c`/`connections.c` | `low` |
| `auth.failure` | `authentication` | klasyfikacja logu | `medium` |
| `auth.success` | `authentication` | klasyfikacja logu | `high` |
| `samba.audit` | `file` | klasyfikacja logu | `low` |
| `system.heartbeat` | `system` | `heartbeat.c` | `info` |
| `system.source_unavailable`, `system.observation_gap` | `system` | `monitor.c`, `main.c` | `medium` |

Zarezerwowane na etap 2, bez implementacji teraz: `auth.attempt` (z hasłem), `net.scan`.
Typ spoza katalogu: serwer **przyjmuje i zapisuje**, oznacza `event.type_unknown=true` w statystykach. Nie odrzuca (anty-cel: gubienie zdarzeń).

Tabela mapowania do ECS (dla eksportu w przyszłości): `event.src.ip`→`source.ip`, `event.dst.port`→`destination.port`,
`event.user.name`→`user.name`, `event.category`→`event.category`, `event.type`→`event.action`, `event.outcome`→`event.outcome`.

### 5.3 Wersjonowanie

- Plik `VERSION` w korzeniu repo (semver, start `0.2.0`) jest jedynym źródłem.
- Agent: `Makefile` czyta `VERSION` i przekazuje `-DHP_VERSION`; wersja trafia do `agent_version` w każdym raporcie.
- Serwer: wersja do `pom.xml` (z `VERSION`) i endpoint `GET /api/version` → `{ "server_version", "schema_versions": [1,2] }`.
- `schema_version` to wersja kształtu raportu (1 → 2), niezależna od wersji projektu.

### 5.4 Serwer

- `ReportHandler`: dla v2 sprawdza wartości `event` (enumy, typy pól); zły `event` w v2 daje 400 jak zła koperta. v1 przechodzi jak dotąd.
- `ReportStore`: gdy jest `event.src.ip` / `event.user.name`, używa ich zamiast regexów; gdy nie ma (v1), zostają stare regexy jako fallback.
- Statystyki: dodatkowo `by_event_type`.
- Przykłady w `server/examples/` w wersji v2 oraz `docs/api.md` zaktualizowane.

### 5.5 Agent

- `snapshot.c`: wspólna funkcja zapisująca blok `event`, wywoływana ze wszystkich `hp_report_*`.
  Wyciąganie IP/portu/użytkownika z linii sshd i smbd robi się raz, w jednym pliku, z testami na prawdziwych liniach.
- Klasyfikacja logu (`Failed password`, `NT_STATUS_*`, `Accepted ...`) zostaje i zasila `event.type`.

### 5.6 Tryb `--dev`

- `--dev` jest flagą bez wartości (zmiana `hp_parse_args`).
- Z `--dev`: stderr zostaje podłączony; agent wypisuje błędy (zapis/wysyłka raportu, błędy źródeł) i jedną linię na raport (typ, `report_id`, wynik wysyłki).
- Bez `--dev` zachowanie jest identyczne jak dziś (ukrycie, brak wyjścia). Test sprawdza, że bez flagi stderr jest puste.

### 5.7 Testy

- Plik `docs/schema/event-v2.schema.json` (JSON Schema).
- Test sprawdzający przykłady i **rzeczywiste wyjście agenta** względem schematu.
- Testy C: ekstrakcja pól z prawdziwych linii sshd i smbd, `--dev` vs brak flagi.
- Test serwera: v1 przyjęty, v2 przyjęty, v2 z błędnym `event` odrzucony, nieznany `type` zapisany.

## 6. Zostawione wykonawcy (decyzje do podjęcia przy planie)

- Jakim narzędziem walidować JSON Schema w testach (biblioteka Pythona czy Javy). **Moja propozycja:** test Java po stronie serwera, bo Python nie jest dziś zależnością projektu. Do potwierdzenia przy planie.
- Dokładny format linii `--dev` na stderr.
- Czy dashboard pokazuje `event.type`/`severity` już w tym etapie (tylko jeśli zmiana jest mała).

## 7. Uczciwe zastrzeżenia

- Nie sprawdziłem pełnej listy formatów linii sshd i smbd w `monitor.c`; wyciąganie pól może wymagać rozszerzenia klasyfikacji.
- Nie czytałem `dashboard/app.js` w całości; zakładam, że dodanie pola nie psuje renderowania (czyta tylko `analysis.classification` i `evidence`).
- Numer `0.2.0` i nazwy pól to moje propozycje.
