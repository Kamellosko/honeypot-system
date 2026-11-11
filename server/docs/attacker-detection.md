# Wykrywanie atakującego (strona serwera)

Dokument opisuje, jak serwer rozpoznaje i klasyfikuje atakujących. Logika jest
w [`ReportStore`](../src/main/java/pl/honeypot/server/store/ReportStore.java),
wystawiona przez `GET /api/attackers`
([`AttackersHandler`](../src/main/java/pl/honeypot/server/api/AttackersHandler.java)).
Agent nie jest zmieniany — serwer korzysta z danych, które agent i tak wysyła.

## Założenie

Honeypot stoi tak, że **nikt z firmy nie ma na nim konta i nie ma powodu się z
nim łączyć**. Dlatego każde zdalne IP widziane w połączeniach lub nieudanych
logowaniach jest traktowane jako wrogie. Próg i okna czasu służą tylko do
**stopniowania**, jak bardzo wrogie.

Ruch z pętli zwrotnej (`127.0.0.0/8`, `::1`) jest pomijany — to agent, dashboard
przez tunel SSH i własne dostawy serwera, nie atakujący.

## Skąd biorą się IP atakujących

Serwer wyciąga je z raportów w `ReportStore.index(...)`:

| Źródło w raporcie | Pole | Liczone jako |
| --- | --- | --- |
| `source: network`, `tcp_connection_observed` | `connection.peer.ip` / `.mac` | połączenie |
| `classification: authentication_failure` (SSH i SMB) | `network_context.endpoints[].ip` | nieudane logowanie |

SSH i SMB trafiają do tego samego kanału `authentication_failure`, bo agent
dopasowuje w logach wzorzec „Failed password" / `NT_STATUS_LOGON_FAILURE`.

## Klasyfikacja (poziom zagrożenia)

Dla każdego IP serwer trzyma liczniki oraz dwa okna przesuwne (bufory znaczników
czasu). Przy odczycie `/api/attackers` liczy zdarzenia w oknie względem „teraz"
i nadaje poziom:

| Poziom | Warunek | Znaczenie |
| --- | --- | --- |
| `confirmed` | udane logowanie na konto z `detection.confirm.accounts` (np. `backup_srv`) | pewny atak — hasła tych kont są niezgadywalne |
| `brute_force` | ≥ 5 nieudanych logowań z tego IP w 10 min | zgadywanie haseł |
| `fast_enum` | ≥ 3 różne porty lokalne dotknięte przez to IP w 60 s | skan portów (Windows rusza tylko 445/139, więc nie wpada) |
| `suspicious` | ≥ 1 nieudane logowanie (poniżej progu) albo odczyt okruszka | warte oka |
| `contact` | tylko połączenie, zero powyższych | szum / wczesny kontakt |

Progi to stałe w `ReportStore`:

```
FAIL_WINDOW = 10 min   FAIL_THRESHOLD = 5
ENUM_WINDOW = 60 s     PORT_SCAN_THRESHOLD = 3
```

Konfigurowalne w `server.properties`:

```
detection.confirm.accounts=backup_srv         # udane logowanie = confirmed
detection.breadcrumb.marker=kopia_zapasowa.sh # odczyt pliku z tym markerem = breadcrumb_read
```

Poziom `confirmed` i flaga `breadcrumb_read` biorą się z **parsowania treści logu**
(`content`): „Accepted … for <konto> from <IP>" (udane SSH) oraz obecność markera
okruszka w linii `full_audit` (IP z `network_context`). `confirmed` nadpisuje każdy
inny poziom.

Lista jest sortowana malejąco po poziomie, a przy remisie po czasie ostatniego
zdarzenia — najgroźniejsi i najświeżsi na górze.

## Jak liczone są okna

- Każde nieudane logowanie dokłada znacznik czasu do `failTimes`, każde zdarzenie
  do `eventTimes`.
- Po dołożeniu bufor jest przycinany do długości okna (`pruneOlderThan`), więc
  nie rośnie w nieskończoność (ogranicza też pamięć).
- `/api/attackers` zlicza znaczniki nowsze niż `teraz − okno`. Stary atak sprzed
  godziny ma `failures_10m = 0` i spada do `suspicious`/`contact`, mimo że
  `auth_failures` (licznik łączny) pozostaje wysoki.

## Odpowiedź `GET /api/attackers`

```json
[
  {
    "ip": "10.13.37.66",
    "mac": "00:0c:29:ab:cd:ef",
    "threat": "brute_force",
    "first_seen": "2026-11-11T12:51:25Z",
    "last_seen": "2026-11-11T12:51:25Z",
    "connections": 0,
    "auth_failures": 5,
    "events": 5,
    "failures_10m": 5,
    "events_1m": 5,
    "distinct_ports": 1,
    "confirmed": false,
    "breadcrumb_read": false,
    "last_operation": "append"
  }
]
```

| Pole | Opis |
| --- | --- |
| `ip`, `mac` | adres atakującego; MAC tylko w jednej sieci L2, inaczej `null` |
| `threat` | poziom z tabeli wyżej |
| `connections` / `auth_failures` / `events` | liczniki łączne (od startu/odbudowy) |
| `failures_10m` / `events_1m` / `distinct_ports` | liczniki w oknie; `failures_10m` i `distinct_ports` decydują o `threat` |
| `confirmed` / `breadcrumb_read` | flagi z treści logów (udane logowanie / odczyt okruszka) |
| `first_seen` / `last_seen` / `last_operation` | kontekst czasowy |

## Trwałość

Tabela atakujących jest w pamięci, ale **odtwarza się przy starcie** z
`events.jsonl` (`ReportStore.rebuild()` odtwarza zdarzenia przez `index`), więc
restart serwera nie gubi historii. Odtwarzanie używa znaczników `received_at` z
zapisanych zdarzeń, więc okna liczą się względem rzeczywistego czasu zdarzeń.

## Ograniczenia (świadome)

- **Odczyty widać tylko, gdy włączony `full_audit`.** Agent sam wykrywa
  zapisy/zmiany, nie odczyty; `full_audit` (konfiguracja Samby) loguje otwarcia/
  odczyty jako `samba_audit`, skąd serwer rozpoznaje odczyt okruszka. Pozostałe
  odczyty trafiają do dziennika, ale nie podnoszą poziomu `threat`.
- **Zapis pliku nie ma IP.** Zdarzenia `share` nie niosą adresu klienta SMB, więc
  aktywności na plikach nie da się przypisać do konkretnego IP w tej tabeli.

## Możliwe rozszerzenia

- Różne loginy z jednego IP (`user=` z treści logu) jako osobny wskaźnik brute-force.
- Aktywność poza godzinami pracy (`received_at` poza 7–18 w dni robocze).
- Dostęp do pliku-kanarka jako osobna, pewna klasyfikacja.
- Korelacja czasowa „odczyt okruszka → logowanie `backup_srv`" jako jedna historia
  (dziś oba sygnały są osobne: `breadcrumb_read` + `confirmed`).
