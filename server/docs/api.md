# API serwera

Transport: **HTTPS** (TLS 1.2+), treść JSON. Serwer nasłuchuje
na `127.0.0.1:8443`; z zewnątrz tylko przez tunel SSH. Agent wysyła **wszystkie** raporty na
`POST /events` (ten sam odbiornik także jako `POST /api/events`), endpointy `GET /api/...` służą dashboardowi. API **nie ma uwierzytelniania**
(ochrona: bind na loopbacku i uprawnienia plików); każdy lokalny użytkownik, który zobaczy port,
może czytać dane i wysyłać raporty.

Agent weryfikuje łańcuch TLS i adres w SAN certyfikatu (nie da się tego wyłączyć). Certyfikat
tworzy `server/scripts/gen-certs.sh` (SAN domyślnie `IP:127.0.0.1`), a CA musi być w magazynie
zaufania systemu (`/etc/pki/ca-trust/source/anchors/sysmon-ca.crt`).

## 1. Zgłoszenie raportu (agent → serwer)

```
POST /events        Content-Type: application/json        (do 64 MB)
```

Wspólna koperta:

| Pole | Typ | Opis |
|------|-----|------|
| `schema_version` | int | `1` (stary agent) lub `2` (obecny); serwer przyjmuje oba |
| `report_id` | string | 64 znaki hex (lowercase), unikalny; transmisja bywa ponawiana |
| `agent_id` | string | `[A-Za-z0-9._-]`, 1–64 znaków |
| `observed_at` | string | czas zdarzenia UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `source` | string | `share` \| `log` \| `network` \| `system` \| `monitor` \| `source` |
| `operation` | string | `[a-z0-9_]`, 1–64 znaków, np. `create_delete`, `append`, `tcp_connection_observed`, `observation_gap`, `heartbeat` |
| `path` | string \| null | ścieżka; `null` + `path_base64` gdy nazwa nie jest poprawnym UTF-8 |
| `analysis` | object | `{ "classification": ..., "actor": null }` |
| `complete` | bool | czy raport jest kompletny |
| `error` | string \| null | przyczyna niekompletności |
| `agent_version` | string | tylko v2: wersja agenta (plik `VERSION`) |
| `event` | object | tylko v2: ustandaryzowany opis zdarzenia, patrz niżej |

Blok `event` (v2; schemat: [`docs/schema/event-v2.schema.json`](../../docs/schema/event-v2.schema.json), pola zbliżone do ECS):

| Pole | Opis |
|------|------|
| `category`, `type` | `[A-Za-z0-9_.-]{1,64}`, np. `authentication` / `authentication_failure` |
| `severity` | `info` \| `low` \| `medium` \| `high` |
| `outcome` | `success` \| `failure` \| `unknown` |
| `service`, `action` | string lub `null` |
| `src`, `dst` | `{ip, port, mac}`; `mac` jest zawsze `null` (etap 1) |
| `user` | `null` albo `{ "name": ... }` |
| `credential` | `null` albo `{ "password": tekst\|null, "password_base64": tekst }` (0.3.0, tylko `auth.attempt`; hasło nie-UTF-8 idzie w `password_base64`, `password` jest wtedy `null`; limit 1024 znaków) |
| `detail` | `null` albo `{ "ports": int>=1, "scan": nazwa, "window_seconds": int>=1 }` (0.3.0, tylko `net.scan`) |

**Typy dodane w 0.3.0 (etap 2).** `auth.attempt` (`authentication`, `medium`, `failure`, `service: ssh`): próbowane hasło SSH
z hooka PAM; zawsze towarzyszy mu zwykłe `auth.failure` z logu `sshd` (dwa niezależne źródła, serwer nie liczy prób
podwójnie). `net.scan` (`network`, `medium`, `unknown`, `src.ip` ustawione, `dst.port` `null`): agent zgłasza skan, gdy jedno
źródło dotknie co najmniej 10 różnych zamkniętych portów w 10 s (rodzaj w `detail.scan`: `syn`, `null`, `xmas`, `fin`, `other`).
Serwer oznacza takie źródło w `/api/attackers` jako `fast_enum` (flaga trwała, nie okienkowa).
**Hasła są zapisywane jawnie** (`credential.password`, a także w surowej treści logu); zabezpiecz magazyn tak jak raporty z treścią plików.

Stare pola (`analysis.classification` itd.) zostają obok `event`. Serwer waliduje `event` w raportach v2 (zły blok → `400`)
i liczy zdarzenia po `event.type` (`by_event_type` w `/api/stats`).

Pola zależne od typu: `metadata`, `content_changes`, `evidence[]`, `connection{}`,
`previous_path`, `content` / `content_base64`, `network_context`. Przykłady: `examples/report-*.json`.
Źródłem prawdy o schemacie jest kod agenta (`agent/src/snapshot.c`, `network.c`, `heartbeat.c`).

**Odpowiedzi**

| Kod | Treść | Znaczenie dla agenta |
|-----|-------|----------------------|
| `201` | `{"event_id": N, "report_id": "..."}` | zapisany (na dysku, `fsync`) — agent kasuje z kolejki |
| `200` | `{"report_id": "...", "duplicate": true}` | ten `report_id` już był — agent kasuje |
| `200` | `{"report_id": "...", "ignored": true}` | własne połączenie agenta z serwerem na loopbacku (zapobiega pętli zwrotnej); nie zapisano — agent kasuje |
| `400` | błąd | zły JSON albo zła koperta (`schema_version`, `report_id`, `agent_id`, `source`, `operation`, `analysis.classification` `[A-Za-z0-9_.-]`, 1–64 znaki) albo więcej niż 1000 różnych `agent_id` — agent **przenosi raport do `*.rejected`** i wysyła następne |
| `413` | błąd | raport > 64 MB — jak wyżej |
| `5xx` | błąd | chwilowy problem — agent ponawia ten sam raport |

Serwer odpowiada 2xx dopiero po zapisie. Przy błędzie zapisu (np. brak miejsca) odpowiada 500 i **nie**
zapamiętuje `report_id`, więc ponowna wysyłka zostanie zapisana. Serwer dokleja `event_id` i `received_at`
(czas serwera; używany też do oceny, czy agent jest `online`).

## 2. Lista agentów (serwer → dashboard)

```
GET /api/agents
```

Agenci wykrywani są dynamicznie z raportów. `status` to `online`, gdy ostatni raport dotarł w ciągu 90 s,
inaczej `offline`. Pola: `agent_id`, `status`, `last_seen`, `first_seen`, `total_reports`,
`last_source`, `last_operation`, `last_classification`.

## 3. Dziennik zdarzeń (serwer → dashboard)

```
GET /api/events?agent_id=&source=&limit=
```

Najnowsze pierwsze; `limit` ≥ 1, domyślnie 100, maksymalnie 1000 (większa wartość jest obcinana do 1000).
Każdy element to pełny raport z `event_id` i `received_at`. Serwer czyta plik zdarzeń od końca i
zatrzymuje się po `limit` pasujących raportach, więc koszt nie zależy od rozmiaru całego pliku.

## 4. Statystyki (serwer → dashboard)

```
GET /api/stats
```

Pola: `total_events`, `total_agents`, `online_agents`, `by_source`, `by_classification`, `by_operation`.
W `by_classification` i `by_operation` jest najwyżej 200 różnych kluczy, dalsze nowe wartości liczą się pod `other`.

## 5. Wykryci atakujący (serwer → dashboard)

```
GET /api/attackers
```

Zdalne IP z połączeń TCP i nieudanych logowań, stopniowane po zachowaniu: `contact` → `suspicious` →
`fast_enum` (≥ 3 różne porty z jednego IP w 60 s) → `brute_force` (≥ 5 nieudanych logowań w 10 min) →
`confirmed` (udane logowanie na konto z `detection.confirm.accounts`). Loopback jest pomijany.
Pola: `ip`, `mac`, `threat`, `first_seen`, `last_seen`, `connections`, `auth_failures`, `events`,
`failures_10m`, `events_1m`, `distinct_ports`, `confirmed`, `breadcrumb_read`, `last_operation`.
Szczegóły i progi: [`attacker-detection.md`](attacker-detection.md).

## 6. Wersja (GET /api/version)

`{"server_version": "...", "schema_versions": [1, 2]}`: wersja serwera i wersje schematu, które przyjmuje.

## Uwagi

- Pliki zdarzeń: `/var/lib/sysmon/events.jsonl` (`0600`). Zawierają treść plików i logów.
- **MAC przechodzi tylko w obrębie jednej sieci L2.** Dla napastnika zza routera `peer.mac` bywa `null`
  z `mac_status` wyjaśniającym powód.
- Deduplikacja po `report_id` jest po stronie serwera; agent może słać duplikaty.
