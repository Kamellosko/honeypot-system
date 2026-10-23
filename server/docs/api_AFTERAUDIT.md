# API serwera (v1) — wersja po audycie

Zastępuje [api.md](api.md). Transport: **HTTPS** (TLS 1.2+), treść JSON. Serwer nasłuchuje
na `127.0.0.1:8443`; z zewnątrz tylko przez tunel SSH. Agent wysyła **wszystkie** raporty na
`POST /events`, endpointy `GET /api/v1/...` służą dashboardowi. API **nie ma uwierzytelniania**
(ochrona: bind na loopbacku i uprawnienia plików); każdy lokalny użytkownik, który zobaczy port,
może czytać dane i wysyłać raporty.

Agent weryfikuje łańcuch TLS i adres w SAN certyfikatu (nie da się tego wyłączyć). Certyfikat
tworzy `server/scripts/gen-certs.sh` (SAN domyślnie `IP:127.0.0.1`), a CA musi być w magazynie
zaufania systemu (`/etc/pki/ca-trust/source/anchors/sysmon-ca.crt`).

## 1. Zgłoszenie raportu (agent → serwer)

```
POST /events        Content-Type: application/json        (do 32 MB)
```

Wspólna koperta:

| Pole | Typ | Opis |
|------|-----|------|
| `schema_version` | int | zawsze `1` |
| `report_id` | string | 64 znaki hex (lowercase), unikalny; transmisja bywa ponawiana |
| `agent_id` | string | `[A-Za-z0-9._-]`, 1–64 znaków |
| `observed_at` | string | czas zdarzenia UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `source` | string | `share` \| `log` \| `network` \| `system` \| `monitor` \| `source` |
| `operation` | string | `[a-z0-9_]`, 1–64 znaków, np. `create_delete`, `append`, `tcp_connection_observed`, `observation_gap`, `heartbeat` |
| `path` | string \| null | ścieżka; `null` + `path_base64` gdy nazwa nie jest poprawnym UTF-8 |
| `analysis` | object | `{ "classification": ..., "actor": null }` |
| `complete` | bool | czy raport jest kompletny |
| `error` | string \| null | przyczyna niekompletności |

Pola zależne od typu: `metadata`, `content_changes`, `evidence[]`, `connection{}`,
`previous_path`, `content` / `content_base64`, `network_context`. Przykłady: `examples/report-*.json`.
Źródłem prawdy o schemacie jest kod agenta (`agent/src/snapshot.c`, `network.c`, `heartbeat.c`).

**Odpowiedzi**

| Kod | Treść | Znaczenie dla agenta |
|-----|-------|----------------------|
| `201` | `{"event_id": N, "report_id": "..."}` | zapisany (na dysku, `fsync`) — agent kasuje z kolejki |
| `200` | `{"report_id": "...", "duplicate": true}` | ten `report_id` już był — agent kasuje |
| `200` | `{"report_id": "...", "ignored": true}` | własne połączenie agenta z serwerem na loopbacku (zapobiega pętli zwrotnej); nie zapisano — agent kasuje |
| `400` | błąd | zła koperta (`schema_version`, `report_id`, `agent_id`, `source`, `operation`) — agent **przenosi raport do `*.rejected`** i wysyła następne |
| `413` | błąd | raport > 32 MB — jak wyżej |
| `5xx` | błąd | chwilowy problem — agent ponawia ten sam raport |

Serwer odpowiada 2xx dopiero po zapisie. Przy błędzie zapisu (np. brak miejsca) odpowiada 500 i **nie**
zapamiętuje `report_id`, więc ponowna wysyłka zostanie zapisana. Serwer dokleja `event_id` i `received_at`
(czas serwera; używany też do oceny, czy agent jest `online`).

## 2. Lista agentów (serwer → dashboard)

```
GET /api/v1/agents
```

Agenci wykrywani są dynamicznie z raportów. `status` to `online`, gdy ostatni raport dotarł w ciągu 90 s,
inaczej `offline`. Pola: `agent_id`, `status`, `last_seen`, `first_seen`, `total_reports`,
`last_source`, `last_operation`, `last_classification`.

## 3. Dziennik zdarzeń (serwer → dashboard)

```
GET /api/v1/events?agent_id=&source=&limit=
```

Najnowsze pierwsze; `limit` ≥ 1 (dashboard domyślnie wysyła 100). Każdy element to pełny raport
z `event_id` i `received_at`. Uwaga: serwer czyta cały plik zdarzeń przy każdym zapytaniu
(odczyt nie blokuje zapisu, ale czas i pamięć rosną z rozmiarem pliku).

## 4. Statystyki (serwer → dashboard)

```
GET /api/v1/stats
```

Pola: `total_events`, `total_agents`, `online_agents`, `by_source`, `by_classification`, `by_operation`.

## Uwagi

- Pliki zdarzeń: `/var/lib/sysmon/events.jsonl` (`0600`). Zawierają treść plików i logów.
- **MAC przechodzi tylko w obrębie jednej sieci L2.** Dla napastnika zza routera `peer.mac` bywa `null`
  z `mac_status` wyjaśniającym powód.
- Deduplikacja po `report_id` jest po stronie serwera; agent może słać duplikaty.
