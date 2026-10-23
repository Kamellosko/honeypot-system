# API serwera (v1)

Transport: **HTTPS** (TLS wymagany). Treść JSON (`Content-Type: application/json`).
Agent inicjuje każde połączenie i wysyła **wszystkie** raporty na jeden endpoint
(`POST /events`). Endpointy odczytu (`/api/v1/...`) służą dashboardowi.

Agent weryfikuje łańcuch TLS oraz adres/host odbiornika w SAN certyfikatu i nie da
się tego wyłączyć po stronie agenta. Certyfikat musi być zaufany przez agenta
(`SSL_CERT_FILE` lub systemowy magazyn CA), a jego SAN musi zawierać dokładnie
adres, pod który agent się łączy. Keystore i CA tworzy `scripts/gen-certs.sh`.

---

## 1. Zgłoszenie raportu (agent → serwer)

```
POST /events
```

Agent wysyła tu każdy typ raportu: zmianę pliku, rename, usunięcie, obserwację
połączenia TCP, dowód z logu oraz heartbeat. Wszystkie dzielą wspólną kopertę,
a pola specyficzne zależą od `source`/`operation`.

Wspólna koperta:

| Pole | Typ | Opis |
|------|-----|------|
| `schema_version` | int | zawsze `1` |
| `report_id` | string | 64 znaki hex (lowercase), unikalny; transmisja bywa ponawiana |
| `agent_id` | string | identyfikator agenta |
| `observed_at` | string | czas zdarzenia UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `source` | string | `share` \| `log` \| `network` \| `system` |
| `operation` | string | np. `create`, `delete`, `rename`, `downtime_change`, `tcp_connection_observed`, `observation_gap`, `heartbeat` |
| `path` | string \| null | ścieżka; `null` + `path_base64` gdy nazwa nie jest poprawnym UTF-8 |
| `analysis` | object | `{ "classification": ..., "actor": null }` |
| `complete` | bool | czy raport jest kompletny |
| `error` | string \| null | przyczyna niekompletności |

Pola zależne od typu: `metadata` (rozmiary/uprawnienia pliku), `content_changes`
(`old_sha256`/`new_sha256` + diff lub bloki base64), `evidence[]`,
`connection{}` (dla `network`), `previous_path` (dla `rename`), `content` /
`content_base64` i `network_context` (dla dowodów z logów).

Przykłady: `examples/report-*.json`. Źródłem prawdy o schemacie jest kod agenta
(`agent/src/snapshot.c`, `network.c`, `heartbeat.c`).

**Odpowiedzi**
- `201 Created` → `{"event_id": N, "report_id": "..."}` — raport zapisany.
- `200 OK` → `{"report_id": "...", "duplicate": true}` — ten `report_id` już był
  (ponowiona dostawa); nie zapisujemy drugi raz.
- `400` — błędna koperta (`schema_version`, `report_id` lub `agent_id`).

Serwer odpowiada 2xx **dopiero po zapisaniu** raportu (agent kasuje go z kolejki
po 2xx; inny kod → ponawia). Każde 2xx (także dla duplikatu) zamyka pozycję w
kolejce agenta. Serwer dokleja własne `event_id` i `received_at`.

---

## 2. Lista agentów (serwer → dashboard)

```
GET /api/v1/agents
```

Agenci wykrywani są dynamicznie z napływających raportów (brak provisioningu).

```json
[
  {
    "agent_id": "alma10-01",
    "status": "online",
    "last_seen": "2026-10-18T12:52:09Z",
    "first_seen": "2026-10-18T12:50:00Z",
    "total_reports": 42,
    "last_source": "share",
    "last_operation": "create",
    "last_classification": "file_change"
  }
]
```

`status` to `online`, gdy ostatni raport dotarł w ciągu 90 s, inaczej `offline`.

---

## 3. Dziennik zdarzeń (serwer → dashboard)

```
GET /api/v1/events
```

Zwraca zapisane raporty, najnowsze pierwsze. Parametry (opcjonalne):

| Parametr | Opis |
|----------|------|
| `agent_id` | filtr po agencie |
| `source` | filtr po `source` (`share`/`log`/`network`/`system`) |
| `limit` | ogranicza do N najnowszych (≥ 1) |

Każdy element to pełny raport agenta wzbogacony o `event_id` i `received_at`.

---

## 4. Statystyki (serwer → dashboard)

```
GET /api/v1/stats
```

```json
{
  "total_events": 42,
  "total_agents": 1,
  "online_agents": 1,
  "by_source": { "share": 30, "network": 8, "system": 4 },
  "by_classification": { "file_change": 25, "tcp_connection": 8 },
  "by_operation": { "create": 20, "heartbeat": 4 }
}
```

---

## Uwagi

- **MAC przechodzi tylko w obrębie jednej sieci L2.** Dla atakującego zza routera
  agent zobaczy MAC bramy lub nic; w raportach połączeń `peer.mac` bywa `null`
  z `mac_status` wyjaśniającym powód. `src_ip`/`peer.ip` jest wiarygodniejsze.
- Raporty mogą zawierać treść plików i logów — zabezpiecz serwer i `data/`.
- Deduplikacja po `report_id` jest po stronie serwera; agent może słać duplikaty.
