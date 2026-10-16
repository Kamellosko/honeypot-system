# API serwera (v1)

Transport: HTTP, treść JSON (`Content-Type: application/json`). Wszystkie połączenia
inicjuje agent. Prefiks ścieżek: `/api/v1`.

Sensor musi wcześniej istnieć w tabeli `sensors`. Nieznany `sensor_id` daje `404`.

---

## 1. Pobranie konfiguracji

Agent wysyła to zapytanie przy starcie, zanim otworzy porty-wabiki.

```
GET /api/v1/config/{sensor_id}
```

**200 OK**
```json
{
  "sensor_id": "sensor-01",
  "port_count": 4,
  "timeout_sec": 5,
  "heartbeat_sec": 30,
  "srv_port": 8000,
  "ports": "22,23,80,2222"
}
```

| Pole | Typ | Opis |
|------|-----|------|
| `sensor_id` | string | ID honeypota |
| `port_count` | int | liczba portów w `ports`, przydatna do alokacji tablicy w C |
| `timeout_sec` | int | timeout gniazda (`SO_RCVTIMEO`) |
| `heartbeat_sec` | int | interwał heartbeatu |
| `srv_port` | int | port serwera, na który agent wysyła raporty |
| `ports` | string | numery portów-wabików oddzielone przecinkami, bez spacji, rosnąco |

**404** – nieznany sensor.

---

## 2. Zgłoszenie próby połączenia

```
POST /api/v1/events
```

```json
{
  "sensor_id": "sensor-01",
  "state": "handling_conn",
  "mac": "02:42:ac:12:00:05",
  "src_ip": "172.18.0.5"
}
```

| Pole | Typ | Wymagane | Opis |
|------|-----|:--------:|------|
| `sensor_id` | string | tak | ID honeypota |
| `state` | string | tak | stan agenta: `init`, `idle`, `handling_conn`, `shutdown`, `error` |
| `mac` | string \| null | nie | MAC atakującego, `aa:bb:cc:dd:ee:ff` (wielkość liter dowolna) |
| `src_ip` | string \| null | nie (zalecane) | IP atakującego |

**201 Created** → `{"event_id": 42}`
**400** – błędne pole. **404** – nieznany sensor.

Serwer sam nadaje czas odbioru (`received_at`).

---

## 3. Heartbeat

Agent wysyła go co `heartbeat_sec` sekund (z konfiguracji).

```
POST /api/v1/heartbeat
```

```json
{
  "sensor_id": "sensor-01",
  "events_since_last": 0,
  "uptime_sec": 86400
}
```

| Pole | Typ | Wymagane | Opis |
|------|-----|:--------:|------|
| `sensor_id` | string | tak | ID honeypota |
| `events_since_last` | int | tak | liczba zdarzeń od poprzedniego heartbeatu (≥ 0) |
| `uptime_sec` | int | tak | czas działania agenta w sekundach (≥ 0) |

**204 No Content**, bez treści.
**400** – błędne pole. **404** – nieznany sensor.

Serwer zapisuje wiersz w `heartbeats` i odświeża `sensors.last_seen` oraz `status = online`.

---

## 4. Raport błędu

Drugi typ wiadomości od agenta — zgłoszenie usterki (odpowiada stanowi `STATE_ERROR`).

```
POST /api/v1/errors
```

```json
{
  "sensor_id": "sensor-01",
  "state": "error",
  "error_id": 2
}
```

| Pole | Typ | Wymagane | Opis |
|------|-----|:--------:|------|
| `sensor_id` | string | tak | ID honeypota |
| `state` | string | tak | stan agenta w chwili błędu (ten sam zbiór co w zdarzeniu) |
| `error_id` | int | tak | kod błędu nadawany przez agenta (katalog do ustalenia z osobą A) |

**201 Created** → `{"report_id": 7}`
**400** – błędne pole. **404** – nieznany sensor.

---

## Planowane (kolejne fazy)

| Endpoint | Faza | Opis |
|----------|------|------|
| `GET /api/v1/sensors` | 1 | dla dashboardu: lista sensorów, `status`, `last_seen` |
| `GET /api/v1/events` | 1 | dla dashboardu: oś czasu zdarzeń |
| `GET /api/v1/ioc` | 3 | lista blokad dla agenta |

---

## Uwagi

- **MAC przechodzi tylko w obrębie jednej sieci L2.** Gdy atakujący jest za routerem, czyli
  w każdym ataku z internetu, agent zobaczy MAC routera lub bramy, a nie atakującego. Dlatego
  `mac` jest opcjonalne, a `src_ip` zalecane. W labie dockerowym (jedna sieć bridge) MAC będzie
  prawdziwy. Agent może go odczytać z `/proc/net/arp` po IP z `getpeername()`.
- `GET /config` zastępuje `POST /register` z `projekt_honeypot.md`. Pobranie konfiguracji
  oznacza sensor jako `online`.
