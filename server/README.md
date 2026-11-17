# Serwer (kolektor + dashboard)

Odbiornik raportów honeypota: przyjmuje raporty agenta C po **HTTPS** (`POST /events`), zapisuje je do
`events.jsonl` (deduplikacja po `report_id`) i udostępnia dashboardowi widoki tylko do odczytu pod `/api/v1/*`.
Serwuje też sam dashboard z katalogu `../dashboard` (ten sam origin, bez CORS). Agenci są wykrywani
z napływających raportów, nie trzeba ich rejestrować.

Domyślnie serwer nasłuchuje **tylko na `127.0.0.1:8443`**: agent i serwer działają na tej samej maszynie,
a dashboard ogląda się przez tunel SSH. Pełna instalacja na AlmaLinux: [`../INSTALL.md`](../INSTALL.md).

## Wymagania

JDK 21, Maven, `openssl` (certyfikaty).

## Uruchomienie lokalne

```sh
cd server
mvn -DskipTests package                    # -> target/honeypot-server.jar
./scripts/gen-certs.sh                     # -> certs/server-keystore.p12 i certs/ca.crt (SAN: IP:127.0.0.1)
java -jar target/honeypot-server.jar config/server.properties
```

Dashboard: `https://127.0.0.1:8443/` (przeglądarka ostrzeże o własnym CA; zaakceptuj albo zaimportuj `certs/ca.crt`).

Szybki test bez agenta:

```sh
curl --cacert certs/ca.crt -X POST https://127.0.0.1:8443/events \
  -H 'Content-Type: application/json' --data @examples/report-file-change.json
curl --cacert certs/ca.crt https://127.0.0.1:8443/api/v1/stats
```

Agent weryfikuje TLS i nie da się tego wyłączyć, więc musi ufać CA serwera, a adres, pod który się łączy,
musi być w SAN certyfikatu (`./scripts/gen-certs.sh IP:<adres>`). Instalator agenta (`scripts/install-agent-service.sh`)
dodaje CA do magazynu zaufania systemu.

## Konfiguracja (`config/server.properties`)

| Klucz | Znaczenie |
|-------|-----------|
| `server.bind`, `server.port` | adres i port nasłuchu (domyślnie `127.0.0.1:8443`) |
| `server.keystore` | PKCS12 z certyfikatem i kluczem serwera (z `gen-certs.sh`) |
| `server.keystore.password` | hasło keystore (domyślnie `changeit`; zmień przy wdrożeniu) |
| `data.dir` | katalog logu `events.jsonl` |
| `dashboard.dir` | katalog dashboardu do serwowania; pusty lub brak = nie serwuj |

Aby serwer był osiągalny z innej maszyny, ustaw `server.bind=0.0.0.0` i otwórz port w zaporze. Uwaga: API
nie ma uwierzytelniania, więc nie rób tego poza odizolowaną siecią.

## Endpointy

Pełny opis: [`docs/api.md`](docs/api.md). Skrót:

- `POST /events`: agent wysyła tu każdy raport (`schema_version` 1),
- `GET /api/v1/agents`: agenci i stan online,
- `GET /api/v1/events?agent_id=&source=&limit=`: zdarzenia, najnowsze pierwsze (domyślnie 100, maks. 1000),
- `GET /api/v1/stats`: liczniki zbiorcze.
