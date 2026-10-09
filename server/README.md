# honeypot-server

Centralny serwer (kolektor + REST API) w Javie 21. Używa Javalin i SQLite.
Kontrakt API jest w [docs/api.md](docs/api.md).

## Struktura

```
server/
├── pom.xml                         # Maven, buduje target/honeypot-server.jar
├── Dockerfile                      # build na Maven, runtime na almalinux:9
├── config/server.properties        # port, ścieżka bazy, seed
├── deploy/honeypot-server.service  # unit systemd (instalacja na Linuksie)
├── docs/api.md                     # kontrakt agent ↔ serwer
├── examples/                       # przykładowe JSON-y do testów curl
└── src/
    ├── main/java/pl/honeypot/server/
    │   ├── Main.java               # start, routing
    │   ├── ServerConfig.java
    │   ├── api/                    # handlery HTTP
    │   ├── db/                     # połączenie SQLite + repozytoria
    │   └── model/                  # rekordy JSON
    ├── main/resources/db/
    │   ├── schema.sql              # schemat bazy (idempotentny, uruchamiany przy starcie)
    │   └── seed.sql                # sensor-01 do developmentu
    └── test/java/...
```

## Budowanie i uruchomienie

Wymagane: JDK 21 i Maven (AlmaLinux: `dnf install java-21-openjdk-devel maven`).

```bash
mvn package
java -jar target/honeypot-server.jar config/server.properties
```

## Test ręczny

```bash
curl -s localhost:8000/api/v1/config/sensor-01
curl -s -X POST localhost:8000/api/v1/events \
     -H 'Content-Type: application/json' -d @examples/attack-report.json
curl -s -X POST localhost:8000/api/v1/heartbeat \
     -H 'Content-Type: application/json' -d @examples/heartbeat.json -w '%{http_code}\n'
```
