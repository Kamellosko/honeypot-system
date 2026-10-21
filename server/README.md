# Honeypot server (collector + dashboard)

Odbiornik raportów honeypota: przyjmuje raporty agenta C po **HTTPS**
(`POST /events`), zapisuje je do `data/events.jsonl` (deduplikacja po
`report_id`) i udostępnia dashboardowi widoki tylko do odczytu pod `/api/v1/*`.
Może też serwować sam dashboard z katalogu `../dashboard` (ten sam origin, bez
CORS).

Agenci wykrywani są dynamicznie z napływających raportów — nie trzeba ich
wcześniej rejestrować.

## Wymagania

- JDK 21, Maven, `openssl` (do certyfikatów).

## Uruchomienie lokalne (bez Dockera)

```sh
cd server

# 1. Zbuduj serwer
mvn -o -DskipTests package        # -> target/honeypot-server.jar

# 2. Wygeneruj CA + certyfikat serwera (SAN = adres, pod który łączy się agent).
#    Domyślnie IP:127.0.0.1 (zgodny z domyślnym DEST_IP agenta).
./scripts/gen-certs.sh            # -> certs/server-keystore.p12 i certs/ca.crt

# 3. Start (HTTPS na 0.0.0.0:8443, dashboard na /)
java -jar target/honeypot-server.jar config/server.properties
```

Dashboard: otwórz `https://127.0.0.1:8443/` (przeglądarka ostrzeże o
self-signed — zaakceptuj, albo zaimportuj `certs/ca.crt` jako zaufany).

Szybki test bez agenta:

```sh
curl --cacert certs/ca.crt -X POST https://127.0.0.1:8443/events \
  -H 'Content-Type: application/json' \
  --data @examples/report-file-change.json
curl --cacert certs/ca.crt https://127.0.0.1:8443/api/v1/stats
```

## Uruchomienie agenta (kod C bez zmian)

Agent weryfikuje TLS i nie pozwala tego wyłączyć, więc musi zaufać naszemu CA.
Produkcyjny agent używa domyślnego magazynu libcurl/OpenSSL — wskaż mu nasz CA
zmienną `SSL_CERT_FILE` (bez roota, bez zmian w agencie):

```sh
cd ../agent
make
SSL_CERT_FILE=../server/certs/ca.crt ./build/honeypot --ip 127.0.0.1 --port 8443
```

Dla innego hosta: wygeneruj cert z właściwym SAN
(`./scripts/gen-certs.sh IP:192.0.2.10`) i uruchom agenta z `--ip 192.0.2.10`.

## Topologia wielomaszynowa (M1 serwer+dashboard, M2 agent+honeypot, M3 Kali)

Kod się nie zmienia — serwer i tak nasłuchuje na `0.0.0.0`, a dashboard używa
tego samego origin. Dostroić trzeba tylko certy i adresy.

Założenie: `M1 = 10.0.0.1` (serwer), `M2 = 10.0.0.2` (agent + Samba),
`M3` = Kali (atakujący). Podstaw własne adresy.

**M1 — serwer + dashboard**

```sh
cd server
mvn -o -DskipTests package
# SAN MUSI zawierać adres M1 widziany z M2. Dodaj 127.0.0.1, jeśli chcesz też
# otwierać dashboard lokalnie na M1.
./scripts/gen-certs.sh IP:10.0.0.1 IP:127.0.0.1
# otwórz port w firewallu (przykład firewalld / AlmaLinux):
sudo firewall-cmd --add-port=8443/tcp --permanent && sudo firewall-cmd --reload
java -jar target/honeypot-server.jar config/server.properties
```

Skopiuj `server/certs/ca.crt` na M2 (scp/pendrive) — agent musi mu zaufać.
Dashboard: `https://10.0.0.1:8443/` z dowolnej maszyny (zaakceptuj self-signed
lub zaimportuj `ca.crt`).

**M2 — agent + honeypot Samba**

```sh
# ca.crt przeniesione z M1, np. do /etc/honeypot/ca.crt
cd agent && make
SSL_CERT_FILE=/etc/honeypot/ca.crt ./build/honeypot --ip 10.0.0.1 --port 8443
```

Agent monitoruje lokalne udziały Samby i logi na M2 i raportuje do M1. Upewnij
się, że Samba działa i jest osiągalna z M3.

**M3 — Kali (test)**

Uderzaj w honeypot na M2, żeby wygenerować zdarzenia, np.:

```sh
smbclient -L //10.0.0.2 -N                    # enumeracja → połączenie TCP
smbclient //10.0.0.2/public -N -c 'put plik'  # zapis → zmiana pliku
# próby logowania ze złym hasłem → authentication_failure w logach Samby
```

Zdarzenia pojawią się w dashboardzie na M1 (karta agenta „online”, wiersze w
dzienniku: `network/tcp_connection_observed`, `share/create`, `log/...`).

## Konfiguracja (`config/server.properties`)

| Klucz | Znaczenie |
|-------|-----------|
| `server.bind`, `server.port` | adres i port nasłuchu (domyślnie `0.0.0.0:8443`) |
| `server.keystore` | PKCS12 z certem/kluczem serwera (z `gen-certs.sh`) |
| `server.keystore.password` | hasło do keystore (domyślnie `changeit`) |
| `data.dir` | katalog logu `events.jsonl` |
| `dashboard.dir` | katalog dashboardu do serwowania; pusty/brak = nie serwuj |

## Endpointy

Pełny opis: [`docs/api.md`](docs/api.md). Skrót:

- `POST /events` — agent wysyła tu każdy raport (schema_version 1).
- `GET /api/v1/agents` — agenci + liveness.
- `GET /api/v1/events?agent_id=&source=&limit=` — zdarzenia, najnowsze pierwsze.
- `GET /api/v1/stats` — liczniki zbiorcze.
