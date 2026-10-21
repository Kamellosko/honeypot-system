# Instrukcja instalacji — Honeypot System

System składa się z trzech komponentów:

| Komponent | Katalog | Rola |
| --- | --- | --- |
| **Agent** | `agent/` | usługa C na honeypocie: monitoruje udziały i logi Samby, wysyła raporty po HTTPS. Kod gotowy — nie modyfikujemy. |
| **Serwer** | `server/` | odbiornik Java (Javalin): przyjmuje raporty (`POST /events`), zapisuje do `events.jsonl`, udostępnia API `/api/v1/*`, serwuje dashboard. |
| **Dashboard** | `dashboard/` | statyczny panel SOC (HTML/JS), serwowany przez serwer z tego samego origin. |

Transport agent → serwer to **HTTPS z weryfikacją certyfikatu**: agent sprawdza
łańcuch TLS i adres odbiornika w SAN certyfikatu i nie da się tego wyłączyć po
jego stronie. Dlatego serwer zawsze działa po TLS, a honeypot musi ufać CA, który
podpisał certyfikat serwera.

Docelowa topologia (2 maszyny AlmaLinux 9.8):

- **S** — serwer + dashboard,
- **H** — honeypot: Samba (udziały-wabiki) + agent,
- opcjonalnie **atakujący** (np. Kali) uderzający w Sambę na H.

Łączność: `H → S` na TCP **8443** (raporty), `atakujący → H` na TCP **445**
(SMB), przeglądarka → `S:8443` (dashboard).

---

## 1. Szybki start lokalnie (jedna maszyna, do testów)

Bez Dockera, wszystko na `127.0.0.1`. Wymaga JDK 21, Maven, `openssl`.

```sh
cd server
mvn -o -DskipTests package                 # -> target/honeypot-server.jar
./scripts/gen-certs.sh                      # CA + keystore, SAN = 127.0.0.1
java -jar target/honeypot-server.jar config/server.properties
```

Serwer wstaje na `https://127.0.0.1:8443/` i serwuje tam dashboard (certyfikat
self-signed — zaakceptuj w przeglądarce lub zaimportuj `server/certs/ca.crt`).

Test bez agenta:

```sh
curl --cacert certs/ca.crt -X POST https://127.0.0.1:8443/events \
  -H 'Content-Type: application/json' --data @examples/report-file-change.json
curl --cacert certs/ca.crt https://127.0.0.1:8443/api/v1/stats
```

Więcej szczegółów: [`server/README.md`](server/README.md),
API: [`server/docs/api.md`](server/docs/api.md).

---

## 2. Wdrożenie produkcyjne na 2 maszynach (AlmaLinux 9.8)

Ustaw raz zmienne (podstaw własne adresy) — używane w komendach niżej:

```sh
SERVER_IP=10.0.0.10      # adres S widziany z H  (trafia do SAN certyfikatu)
HONEYPOT_IP=10.0.0.20    # adres H (Samba)
AGENT_ID=alma9-hp-01     # dowolny identyfikator honeypota
```

### 2A. Maszyna S — serwer + dashboard

**Pakiety i kod**

```sh
sudo dnf install -y java-21-openjdk-headless maven git openssl
git clone <repo> /opt/src/honeypot-system        # albo skopiuj server/ i dashboard/
cd /opt/src/honeypot-system/server
```

**Build** (upewnij się, że toolchain to JDK 21 — Maven na Almie 9 bywa z JDK 17):

```sh
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
java -version                                     # musi pokazać 21
mvn -DskipTests package                           # -> target/honeypot-server.jar
```

Jar wymaga JRE 21. Jeśli `/usr/bin/java` wskazuje inną wersję, przełącz
`alternatives --config java` albo użyj pełnej ścieżki w unicie
(`/usr/lib/jvm/java-21-openjdk/bin/java`).

**Certyfikat** (SAN = adres S, pod który łączy się H):

```sh
./scripts/gen-certs.sh IP:$SERVER_IP IP:127.0.0.1
# -> certs/server-keystore.p12 (dla Javy), certs/ca.crt (zaufanie dla H)
```

**Rozłożenie plików i użytkownik usługi**

```sh
sudo useradd --system --no-create-home --shell /sbin/nologin honeypot

sudo install -d -o root -g root /opt/honeypot-server
sudo install -m 644 target/honeypot-server.jar /opt/honeypot-server/honeypot-server.jar
sudo cp -r ../dashboard /opt/honeypot-server/dashboard

sudo install -d -o root -g root /etc/honeypot-server
sudo install -m 600 -o honeypot -g honeypot certs/server-keystore.p12 \
     /etc/honeypot-server/server-keystore.p12

sudo tee /etc/honeypot-server/server.properties >/dev/null <<EOF
server.bind=0.0.0.0
server.port=8443
server.keystore=/etc/honeypot-server/server-keystore.p12
server.keystore.password=changeit
data.dir=/var/lib/honeypot-server
dashboard.dir=/opt/honeypot-server/dashboard
EOF
```

> Zmień `changeit`, jeśli generowałeś keystore z `KEYSTORE_PASSWORD=...`.

**Usługa systemd**

```sh
sudo cp deploy/honeypot-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-server
systemctl status honeypot-server
```

Jednostka działa jako `honeypot` i tworzy `/var/lib/honeypot-server`
(`events.jsonl`).

**Firewall i (ewentualnie) SELinux**

```sh
sudo firewall-cmd --add-port=8443/tcp --permanent && sudo firewall-cmd --reload
```

Jeśli w logu usługi jest odmowa bindowania portu (SELinux):

```sh
sudo dnf install -y policycoreutils-python-utils
sudo semanage port -a -t http_port_t -p tcp 8443     # lub -m, jeśli już etykietowany
sudo systemctl restart honeypot-server
```

**Test i przekazanie CA na H**

```sh
curl --cacert certs/ca.crt https://$SERVER_IP:8443/api/v1/stats    # -> JSON
scp certs/ca.crt root@$HONEYPOT_IP:/root/honeypot-ca.crt
```

### 2B. Maszyna H — Samba honeypot + agent

**Repozytorium CRB + pakiety** (`libtdb-devel` jest w CRB):

```sh
sudo dnf config-manager --set-enabled crb
sudo dnf install -y gcc make binutils libcurl-devel openssl-devel libtdb-devel \
     samba samba-common ca-certificates python3 openssl policycoreutils-python-utils git
```

**Udział-wabik Samby**

> Skrót: zamiast wklejać poniższe kroki ręcznie możesz uruchomić gotowy skrypt
> (robi dokładnie to samo — pakiety, udział, SELinux, `smb.conf`, konto-wabik,
> firewall, usługi):
> ```sh
> sudo ~/honeypot-system/scripts/setup-samba-honeypot.sh
> ```
> Ręczne kroki (jeśli wolisz krok po kroku):

```sh
sudo install -d -m 0777 /srv/samba/public
echo "czytaj mnie" | sudo tee /srv/samba/public/README.txt >/dev/null

sudo semanage fcontext -a -t samba_share_t "/srv/samba(/.*)?"
sudo restorecon -Rv /srv/samba
sudo setsebool -P samba_export_all_rw on
```

`/etc/samba/smb.conf` — agent czyta `log file`/`/var/log/samba/*` i klasyfikuje
nieudane logowania po `NT_STATUS_LOGON_FAILURE`, dlatego podnosimy `log level`
dla auth:

```sh
sudo tee /etc/samba/smb.conf >/dev/null <<'EOF'
[global]
   workgroup = WORKGROUP
   server string = fileserver
   security = user
   map to guest = Bad User
   log file = /var/log/samba/log.%m
   max log size = 5000
   log level = 1 auth:3 auth_audit:3
   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes

[public]
   comment = Public Share
   path = /srv/samba/public
   browseable = yes
   writable = yes
   guest ok = yes
   available = yes
EOF

sudo testparm -s
```

(Opcjonalnie konto do prób logowania — realistyczniejsze nieudane auth:)

```sh
sudo useradd -M -s /sbin/nologin decoy
printf 'Decoy123!\nDecoy123!\n' | sudo smbpasswd -a -s decoy
```

Firewall + start Samby:

```sh
sudo firewall-cmd --add-service=samba --permanent && sudo firewall-cmd --reload
sudo systemctl enable --now smb nmb
```

**Zaufanie do certyfikatu serwera** — agent (libcurl) używa systemowego magazynu
CA, a jego usługa ma `ProtectSystem=strict` i nie ustawia `SSL_CERT_FILE`, więc
wgrywamy CA **przed** startem:

```sh
sudo cp /root/honeypot-ca.crt /etc/pki/ca-trust/source/anchors/honeypot-ca.crt
sudo update-ca-trust
curl https://$SERVER_IP:8443/api/v1/stats          # bez --cacert; musi zadziałać
```

**Build i instalacja agenta** (kodu nie zmieniamy; adres serwera przez drop-in):

```sh
cd /opt/src/honeypot-system/agent
make release
# (opcjonalnie) make check-release        # testy; test HTTPS może dać SKIP
sudo make install                         # /usr/local/sbin/sys-auditd + unit + /var/lib/sys-auditd

sudo install -d -m 0755 /etc/systemd/system/sys-auditd.service.d
sudo tee /etc/systemd/system/sys-auditd.service.d/override.conf >/dev/null <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/sbin/sys-auditd --id $AGENT_ID --ip $SERVER_IP --port 8443
EOF
sudo chmod 600 /etc/systemd/system/sys-auditd.service.d/override.conf

sudo systemctl daemon-reload
sudo systemctl enable --now sys-auditd
systemctl status sys-auditd
```

> Diagnostyka agenta jest wyciszona (stdout/stderr → /dev/null). „active" nie
> oznacza dostarczania — potwierdzaj przez dashboard (heartbeat co ~60 s).

---

## 3. Weryfikacja end-to-end

Na S obserwuj dashboard `https://$SERVER_IP:8443/` lub:

```sh
curl --cacert /opt/src/honeypot-system/server/certs/ca.crt \
     https://$SERVER_IP:8443/api/v1/agents
```

W ciągu ~jednego interwału heartbeatu (~60 s) agent `$AGENT_ID` powinien być
`online`. Wygeneruj zdarzenia (z Kali lub dowolnego klienta w sieci H):

```sh
smbclient -L //$HONEYPOT_IP -N                               # enumeracja -> połączenie TCP
smbclient //$HONEYPOT_IP/public -N -c 'ls; put /etc/hostname wykradzione.txt'   # zapis -> file_change
smbclient //$HONEYPOT_IP/public -U decoy%zleHaslo -c 'ls'    # złe hasło -> authentication_failure
```

W dashboardzie pojawią się wiersze `network/tcp_connection_observed`,
`share/create` oraz `log` z klasyfikacją `authentication_failure`.

---

## 4. Rozwiązywanie problemów

- **Agent nie pojawia się / brak zdarzeń.** Z H: `curl https://$SERVER_IP:8443/api/v1/stats`.
  - Błąd TLS (`self-signed` / `unable to get local issuer`) → CA nie wgrane
    (`update-ca-trust`) lub SAN certu ≠ `$SERVER_IP` (przegeneruj na S:
    `./scripts/gen-certs.sh IP:$SERVER_IP`).
  - Timeout → firewall na S (`8443/tcp`) lub brak trasy H ↔ S.
- **Serwer nie startuje — bind denied.** SELinux: nadaj etykietę portowi (2A).
- **Agent nie widzi udziału.** Ścieżka musi istnieć, być katalogiem, bez symlinków
  (`RESOLVE_NO_SYMLINKS`), `available = yes`, nie drukarka. Sprawdź `testparm -s`.
- **Brak logów Samby.** `smb` musi działać i tworzyć pliki w `/var/log/samba/`;
  nieudane logowania wymagają `log level = ... auth:3`.
- **Zła wersja Javy.** Jar wymaga JRE 21 — zweryfikuj `java -version` i unit.
- **Raporty zawierają treść plików/logów** — zabezpiecz `data/` na S.

Szczegóły komponentów: [`server/README.md`](server/README.md),
[`server/docs/api.md`](server/docs/api.md), [`agent/README.md`](agent/README.md).
