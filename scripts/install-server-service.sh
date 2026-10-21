#!/usr/bin/env bash
# Instaluje serwer+dashboard jako usługę systemd na maszynie S (AlmaLinux 9.8),
# tak żeby startował automatycznie po boocie i restartował się po awarii.
# Odpowiednik sekcji 2A w INSTALL.md.
#
# Wymagania (zrób PRZED uruchomieniem, w katalogu server/):
#   - zbudowany jar:   target/honeypot-server.jar     (mvn -DskipTests package)
#   - certy:           certs/server-keystore.p12 i certs/ca.crt  (./scripts/gen-certs.sh IP:<S>)
#
# Uruchom jako root z katalogu repo:
#   sudo ./scripts/install-server-service.sh
#
# Zmienne (opcjonalne):
#   KEYSTORE_PASS=changeit     hasło do keystore (musi zgadzać się z gen-certs)
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Uruchom jako root:  sudo $0" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(dirname "$SCRIPT_DIR")
SERVER_DIR="$REPO/server"
DASH_DIR="$REPO/dashboard"
KEYSTORE_PASS="${KEYSTORE_PASS:-changeit}"

JAR="$SERVER_DIR/target/honeypot-server.jar"
KEYSTORE="$SERVER_DIR/certs/server-keystore.p12"

[ -f "$JAR" ] || { echo "Brak $JAR — najpierw: cd server && mvn -DskipTests package" >&2; exit 1; }
[ -f "$KEYSTORE" ] || { echo "Brak $KEYSTORE — najpierw: cd server && ./scripts/gen-certs.sh IP:<adres_S>" >&2; exit 1; }
[ -d "$DASH_DIR" ] || { echo "Brak katalogu dashboard: $DASH_DIR" >&2; exit 1; }

# Wybierz JRE 21 (na Almie 9 /usr/bin/java bywa 17).
if [ -x /usr/lib/jvm/java-21-openjdk/bin/java ]; then
  JAVA_BIN=/usr/lib/jvm/java-21-openjdk/bin/java
else
  JAVA_BIN=$(command -v java || true)
fi
[ -n "$JAVA_BIN" ] || { echo "Nie znaleziono javy — zainstaluj java-21-openjdk-headless" >&2; exit 1; }
if ! "$JAVA_BIN" -version 2>&1 | grep -q 'version "21'; then
  echo "UWAGA: $JAVA_BIN to nie Java 21 — serwer może nie wstać. Zainstaluj java-21-openjdk." >&2
fi
echo ">> JRE: $JAVA_BIN"

echo ">> Użytkownik usługi"
id honeypot >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin honeypot

echo ">> Pliki aplikacji -> /opt/honeypot-server"
install -d -o root -g root /opt/honeypot-server
install -m 644 "$JAR" /opt/honeypot-server/honeypot-server.jar
rm -rf /opt/honeypot-server/dashboard
cp -r "$DASH_DIR" /opt/honeypot-server/dashboard

echo ">> Konfiguracja + keystore -> /etc/honeypot-server"
install -d -o root -g root /etc/honeypot-server
install -m 600 -o honeypot -g honeypot "$KEYSTORE" /etc/honeypot-server/server-keystore.p12
tee /etc/honeypot-server/server.properties >/dev/null <<EOF
server.bind=0.0.0.0
server.port=8443
server.keystore=/etc/honeypot-server/server-keystore.p12
server.keystore.password=$KEYSTORE_PASS
data.dir=/var/lib/honeypot-server
dashboard.dir=/opt/honeypot-server/dashboard
EOF
chmod 640 /etc/honeypot-server/server.properties
chown root:honeypot /etc/honeypot-server/server.properties

echo ">> Jednostka systemd"
tee /etc/systemd/system/honeypot-server.service >/dev/null <<EOF
[Unit]
Description=Honeypot central server (collector + API + dashboard)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=honeypot
Group=honeypot
ExecStart=$JAVA_BIN -jar /opt/honeypot-server/honeypot-server.jar /etc/honeypot-server/server.properties
Restart=on-failure
RestartSec=5
StateDirectory=honeypot-server
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

echo ">> Firewall (8443/tcp)"
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --add-port=8443/tcp --permanent || true
  firewall-cmd --reload || true
fi

echo ">> SELinux: etykieta portu 8443 (jeśli potrzebna)"
if command -v semanage >/dev/null 2>&1; then
  semanage port -a -t http_port_t -p tcp 8443 2>/dev/null \
    || semanage port -m -t http_port_t -p tcp 8443 2>/dev/null || true
fi

echo ">> Start usługi"
systemctl daemon-reload
systemctl enable --now honeypot-server
sleep 2
systemctl --no-pager status honeypot-server || true

echo
echo "Gotowe. Serwer wstaje automatycznie po boocie (enable) i restartuje się po awarii."
echo "Dane: /var/lib/honeypot-server/events.jsonl"
echo "Test:  curl --cacert $SERVER_DIR/certs/ca.crt https://<adres_S>:8443/api/v1/stats"
