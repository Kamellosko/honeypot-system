#!/usr/bin/env bash
# Instaluje serwer+dashboard (na TEJ SAMEJ maszynie co agent, nasłuch tylko 127.0.0.1) jako usługę systemd na maszynie S (AlmaLinux 9.8),
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
KEYSTORE_PASS="${KEYSTORE_PASS:-${KEYSTORE_PASSWORD:-changeit}}"   # ta sama zmienna co w gen-certs.sh
umask 077

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
id sysmon >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin sysmon

echo ">> Pliki aplikacji -> /opt/sysmon"
install -d -o root -g root /opt/sysmon
install -m 644 "$JAR" /opt/sysmon/collector.jar
rm -rf /opt/sysmon/dashboard
cp -r "$DASH_DIR" /opt/sysmon/dashboard
chmod -R u=rwX,go=rX /opt/sysmon/dashboard   # umask 077 zrobiłby go nieczytelnym dla użytkownika sysmon

echo ">> Konfiguracja + keystore -> /etc/sysmon"
install -d -o root -g root /etc/sysmon
install -m 600 -o sysmon -g sysmon "$KEYSTORE" /etc/sysmon/collector.p12
install -m 640 -o root -g sysmon /dev/null /etc/sysmon/collector.properties
tee /etc/sysmon/collector.properties >/dev/null <<EOF
server.bind=127.0.0.1
server.port=8443
server.keystore=/etc/sysmon/collector.p12
server.keystore.password=$KEYSTORE_PASS
data.dir=/var/lib/sysmon
dashboard.dir=/opt/sysmon/dashboard
EOF
chmod 640 /etc/sysmon/collector.properties
chown root:sysmon /etc/sysmon/collector.properties

echo ">> Jednostka systemd"
tee /etc/systemd/system/sysmon-collector.service >/dev/null <<EOF
[Unit]
Description=System monitor collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sysmon
Group=sysmon
ExecStart=$JAVA_BIN -jar /opt/sysmon/collector.jar /etc/sysmon/collector.properties
Restart=on-failure
RestartSec=5
StateDirectory=sysmon
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

echo ">> Firewall: BEZ zmian (8443 nasłuchuje tylko na 127.0.0.1, nie otwieramy portu)"

echo ">> SELinux: etykieta portu 8443 (jeśli potrzebna)"
if command -v semanage >/dev/null 2>&1; then
  semanage port -a -t http_port_t -p tcp 8443 2>/dev/null \
    || semanage port -m -t http_port_t -p tcp 8443 2>/dev/null || true
fi

chmod 644 /etc/systemd/system/sysmon-collector.service

echo ">> Start usługi"
systemctl daemon-reload
systemctl enable sysmon-collector
systemctl restart sysmon-collector   # enable --now nie restartuje działającej usługi, więc po aktualizacji ruszałby stary jar
sleep 2
systemctl --no-pager status sysmon-collector || true

echo
echo "Gotowe. Serwer wstaje automatycznie po boocie (enable) i restartuje się po awarii."
echo "Dane: /var/lib/sysmon/events.jsonl"
echo "Test:  curl --cacert $SERVER_DIR/certs/ca.crt https://127.0.0.1:8443/api/v1/stats"
echo "Dashboard z zewnątrz tylko przez tunel SSH:  ssh -L 8443:127.0.0.1:8443 <user>@<host>  ->  https://127.0.0.1:8443/"
