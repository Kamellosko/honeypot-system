#!/usr/bin/env bash
# Pełna instalacja / aktualizacja honeypota na jednej maszynie (AlmaLinux 9/10), jedną komendą z katalogu repo:
#   sudo ./scripts/install-all.sh              # pierwsza instalacja albo aktualizacja
#   sudo ./scripts/install-all.sh --samba      # wymuś ponowne skonfigurowanie wabika (SSH + Samba)
#   sudo ./scripts/install-all.sh --no-samba   # pomiń wabika nawet przy pierwszej instalacji
#
# Kolejno: pakiety (tylko brakujące) -> jar serwera (tylko gdy brak) -> certyfikaty (tylko gdy brak)
#          -> usługa serwera -> wabik Samba/SSH (tylko gdy jeszcze nie skonfigurowany) -> agent.
# Każdy krok można powtarzać; aktualizacja nie rusza certyfikatów, ustawień alert.* ani wabika.
#
# Zmienne (opcjonalne):
#   AGENT_ID   identyfikator agenta; domyślnie ten z obecnej instalacji, a przy pierwszej instalacji nazwa hosta
#
# Bez internetu: pakiety muszą być już zainstalowane, a jar zbudowany na innym komputerze i skopiowany do
# server/target/honeypot-server.jar.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Uruchom jako root:  sudo $0" >&2; exit 1; }

REPO=$(cd "$(dirname "$0")/.." && pwd)
BUILD_USER="${SUDO_USER:-root}"
SAMBA=auto
for a in "$@"; do
  case "$a" in
    --samba) SAMBA=yes ;;
    --no-samba) SAMBA=no ;;
    *) echo "Nieznana opcja: $a" >&2; exit 1 ;;
  esac
done
as_user() { runuser -u "$BUILD_USER" -- env JAVA_HOME=/usr/lib/jvm/java-21-openjdk "$@"; }
step() { echo; echo "=== $* ==="; }

step "1/5 Pakiety"
PKGS=(gcc make curl-devel openssl-devel libtdb-devel java-21-openjdk-devel maven jq rsync)
MISSING=()
for p in "${PKGS[@]}"; do rpm -q "$p" >/dev/null 2>&1 || MISSING+=("$p"); done
if [ ${#MISSING[@]} -eq 0 ]; then
  echo "wszystkie są"
else
  echo "brakuje: ${MISSING[*]}"
  dnf install -y epel-release dnf-plugins-core
  dnf config-manager --set-enabled crb
  dnf install -y "${MISSING[@]}" || { echo "dnf nie zainstalował pakietów (brak internetu?)" >&2; exit 1; }
fi

step "2/5 Serwer: jar i certyfikaty"
JAR="$REPO/server/target/honeypot-server.jar"
if [ -f "$JAR" ]; then
  echo "jar jest: $JAR ($(date -r "$JAR" '+%F %T'))"
  if [ -n "$(find "$REPO/server/src/main" -newer "$JAR" -type f -print -quit)" ]; then
    echo "UWAGA: źródła serwera są nowsze niż jar. Skopiuj świeży jar albo usuń stary, żeby zbudować go tutaj." >&2
  fi
else
  echo "brak jara, buduję (mvn)"
  as_user mvn -q -f "$REPO/server/pom.xml" -DskipTests package
fi
if [ -f "$REPO/server/certs/server-keystore.p12" ]; then
  echo "certyfikaty są"
else
  (cd "$REPO/server" && as_user ./scripts/gen-certs.sh IP:127.0.0.1)
fi

step "3/5 Usługa serwera"
"$REPO/scripts/install-server-service.sh"

step "4/5 Wabik (SSH + Samba)"
if [ "$SAMBA" = auto ]; then
  systemctl is-enabled smb >/dev/null 2>&1 && SAMBA=no || SAMBA=yes
  [ "$SAMBA" = no ] && echo "już skonfigurowany, pomijam (wymuś: --samba)"
fi
if [ "$SAMBA" = yes ]; then
  [ -f "$REPO/samba_structure/honeypot.conf" ] || {
    echo "Brak samba_structure/honeypot.conf: skopiuj honeypot.conf.example, uzupełnij i uruchom ponownie." >&2; exit 1; }
  echo "krok SELinux trwa 1-3 min bez wypisu, nie przerywaj"
  "$REPO/samba_structure/setup-honeypot.sh"
fi

step "5/5 Agent"
OVERRIDE=/etc/systemd/system/sys-auditd.service.d/override.conf
if [ -z "${AGENT_ID:-}" ] && [ -f "$OVERRIDE" ]; then
  AGENT_ID=$(sed -n 's/.*--id \([^ ]*\).*/\1/p' "$OVERRIDE" | head -n1)
fi
AGENT_ID="${AGENT_ID:-$(hostname -s)}"
AGENT_ID="$AGENT_ID" "$REPO/scripts/install-agent-service.sh" "$REPO/agent"

step "Sprawdzenie"
sleep 3
systemctl is-active sysmon-collector sys-auditd || true
journalctl -u sysmon-collector -n 50 --no-pager | grep 'alert:' | tail -n1 || echo "alerty mailowe wyłączone (brak alert.* w /etc/sysmon/collector.properties)"
echo
echo "Gotowe: agent '$AGENT_ID'. Po ok. minucie powinien być online:"
echo "  curl -s --cacert $REPO/server/certs/ca.crt https://127.0.0.1:8443/api/agents"
