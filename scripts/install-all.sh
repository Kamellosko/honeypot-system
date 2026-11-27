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

# --- uzupełnianie pustych pól honeypot.conf pytaniami (czyta z terminala, działa też przy "| tail") ---
tty_ok() { [ -r /dev/tty ] || { echo "Puste pola w $CONF, a brak terminala do pytań: uzupełnij plik ręcznie." >&2; exit 1; }; }

# Hasło z klawiatury; Enter = losowe. Bez " $ ` \ | (psułyby plik konfiguracyjny).
ask_pass() {
  local label=$1 p
  while :; do
    printf '%s (Enter = losowe): ' "$label" >/dev/tty; read -r p </dev/tty
    [ -n "$p" ] || p="$2$(openssl rand -hex 3)!"
    case "$p" in *[\"\$\`\\\|]*) echo "  bez znaków \" \$ \` \\ |" >/dev/tty ;; *) break ;; esac
  done
  echo "  -> $p" >/dev/tty
  REPLY=$p
}

# Wpisuje wartość w pustą linię KEY="" (wartość przez ENVIRON, więc znaki specjalne nie są interpretowane).
set_var() {
  V=$2 awk -v k="$1" 'index($0, k "=\"\"") == 1 { print k "=\"" ENVIRON["V"] "\"" substr($0, length(k) + 4); next } { print }' \
    "$CONF" >"$CONF.tmp" && cat "$CONF.tmp" >"$CONF" && rm -f "$CONF.tmp"
}

# Wpisuje hasło w linię konta Samby "login|GECOS|".
set_smb() {
  V=$2 awk -v l="$1" '{ t = $0; sub(/^[ \t]+/, "", t) }
    index(t, "\"" l "|") == 1 && $0 ~ /\|"[ \t]*$/ { sub(/"[ \t]*$/, ""); print $0 ENVIRON["V"] "\""; next } { print }' \
    "$CONF" >"$CONF.tmp" && cat "$CONF.tmp" >"$CONF" && rm -f "$CONF.tmp"
}

fill_conf() {
  local key u
  # shellcheck disable=SC1090
  source "$CONF"
  if [ -z "${HP_ADMIN_PUBKEY:-}" ]; then
    tty_ok
    echo "Klucz publiczny SSH admina ($HP_ADMIN_USER). Na hoście: cat ~/.ssh/id_ed25519.pub (albo ssh-keygen -t ed25519)." >/dev/tty
    while :; do
      printf 'Wklej klucz (ssh-ed25519 ...): ' >/dev/tty; read -r key </dev/tty
      case "$key" in ssh-*|ecdsa-*) break ;; *) echo "  to nie wygląda na klucz publiczny" >/dev/tty ;; esac
    done
    set_var HP_ADMIN_PUBKEY "$key"
  fi
  if [ -z "${HP_SHELL_DECOY_PASS:-}" ]; then
    tty_ok
    ask_pass "Hasło konta-przynęty SSH $HP_SHELL_DECOY_USER" "Backup2026_"
    set_var HP_SHELL_DECOY_PASS "$REPLY"
  fi
  for u in "${HP_SAMBA_USERS[@]}"; do
    [ -z "${u##*|}" ] || continue
    tty_ok
    ask_pass "Hasło Samby dla ${u%%|*}" "Fin2026_"
    set_smb "${u%%|*}" "$REPLY"
  done
}

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
  CONF="$REPO/samba_structure/honeypot.conf"
  if [ ! -f "$CONF" ]; then
    install -m 600 -o "$BUILD_USER" "$REPO/samba_structure/honeypot.conf.example" "$CONF"
    echo "utworzono $CONF z przykładu"
  fi
  fill_conf
  echo "krok SELinux trwa 1-3 min bez wypisu, nie przerywaj"
  "$REPO/samba_structure/setup-honeypot.sh"
  # Konto admina dostaje tylko klucz SSH; hasło jest potrzebne do sudo.
  # shellcheck disable=SC1090
  ADMIN=$(source "$CONF"; echo "$HP_ADMIN_USER")
  case "$(passwd -S "$ADMIN" 2>/dev/null | awk '{print $2}')" in
    P|PS) echo "$ADMIN ma już hasło" ;;
    *) printf '\nUstaw hasło do sudo dla %s:\n' "$ADMIN" >/dev/tty; passwd "$ADMIN" </dev/tty >/dev/tty 2>&1 ;;
  esac
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
