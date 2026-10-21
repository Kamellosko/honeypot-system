#!/usr/bin/env bash
# Buduje agenta i instaluje go jako usługę systemd (sys-auditd) na maszynie H
# (AlmaLinux 9.8), tak żeby startował automatycznie po boocie i restartował się
# po awarii. Odpowiednik sekcji 2B (agent) w INSTALL.md.
#
# Uruchom jako root na H:
#   sudo SERVER_IP=192.168.1.86 ./install-agent-service.sh [katalog_zrodel_agenta]
#
# Zmienne:
#   SERVER_IP     (WYMAGANE) adres serwera S
#   SERVER_PORT   port serwera (domyślnie 8443)
#   AGENT_ID      identyfikator (domyślnie nazwa hosta)
#   FORTIFY_LEVEL poziom _FORTIFY_SOURCE (domyślnie 2 — GCC 11 na Almie 9 nie
#                 wspiera 3; na Almie 10 / gcc-toolset-14 możesz dać 3)
#
# Zanim uruchomisz: CA serwera musi być zaufane w systemie
#   sudo cp ca.crt /etc/pki/ca-trust/source/anchors/honeypot-ca.crt && sudo update-ca-trust
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Uruchom jako root:  sudo SERVER_IP=<adres_S> $0" >&2
  exit 1
fi
: "${SERVER_IP:?Ustaw SERVER_IP=<adres_S>}"
SERVER_PORT="${SERVER_PORT:-8443}"
AGENT_ID="${AGENT_ID:-$(hostname -s)}"
FORTIFY_LEVEL="${FORTIFY_LEVEL:-2}"

# Katalog ze źródłami agenta: argument, albo bieżący, albo ~/agent.
AGENT_SRC="${1:-}"
if [ -z "$AGENT_SRC" ]; then
  if [ -f "./Makefile" ] && [ -d "./src" ]; then AGENT_SRC="$PWD"
  elif [ -f "$HOME/agent/Makefile" ]; then AGENT_SRC="$HOME/agent"
  else echo "Nie znalazłem źródeł agenta — podaj katalog: $0 /sciezka/do/agent" >&2; exit 1; fi
fi
[ -f "$AGENT_SRC/Makefile" ] || { echo "Brak Makefile w $AGENT_SRC" >&2; exit 1; }
echo ">> Źródła agenta: $AGENT_SRC"
echo ">> Cel: --id $AGENT_ID --ip $SERVER_IP --port $SERVER_PORT (FORTIFY=$FORTIFY_LEVEL)"

HARDEN="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$FORTIFY_LEVEL -fstack-protector-strong -fPIE -fvisibility=hidden"

echo ">> Sprawdzenie zaufania do CA serwera (łączność TLS)"
if ! curl -sf "https://$SERVER_IP:$SERVER_PORT/api/v1/stats" >/dev/null; then
  echo "UWAGA: nie udało się połączyć TLS z https://$SERVER_IP:$SERVER_PORT" >&2
  echo "       Upewnij się, że CA jest zaufane (update-ca-trust) i serwer działa." >&2
  echo "       Kontynuuję — agent i tak będzie ponawiał dostawy." >&2
fi

echo ">> Build (release) + instalacja"
make -C "$AGENT_SRC" release HARDEN_CFLAGS="$HARDEN"
make -C "$AGENT_SRC" install HARDEN_CFLAGS="$HARDEN"

echo ">> Drop-in systemd z adresem serwera"
install -d -m 0755 /etc/systemd/system/sys-auditd.service.d
tee /etc/systemd/system/sys-auditd.service.d/override.conf >/dev/null <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/sbin/sys-auditd --id $AGENT_ID --ip $SERVER_IP --port $SERVER_PORT
EOF
chmod 600 /etc/systemd/system/sys-auditd.service.d/override.conf

echo ">> Start usługi"
systemctl daemon-reload
systemctl enable --now sys-auditd
sleep 2
systemctl --no-pager status sys-auditd || true

echo
echo "Gotowe. Agent '$AGENT_ID' wstaje automatycznie po boocie i restartuje się po awarii."
echo "Weryfikacja na S:  /api/v1/agents powinno pokazać '$AGENT_ID' online (po ~minucie heartbeat)."
