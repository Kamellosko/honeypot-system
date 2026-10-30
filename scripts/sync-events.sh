#!/usr/bin/env bash
# Kopiuje log zdarzeń (events.jsonl) na INNĄ maszynę, żeby przejęcie honeypota
# nie kasowało dowodów. To jedyny ruch WYCHODZĄCY z maszyny — ustaw cel świadomie.
#
# Wymaga: rsync + klucz SSH (bez hasła) do celu, zapisany w ~/.ssh i zaufany.
#
# Uwaga: ten klucz leży na honeypocie, więc ktoś, kto przejmie roota, ma go też. Na maszynie odbiorczej:
#   - ogranicz klucz do wgrywania w jeden katalog, w authorized_keys:
#       restrict,command="rrsync -wo /srv/honeypot-logs" ssh-ed25519 AAAA... honeypot
#   - klucz nadal może NADPISAĆ plik, więc odbiorca sam robi kopie, których ten klucz nie rusza,
#     np. cron: cp /srv/honeypot-logs/events.jsonl /srv/honeypot-logs-archiwum/events-$(date +%F-%H).jsonl
#
# Użycie (jako root, najlepiej z cron co 5-10 min):
#   REMOTE=backup@10.0.0.50:/srv/honeypot-logs/ /usr/local/sbin/sync-events.sh
#   */10 * * * * root REMOTE=backup@10.0.0.50:/srv/honeypot-logs/ /usr/local/sbin/sync-events.sh
#
# Zmienne:
#   REMOTE   (WYMAGANE) cel rsync, np. uzytkownik@host:/sciezka/
#   SRC      plik źródłowy (domyślnie /var/lib/sysmon/events.jsonl)
#   SSH_KEY  klucz prywatny (domyślnie /root/.ssh/id_ed25519)
set -euo pipefail

: "${REMOTE:?Ustaw REMOTE=uzytkownik@host:/sciezka/}"
SRC="${SRC:-/var/lib/sysmon/events.jsonl}"
SSH_KEY="${SSH_KEY:-/root/.ssh/id_ed25519}"

[ -f "$SRC" ] || exit 0   # jeszcze brak zdarzeń

# --append-verify: log tylko rośnie, więc dosyłamy końcówkę.
exec rsync -a --append-verify \
  -e "ssh -i \"$SSH_KEY\" -o BatchMode=yes -o StrictHostKeyChecking=accept-new" \
  "$SRC" "$REMOTE"
