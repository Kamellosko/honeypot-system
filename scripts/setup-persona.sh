#!/usr/bin/env bash
# Tożsamość maszyny: ma wyglądać jak zwykły, trochę zaniedbany serwer plików
# małej firmy (AlmaLinux 9.8). Odpowiada punktowi 2 z propozycji realizmu.
#
# Co robi:
#   - ustawia nazwę hosta i wpis w /etc/hosts,
#   - baner logowania SSH + MOTD (typowy tekst firmowy),
#   - katalogi domowe kont z Samby (z plikami o różnych datach),
#   - cotygodniowa kopia zapasowa udziałów (cron) i logrotate dla własnych logów.
#
# Uruchom jako root PO setup-samba-honeypot.sh:
#   sudo ./scripts/setup-persona.sh
#
# Zmienne (opcjonalne):
#   HP_HOSTNAME=fs01        HP_DOMAIN=firma.local     HP_COMPANY="Firma Sp. z o.o."
#   HP_IP=<adres_maszyny>   (jeśli podany, trafia do /etc/hosts; domyślnie 127.0.1.1)
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Uruchom jako root:  sudo $0" >&2
  exit 1
fi

getent group pracownicy >/dev/null || { echo "Najpierw uruchom setup-samba-honeypot.sh (brak grupy pracownicy)" >&2; exit 1; }

HP_HOSTNAME="${HP_HOSTNAME:-fs01}"
HP_DOMAIN="${HP_DOMAIN:-firma.local}"
HP_COMPANY="${HP_COMPANY:-Firma Sp. z o.o.}"
HP_IP="${HP_IP:-127.0.1.1}"

echo ">> Nazwa hosta: $HP_HOSTNAME.$HP_DOMAIN"
hostnamectl set-hostname "$HP_HOSTNAME.$HP_DOMAIN"
sed -i "/ $HP_HOSTNAME\(\.$HP_DOMAIN\)\?\( \|\$\)/d" /etc/hosts
echo "$HP_IP $HP_HOSTNAME.$HP_DOMAIN $HP_HOSTNAME" >> /etc/hosts

echo ">> Baner SSH i MOTD"
cat > /etc/issue.net <<EOF
$HP_COMPANY - system przeznaczony wylacznie dla upowaznionych uzytkownikow.
Dzialania w systemie moga byc rejestrowane.
EOF
install -d -m 0755 /etc/ssh/sshd_config.d
echo "Banner /etc/issue.net" > /etc/ssh/sshd_config.d/20-banner.conf
cat > /etc/motd <<EOF

  $HP_COMPANY - serwer plikow ($HP_HOSTNAME)
  Kopie zapasowe: niedziela 02:00. Problemy zglaszaj do dzialu IT.

EOF
if sshd -t 2>/dev/null; then systemctl reload sshd 2>/dev/null || true; else echo "UWAGA: sshd -t zgłosił błąd — usuń /etc/ssh/sshd_config.d/20-banner.conf" >&2; fi

echo ">> Katalogi domowe kont (daty w przeszłości)"
for u in $(getent group pracownicy | cut -d: -f4 | tr ',' ' '); do
  id "$u" >/dev/null 2>&1 || continue
  h="/home/$u"
  install -d -o "$u" -g "$u" -m 0700 "$h" 2>/dev/null || { groupadd -f "$u"; install -d -o "$u" -g "$u" -m 0700 "$h"; }
  [ -e "$h/.bash_logout" ] || cp /etc/skel/.bash_logout /etc/skel/.bash_profile /etc/skel/.bashrc "$h/" 2>/dev/null || true
  [ -e "$h/notatki.txt" ] || printf 'Do zrobienia: przeglad uprawnien do udzialow, zmiana hasla.\n' > "$h/notatki.txt"
  chown -R "$u:$u" "$h"
  find "$h" -type f | while IFS= read -r f; do touch -d "$((RANDOM % 500 + 30)) days ago" "$f"; done
done

echo ">> Kopia zapasowa udziałów (cron, niedziela 02:00)"
install -d -m 0750 /var/backups
cat > /usr/local/sbin/backup-fs.sh <<'EOF'
#!/bin/sh
# Cotygodniowa kopia udziałów, trzymamy 4 ostatnie.
set -eu
tar -czf "/var/backups/fs-$(date +%F).tgz" -C /srv samba 2>/dev/null
ls -1t /var/backups/fs-*.tgz | tail -n +5 | xargs -r rm -f
logger -t backup-fs "kopia zapasowa udzialow wykonana"
EOF
chmod 0755 /usr/local/sbin/backup-fs.sh
echo "0 2 * * 0 root /usr/local/sbin/backup-fs.sh" > /etc/cron.d/backup-fs
chmod 0644 /etc/cron.d/backup-fs

echo ">> Logrotate dla logów Samby (jak w standardowej instalacji)"
if [ ! -f /etc/logrotate.d/samba ]; then
  cat > /etc/logrotate.d/samba <<'EOF'
/var/log/samba/log.smbd /var/log/samba/log.nmbd {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    postrotate
        /usr/bin/systemctl reload smb nmb >/dev/null 2>&1 || true
    endscript
}
EOF
fi

echo
echo "Gotowe. Sprawdź:  hostnamectl;  cat /etc/motd;  ssh <host> (baner)."
echo "Odciski sprzętu VM (MAC, DMI) ustawia się w hiperwizorze, nie na tej maszynie."
