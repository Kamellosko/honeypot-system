#!/usr/bin/env bash
# Konfiguracja honeypota Samby na maszynie H (AlmaLinux 9.8) — odpowiednik
# sekcji 2B w INSTALL.md. Agent tego NIE robi (tylko monitoruje), dlatego
# Sambę stawiamy osobno tym skryptem.
#
# Uruchom jako root na maszynie H:
#   sudo ./scripts/setup-samba-honeypot.sh
#
# Po wykonaniu działający agent wykryje nowy udział i logi przy kolejnym
# odświeżeniu źródeł (~60 s) — restart agenta nie jest potrzebny.
#
# Zmienne (opcjonalne):
#   CREATE_DECOY=yes|no   konto-wabik do prób logowania (domyślnie yes)
#   DECOY_USER=decoy
#   DECOY_PASS=Decoy123!
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Uruchom jako root:  sudo $0" >&2
  exit 1
fi

SHARE_PATH=/srv/samba/public
CREATE_DECOY="${CREATE_DECOY:-yes}"
DECOY_USER="${DECOY_USER:-decoy}"
DECOY_PASS="${DECOY_PASS:-Decoy123!}"

echo ">> Pakiety"
dnf install -y samba samba-common policycoreutils-python-utils

echo ">> Katalog udziału-wabika: $SHARE_PATH"
install -d -m 0777 "$SHARE_PATH"
[ -e "$SHARE_PATH/README.txt" ] || echo "czytaj mnie" > "$SHARE_PATH/README.txt"

if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
  echo ">> SELinux: etykieta udziału + zapis"
  semanage fcontext -a -t samba_share_t "/srv/samba(/.*)?" 2>/dev/null \
    || semanage fcontext -m -t samba_share_t "/srv/samba(/.*)?"
  restorecon -Rv /srv/samba
  setsebool -P samba_export_all_rw on
else
  echo ">> SELinux wyłączony/niedostępny — pomijam etykiety"
fi

echo ">> /etc/samba/smb.conf"
if [ -f /etc/samba/smb.conf ] && [ ! -f /etc/samba/smb.conf.bak ]; then
  cp -a /etc/samba/smb.conf /etc/samba/smb.conf.bak
  echo "   (kopia zapasowa poprzedniej konfiguracji: /etc/samba/smb.conf.bak)"
fi
cat > /etc/samba/smb.conf <<'EOF'
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

echo ">> Walidacja konfiguracji (testparm)"
testparm -s

if [ "$CREATE_DECOY" = "yes" ]; then
  echo ">> Konto-wabik Samby: $DECOY_USER"
  id "$DECOY_USER" >/dev/null 2>&1 || useradd -M -s /sbin/nologin "$DECOY_USER"
  printf '%s\n%s\n' "$DECOY_PASS" "$DECOY_PASS" | smbpasswd -a -s "$DECOY_USER" >/dev/null
fi

echo ">> Firewall + usługi"
firewall-cmd --add-service=samba --permanent
firewall-cmd --reload
systemctl enable --now smb nmb

echo
echo "Gotowe. Udział [public] -> $SHARE_PATH"
echo "Agent wykryje udział i logi przy kolejnym odświeżeniu źródeł (~60 s)."
echo "Test z klienta:  smbclient //<IP_H>/public -N -c 'ls; put /etc/hostname wykradzione.txt'"
