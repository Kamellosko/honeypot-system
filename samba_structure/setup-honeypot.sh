#!/usr/bin/env bash
# setup-honeypot.sh — konfiguruje honeypot (SSH + Samba) wg honeypot.conf.
# Cel: maszyna wygląda jak zwykły serwer plików Działu Finansów.
# Uruchom jako root na AlmaLinux 9:   sudo ./setup-honeypot.sh
#
# UWAGA: pierwsza wersja — przetestuj na maszynie testowej przed produkcją.
# Kroki ryzykowne (wtmp, auditd->syslog) są "best-effort" i nie wywalają skryptu.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${1:-$HERE/honeypot.conf}"
[ -f "$CONF" ] || { echo "Brak pliku konfiguracyjnego: $CONF" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONF"

[ "$(id -u)" -eq 0 ] || { echo "Uruchom jako root: sudo $0" >&2; exit 1; }

# --- walidacja wymaganych pól ---
req() { [ -n "${!1:-}" ] || { echo "Uzupełnij $1 w $CONF" >&2; exit 1; }; }
req HP_SHELL_DECOY_PASS
req HP_ADMIN_PUBKEY
for u in "${HP_SAMBA_USERS[@]}"; do
  [ -n "${u##*|}" ] || { echo "Uzupełnij hasło konta Samby: ${u%%|*}" >&2; exit 1; }
done

echo ">> [1] Tożsamość: hostname / strefa / locale"
hostnamectl set-hostname "$HP_HOSTNAME"
timedatectl set-timezone "$HP_TIMEZONE" || true
localectl set-locale "LANG=$HP_LOCALE" 2>/dev/null || true

echo ">> Pakiety"
dnf install -y samba samba-common samba-vfs-modules policycoreutils-python-utils \
               audit openssh-server rsyslog util-linux
if [ "${HP_ENABLE_WSDD:-no}" = "yes" ]; then
  dnf install -y wsdd 2>/dev/null || echo "   (wsdd niedostępny — włącz EPEL: dnf install -y epel-release, potem wsdd)"
fi

echo ">> [2] Grupy i konta"
for g in "$HP_SMB_GROUP" zarzad; do getent group "$g" >/dev/null || groupadd "$g"; done

# Prawdziwy admin — key-only, sudo (wheel), powłoka.
if ! id "$HP_ADMIN_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash -G wheel -c "Administrator systemu" "$HP_ADMIN_USER"
fi
install -d -m 700 -o "$HP_ADMIN_USER" -g "$HP_ADMIN_USER" "/home/$HP_ADMIN_USER/.ssh"
printf '%s\n' "$HP_ADMIN_PUBKEY" > "/home/$HP_ADMIN_USER/.ssh/authorized_keys"
chown "$HP_ADMIN_USER:$HP_ADMIN_USER" "/home/$HP_ADMIN_USER/.ssh/authorized_keys"
chmod 600 "/home/$HP_ADMIN_USER/.ssh/authorized_keys"

# Konto SSH-shell (przynęta) — hasło = okruszek.
if ! id "$HP_SHELL_DECOY_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash -c "Konto kopii zapasowych" "$HP_SHELL_DECOY_USER"
fi
printf '%s:%s' "$HP_SHELL_DECOY_USER" "$HP_SHELL_DECOY_PASS" | chpasswd

# Konta tylko-Samba (bez powłoki) + hasła Samby.
for entry in "${HP_SAMBA_USERS[@]}"; do
  IFS='|' read -r login gecos pass <<<"$entry"
  id "$login" >/dev/null 2>&1 || useradd -M -s /sbin/nologin -G "$HP_SMB_GROUP" -c "$gecos" "$login"
  printf '%s\n%s\n' "$pass" "$pass" | smbpasswd -a -s "$login" >/dev/null
done

echo ">> [5] Struktura katalogów i treść (txt/csv, daty rozłożone w czasie)"
BASE="$HP_SMB_BASE"
install -d -m 0755 "$BASE"
install -d -o root -g "$HP_SMB_GROUP" -m 2770 "$BASE/Finanse" "$BASE/Archiwum"
install -d -o root -g zarzad          -m 2770 "$BASE/Zarzad"
install -d -m 0755 "$BASE/Wspolny"

# mk <sciezka> <dni_temu> <wlasciciel:grupa> <tresc>
mk() { install -d "$(dirname "$1")"; printf '%b\n' "$4" > "$1"; chown "$3" "$1"; chmod 0660 "$1"; touch -d "$2 days ago" "$1"; }

# Wspolny (gość, RO, nieszkodliwe + subtelny ślad do Archiwum)
mk "$BASE/Wspolny/INSTRUKCJA_dostepu.txt" 120 root:root 'Dostep do udzialow dzialowych wymaga konta domenowego.\nKopie zapasowe konfiguracji IT: udzial Archiwum (ukryty).'
mk "$BASE/Wspolny/ogloszenia.txt"          18 root:root 'Przypomnienie: inwentaryzacja srodkow trwalych do konca miesiaca.'
chmod -R a-w "$BASE/Wspolny"

# Finanse (za hasłem) — kilka kategorii, lata
for Y in 2022 2023 2024; do
  mk "$BASE/Finanse/Faktury/$Y/FV_${Y}_001.csv" $((RANDOM%300+30)) "root:$HP_SMB_GROUP" "numer;kontrahent;kwota_brutto\nFV/$Y/001;Kontrahent Alfa;$((RANDOM%9000+1000)).00"
  mk "$BASE/Finanse/Rozliczenia_VAT/$Y/VAT_$Y.txt" $((RANDOM%300+30)) "root:$HP_SMB_GROUP" "Rozliczenie VAT $Y - przekazane do biura ksiegowego."
done
mk "$BASE/Finanse/Zestawienia/zestawienie_kosztow.csv" 60 "root:$HP_SMB_GROUP" 'dzial;koszt_miesiac\nIT;12400\nAdministracja;8300\nLogistyka;15700'
mk "$BASE/Finanse/Budzet/budzet_2024_projekt.csv"      95 "root:$HP_SMB_GROUP" 'pozycja;plan;wykonanie\nWynagrodzenia;1200000;980000\nUslugi obce;340000;275000'
mk "$BASE/Finanse/Umowy/umowa_serwis_IT.txt"          410 "root:$HP_SMB_GROUP" 'Umowa serwisowa IT - do uzupelnienia danymi kontrahenta.'
mk "$BASE/Finanse/do_sprawdzenia/rozbieznosc_kasa.txt" 12 "root:$HP_SMB_GROUP" 'Do wyjasnienia: rozbieznosc w raporcie kasowym za ostatni tydzien.'

echo ">> [6] Okruszek: poświadczenia backup_srv w Archiwum\$"
# UWAGA reachability: Archiwum wymaga @finanse — okruszek osiagalny po zdobyciu konta persony.
mk "$BASE/Archiwum/IT/kopia_zapasowa.sh" 240 "root:$HP_SMB_GROUP" "#!/bin/sh\n# Nocna kopia udzialow na serwer archiwum.\nUSER=$HP_SHELL_DECOY_USER\nPASS=$HP_SHELL_DECOY_PASS\nsshpass -p \"\$PASS\" scp -r /srv/samba/Finanse \$USER@$HP_FAKE_BACKUP_HOST:/backup/\n"
mk "$BASE/Archiwum/IT/README.txt" 240 "root:$HP_SMB_GROUP" 'Skrypty kopii zapasowych. Nie zmieniac bez zgody dzialu IT.'

# Daty katalogów na koniec (po utworzeniu plików)
find "$BASE" -type d -exec touch -d "$((RANDOM%120+20)) days ago" {} + 2>/dev/null || true

echo ">> [6] Dom backup_srv: history, known_hosts, bałagan"
H="/home/$HP_SHELL_DECOY_USER"
printf 'mysql -h %s -u raport -p finanse_db\nscp backup_%s.tar.gz %s@%s:/backup/\ntar czf backup_$(date +%%F).tar.gz /srv/samba/Finanse\nexit\n' \
  "$HP_FAKE_DB_HOST" "$(date +%Y%m)" "$HP_SHELL_DECOY_USER" "$HP_FAKE_BACKUP_HOST" > "$H/.bash_history"
install -d -m 700 "$H/.ssh"
printf '%s ssh-ed25519 AAAAC3Nza...fingerprint\n%s ssh-ed25519 AAAAC3Nza...fingerprint\n' \
  "$HP_FAKE_DB_HOST" "$HP_FAKE_BACKUP_HOST" > "$H/.ssh/known_hosts"
: > "$H/.viminfo"; : > "$H/.lesshst"; install -d "$H/.cache" "$H/Pobrane"
printf 'raport_kwartalny_v2.csv\ninstrukcja_vpn.pdf (uszkodzony)\n' > "$H/Pobrane/pobrane.txt" || true
chown -R "$HP_SHELL_DECOY_USER:$HP_SHELL_DECOY_USER" "$H"
chmod 600 "$H/.bash_history" "$H/.ssh/known_hosts"

echo ">> [3] SELinux dla udziałów"
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
  semanage fcontext -a -t samba_share_t "$BASE(/.*)?" 2>/dev/null || semanage fcontext -m -t samba_share_t "$BASE(/.*)?"
  restorecon -R "$BASE"
  setsebool -P samba_export_all_rw on
  setsebool -P samba_export_all_ro on
fi

echo ">> [3] smb.conf (udziały + full_audit)"
[ -f /etc/samba/smb.conf ] && [ ! -f /etc/samba/smb.conf.bak ] && cp -a /etc/samba/smb.conf "/etc/samba/smb.conf.bak.$(date +%s)"
AUDIT_VFS='vfs objects = full_audit
   full_audit:prefix = %u|%I|%m|%S
   full_audit:success = connect disconnect opendir mkdir rmdir open read pread write pwrite rename unlink
   full_audit:failure = connect
   full_audit:facility = local5
   full_audit:priority = notice'
cat > /etc/samba/smb.conf <<EOF
[global]
   workgroup = $HP_WORKGROUP
   server string = $HP_SERVER_STRING
   security = user
   map to guest = Never
   log file = /var/log/samba/log.%m
   max log size = 5000
   log level = 1 auth:3 auth_audit:3
   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes

[Wspolny]
   comment = Dokumenty wspolne
   path = $BASE/Wspolny
   guest ok = yes
   guest only = yes
   read only = yes
   browseable = yes
   $AUDIT_VFS

[Finanse]
   comment = Dzial Finansow
   path = $BASE/Finanse
   valid users = @$HP_SMB_GROUP
   read only = no
   browseable = yes
   create mask = 0660
   directory mask = 2770
   $AUDIT_VFS

[Archiwum\$]
   comment = Archiwum IT
   path = $BASE/Archiwum
   valid users = @$HP_SMB_GROUP
   read only = yes
   browseable = no
   $AUDIT_VFS

[Zarzad]
   comment = Zarzad
   path = $BASE/Zarzad
   valid users = @zarzad
   read only = yes
   browseable = yes
   $AUDIT_VFS
EOF
testparm -s >/dev/null

echo ">> [8] rsyslog: full_audit -> $HP_AUDIT_LOG (agent to czyta)"
install -d -m 0755 /var/log/samba
cat > /etc/rsyslog.d/40-samba-audit.conf <<EOF
local5.*   -$HP_AUDIT_LOG
& stop
EOF
systemctl restart rsyslog || true

echo ">> [4/8] auditd: log komend -> syslog (/var/log/messages)"
cat > /etc/audit/rules.d/honeypot.rules <<'EOF'
-a always,exit -F arch=b64 -S execve -k hp_cmd
-a always,exit -F arch=b32 -S execve -k hp_cmd
EOF
augenrules --load 2>/dev/null || true
# Plugin syslog przekazuje zdarzenia audit do sysloga (best-effort; sprawdź /var/log/messages).
if [ -f /etc/audit/plugins.d/syslog.conf ]; then
  sed -i 's/^active = .*/active = yes/' /etc/audit/plugins.d/syslog.conf
fi
service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true

echo ">> [4] sshd: hasło + banner + MOTD + VERBOSE; svc-admin key-only; root off"
cat > /etc/ssh/banner.txt <<EOF
UWAGA: Dostep tylko dla upowaznionych pracownikow. Aktywnosc jest rejestrowana.
EOF
cat > /etc/motd <<EOF
--- Serwer plikow Dzialu Finansow ($HP_COMPANY) ---
Dzial IT: planowana przerwa serwisowa w ostatnia niedziele miesiaca 02:00-04:00.
Kopie zapasowe wykonywane sa codziennie o 01:00.
EOF
cat > /etc/ssh/sshd_config.d/10-honeypot.conf <<EOF
PasswordAuthentication yes
PermitRootLogin no
Banner /etc/ssh/banner.txt
LogLevel VERBOSE

Match User $HP_ADMIN_USER
    PasswordAuthentication no
    AuthenticationMethods publickey
EOF
sshd -t && systemctl reload sshd 2>/dev/null || systemctl restart sshd 2>/dev/null || true

echo ">> [7] Historia logowań (tylko UDANE; przed startem agenta)"
# a) /var/log/secure — linie "Accepted" (agent klasyfikuje jako unknown, nigdy atak)
for ip in "${HP_LOGIN_HISTORY_IPS[@]}"; do
  for d in 2 5 9 14; do
    ts="$(date -d "$d days ago" '+%b %e %H:%M:%S')"
    printf '%s %s sshd[%d]: Accepted publickey for %s from %s port %d ssh2: ED25519 SHA256:xxxx\n' \
      "$ts" "$HP_HOSTNAME" $((RANDOM%40000+1000)) "$HP_ADMIN_USER" "$ip" $((RANDOM%20000+1024)) >> /var/log/secure
  done
done
# b) wtmp (last) — best-effort przez utmpdump; nie wywala skryptu przy błędzie
if command -v utmpdump >/dev/null 2>&1; then
  { for ip in "${HP_LOGIN_HISTORY_IPS[@]}"; do
      t="$(date -d '3 days ago' '+%Y-%m-%dT%H:%M:%S,000000+0000')"
      printf '[7] [%05d] [ts/0] [%s] [%s     ] [pts/0       ] [%s] [%s] [%s]\n' \
        $((RANDOM%40000+1000)) "$HP_SHELL_DECOY_USER" "$HP_SHELL_DECOY_USER" "$ip" "$ip" "$t"
    done; } | utmpdump -r >> /var/log/wtmp 2>/dev/null \
    || echo "   (wtmp: pominięto — format utmpdump do dostrojenia na docelowym systemie)"
fi

echo ">> [7] Stare, zrotowane logi (agent pomija archiwa .gz)"
for n in 2 3 4; do
  : | gzip -c > "/var/log/messages.$n.gz" 2>/dev/null || true
  touch -d "$((n*7)) days ago" "/var/log/messages.$n.gz" 2>/dev/null || true
done

echo ">> [3/4] Firewall: tylko ssh + samba (port ssh czytany z sshd -T)"
if command -v firewall-cmd >/dev/null 2>&1; then
  systemctl enable --now firewalld 2>/dev/null || true
  ZONE="$(firewall-cmd --get-default-zone)"
  SSHP="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"; SSHP="${SSHP:-22}"
  firewall-cmd --permanent --zone="$ZONE" --add-service=samba >/dev/null
  firewall-cmd --permanent --zone="$ZONE" --add-port="$SSHP/tcp" >/dev/null
  [ "${HP_ENABLE_WSDD:-no}" = "yes" ] && firewall-cmd --permanent --zone="$ZONE" --add-port=3702/udp >/dev/null || true
  for s in $(firewall-cmd --permanent --zone="$ZONE" --list-services); do
    case "$s" in ssh|samba|dhcpv6-client) ;; *) firewall-cmd --permanent --zone="$ZONE" --remove-service="$s" >/dev/null ;; esac
  done
  firewall-cmd --reload >/dev/null
fi

echo ">> [3] Start usług Samby (+ wsdd)"
systemctl enable --now smb nmb
[ "${HP_ENABLE_WSDD:-no}" = "yes" ] && (systemctl enable --now wsdd 2>/dev/null || echo "   (uruchom wsdd ręcznie po instalacji pakietu)")

echo
echo "GOTOWE. Następnie (osobno, zgodnie z ustaleniami):"
echo "  - zainstaluj/uruchom agenta (sys-auditd) — PO zasianiu logów (już zrobione tutaj),"
echo "  - dopisz po stronie serwera: korelację okruszka + przestrojenie fast_enum,"
echo "  - zweryfikuj hardening i egress (backup_srv daje realny shell)."
echo "Udziały: Wspolny(gość RO), Finanse(@$HP_SMB_GROUP), Archiwum\$(ukryty), Zarzad(odmowa)."
