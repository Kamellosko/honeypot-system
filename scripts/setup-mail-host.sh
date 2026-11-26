#!/usr/bin/env bash
# Lokalna skrzynka na alarmy honeypota (laboratorium) na komputerze z VirtualBoxem.
#
#   serwer Java (Alma) --SMTP 25--> Postfix (ten komputer) --> ~/Maildir --IMAP 127.0.0.1--> Dovecot --> Thunderbird
#
# Nic nie wychodzi do internetu: Postfix dostarcza wyłącznie lokalnie, a wszystko inne odrzuca.
# Pocztę przyjmuje tylko od siebie (127.0.0.1) i od wabika (HP_IP); reszta sieci dostaje odmowę.
# IMAP słucha tylko na 127.0.0.1, więc skrzynki nie widać z sieci.
#
# Użycie (Linux Mint 22 / Ubuntu 24.04):
#   sudo ./scripts/setup-mail-host.sh
# Zmienne (opcjonalne):
#   HP_IP=192.168.56.6        adres wabika, jedyny zdalny nadawca
#   MAIL_USER=<SUDO_USER>     konto systemowe, do którego trafiają alarmy
# Skrypt można uruchamiać ponownie; za pierwszym razem robi kopię main.cf.
set -euo pipefail

HP_IP="${HP_IP:-192.168.56.6}"
MAIL_USER="${MAIL_USER:-${SUDO_USER:-}}"

[ "$(id -u)" -eq 0 ] || { echo "Uruchom jako root: sudo $0" >&2; exit 1; }
[ -n "$MAIL_USER" ] && [ "$MAIL_USER" != root ] || { echo "Podaj konto na alarmy: sudo MAIL_USER=<login> $0" >&2; exit 1; }
id "$MAIL_USER" >/dev/null 2>&1 || { echo "Brak konta systemowego: $MAIL_USER" >&2; exit 1; }
[[ "$HP_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "HP_IP to nie adres IPv4: $HP_IP" >&2; exit 1; }
command -v apt-get >/dev/null || { echo "Skrypt jest dla Minta/Ubuntu (apt-get)." >&2; exit 1; }
MAIL_HOME="$(getent passwd "$MAIL_USER" | cut -d: -f6)"

echo ">> Pakiety (postfix, dovecot-imapd)"
# Bez pytań instalatora: tryb "Local only", nazwa poczty = nazwa komputera.
debconf-set-selections <<EOF
postfix postfix/main_mailer_type select Local only
postfix postfix/mailname string $(hostname -f 2>/dev/null || hostname)
EOF
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix dovecot-imapd >/dev/null

echo ">> Certyfikat TLS dla 'localhost'"
# Certyfikat z instalacji pakietów ma nazwę komputera z czasu instalacji systemu (np. "mint"), a Thunderbird łączy się
# z "localhost" i przy niezgodnej nazwie nie pozwala dokończyć kreatora konta. Własny certyfikat ma nazwę localhost.
CERT_DIR=/etc/ssl/hp-mail
install -d -m 0755 "$CERT_DIR"
if [ ! -s "$CERT_DIR/localhost.pem" ] || [ ! -s "$CERT_DIR/localhost.key" ]; then
  (umask 077 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=localhost \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$CERT_DIR/localhost.key" -out "$CERT_DIR/localhost.pem" 2>/dev/null)
  chmod 644 "$CERT_DIR/localhost.pem"
fi

echo ">> Postfix: tylko dostarczanie lokalne, nadawcy: localhost i $HP_IP"
[ -f /etc/postfix/main.cf.hp-orig ] || cp -a /etc/postfix/main.cf /etc/postfix/main.cf.hp-orig
# inet_interfaces=all zamiast samego adresu vboxnet0: ten interfejs bywa podnoszony dopiero po starcie Postfixa,
# a wtedy Postfix by nie wstał. Dostęp ogranicza smtpd_client_restrictions (wszyscy spoza mynetworks: odmowa).
postconf -e \
  "inet_interfaces = all" \
  "inet_protocols = ipv4" \
  "mydestination = \$myhostname, localhost.\$mydomain, localhost" \
  "mynetworks = 127.0.0.0/8, $HP_IP/32" \
  "smtpd_client_restrictions = permit_mynetworks, reject" \
  "smtpd_relay_restrictions = permit_mynetworks, reject" \
  "relayhost =" \
  "default_transport = error:wysylka poza ten komputer wylaczona" \
  "relay_transport = error:wysylka poza ten komputer wylaczona" \
  "home_mailbox = Maildir/" \
  "mailbox_command =" \
  "smtpd_banner = \$myhostname ESMTP" \
  "smtpd_tls_cert_file = $CERT_DIR/localhost.pem" \
  "smtpd_tls_key_file = $CERT_DIR/localhost.key" \
  "smtpd_tls_security_level = may"
postfix check

echo ">> Skrzynka $MAIL_HOME/Maildir"
for d in "" /cur /new /tmp; do
  install -d -m 0700 -o "$MAIL_USER" -g "$(id -gn "$MAIL_USER")" "$MAIL_HOME/Maildir$d"
done

echo ">> Dovecot: IMAP tylko na 127.0.0.1"
DOVECOT_VER="$(dovecot --version 2>/dev/null | cut -d. -f1-2)"
case "$DOVECOT_VER" in
  2.3) ;;
  *) echo "UWAGA: Dovecot $DOVECOT_VER; plik poniżej jest w składni 2.3. Przy 2.4 sprawdź 'doveconf -n'." >&2 ;;
esac
cat > /etc/dovecot/conf.d/99-honeypot.conf <<EOF
# Skrzynka alarmów honeypota: tylko lokalnie, tylko IMAP.
listen = 127.0.0.1
protocols = imap
mail_location = maildir:~/Maildir
# Kreator Thunderbirda podaje jako login cały adres (pawel@localhost); konto systemowe to samo "pawel".
auth_username_format = %Ln
ssl = yes
ssl_cert = <$CERT_DIR/localhost.pem
ssl_key = <$CERT_DIR/localhost.key
EOF
doveconf -n >/dev/null

echo ">> Zapora: port 25 tylko z $HP_IP"
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  ufw allow from "$HP_IP" to any port 25 proto tcp comment 'honeypot alarmy' >/dev/null
  echo "   ufw: dodano regułę dla $HP_IP"
else
  echo "   ufw nieaktywny: dostęp ogranicza sam Postfix (inni nadawcy dostają odmowę)"
fi

echo ">> Start usług"
systemctl enable postfix dovecot >/dev/null 2>&1
systemctl restart postfix dovecot

echo ">> Mail testowy"
before="$(find "$MAIL_HOME/Maildir/new" -type f | wc -l)"
printf 'From: honeypot-test@localhost\nTo: %s@localhost\nSubject: [honeypot] test skrzynki\n\nJesli to widzisz w Thunderbirdzie, skrzynka dziala.\n' \
  "$MAIL_USER" | /usr/sbin/sendmail -t
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ "$(find "$MAIL_HOME/Maildir/new" -type f | wc -l)" -gt "$before" ] && break
  sleep 1
done
if [ "$(find "$MAIL_HOME/Maildir/new" -type f | wc -l)" -gt "$before" ]; then
  echo "   OK: mail testowy jest w $MAIL_HOME/Maildir/new"
else
  echo "   BŁĄD: mail testowy nie dotarł; sprawdź: journalctl -u postfix --since -5min" >&2
  exit 1
fi

cat <<EOF

Gotowe. Thunderbird: Plik -> Nowe -> Istniejące konto pocztowe -> "Konfiguruj ręcznie":
  Serwer poczty przychodzącej: IMAP, localhost, port 143, STARTTLS, uwierzytelnianie: zwykłe hasło
  Nazwa użytkownika: $MAIL_USER   Hasło: hasło do tego konta na komputerze
  Serwer wychodzący: localhost, port 25, STARTTLS, bez uwierzytelniania; certyfikat samopodpisany: potwierdź wyjątek
  Adres e-mail w kreatorze: $MAIL_USER@localhost
Na Almie (collector.properties): alert.smtp.host=$(ip -4 -o addr show | awk -v hp="${HP_IP%.*}." '$4 ~ "^"hp {split($4,a,"/"); print a[1]; exit}'), alert.smtp.port=25, alert.to=$MAIL_USER@localhost
Test z Almy:  curl -v --url smtp://<ten-adres>:25 --mail-from honeypot@localhost --mail-rcpt $MAIL_USER@localhost -T <(printf 'Subject: test z Almy\n\nok\n')
Wycofanie: sudo cp /etc/postfix/main.cf.hp-orig /etc/postfix/main.cf; sudo rm /etc/dovecot/conf.d/99-honeypot.conf;
           sudo apt-get purge postfix dovecot-imapd
EOF
