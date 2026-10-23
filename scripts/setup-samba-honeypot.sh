#!/usr/bin/env bash
# Konfiguracja Samby tak, żeby maszyna wyglądała jak zwykły serwer plików małej
# firmy (AlmaLinux 9.8) — odpowiednik sekcji 2B w INSTALL.md. Agent tego NIE
# robi (tylko monitoruje), dlatego Sambę stawiamy osobno tym skryptem.
#
# Realizm zamiast wabika "public/guest/0777":
#   - udziały firmowe z uwierzytelnianiem (bez guest ok), prawa grupowe 2770,
#   - kilka kont o nazwach jak w firmie i hasłach słabych, ale nie absurdalnych,
#   - pliki z datami modyfikacji rozłożonymi na ~2 lata (nie "wszystko dziś"),
#   - poziom logów auth:3, żeby agent widział NT_STATUS_LOGON_FAILURE.
#
# Uruchom jako root:   sudo ./scripts/setup-samba-honeypot.sh
# Potem (osobno):      sudo ./scripts/setup-persona.sh
#
# Agent wykryje nowe udziały i logi przy kolejnym odświeżeniu źródeł (~60 s).
#
# Zmienne:
#   SMB_USERS (WYMAGANE) konta Samby: login:haslo:grupy,po,przecinku — rozdzielone spacjami.
#             Nie ma wartości domyślnej, żeby hasła nie trafiły do repozytorium. Przykład:
#   sudo SMB_USERS='jkowalski:<haslo1>:pracownicy anowak:<haslo2>:pracownicy,ksiegowosc mwisniewska:<haslo3>:pracownicy,kadry' ./scripts/setup-samba-honeypot.sh
#             Hasła mają być słabe, ale wiarygodne (np. Lato2024!), unikalne dla tej maszyny.
#   HP_WORKGROUP="FIRMA"   HP_SERVER_STRING="Serwer plikow"
#   CLEANUP_OLD=yes|no     usuń stary udział /srv/samba/public i konto decoy (domyślnie yes)
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Uruchom jako root:  sudo $0" >&2
  exit 1
fi

HP_WORKGROUP="${HP_WORKGROUP:-FIRMA}"
HP_SERVER_STRING="${HP_SERVER_STRING:-Serwer plikow}"
: "${SMB_USERS:?Ustaw SMB_USERS='login:haslo:grupy ...' (patrz komentarz na górze skryptu)}"
CLEANUP_OLD="${CLEANUP_OLD:-yes}"
BASE=/srv/samba

# Walidacja przed jakąkolwiek zmianą: każdy wpis to login:haslo:grupy (hasło może zawierać ':').
names=()
for entry in $SMB_USERS; do
  case "$entry" in
    ?*:?*:?*) names+=("${entry%%:*}") ;;
    *) echo "Zły wpis w SMB_USERS: '$entry' (oczekiwane login:haslo:grupy)" >&2; exit 1 ;;
  esac
done
U1="${names[0]}"; U2="${names[1]:-$U1}"; U3="${names[2]:-$U1}"   # właściciele plików wabików

echo ">> Pakiety"
dnf install -y samba samba-common policycoreutils-python-utils

if [ "$CLEANUP_OLD" = "yes" ]; then
  echo ">> Sprzątanie po starej wersji wabika (public, decoy)"
  # Tylko nasze stare konto-wabik (bez powłoki logowania), nie czyjeś prawdziwe.
  if id decoy >/dev/null 2>&1 && [ "$(getent passwd decoy | cut -d: -f7)" = "/sbin/nologin" ]; then
    smbpasswd -x decoy >/dev/null 2>&1 || true; userdel decoy
  fi
  [ -d "$BASE/public" ] && rm -rf -- "$BASE/public"
fi

echo ">> Grupy i konta"
for g in pracownicy ksiegowosc kadry; do getent group "$g" >/dev/null || groupadd "$g"; done
for entry in $SMB_USERS; do
  user=${entry%%:*}; rest=${entry#*:}; pass=${rest%:*}; groups=${rest##*:}   # hasło = wszystko przed ostatnim ':'
  for g in ${groups//,/ }; do getent group "$g" >/dev/null || groupadd "$g"; done
  if id "$user" >/dev/null 2>&1; then
    usermod -a -G "$groups" "$user"
  else
    useradd -M -s /sbin/nologin -G "$groups" "$user"
  fi
  printf '%s\n%s\n' "$pass" "$pass" | smbpasswd -a -s "$user" >/dev/null
done

# mk <sciezka> <dni_temu> <wlasciciel> <tresc>  — plik z datą modyfikacji w przeszłości.
mk() {
  mkdir -p "$(dirname "$1")"
  printf '%b\n' "$4" > "$1"
  chown "$3" "$1"
  touch -d "$2 days ago" "$1"
}

echo ">> Udziały i pliki w $BASE (daty modyfikacji rozłożone w czasie)"
install -d -o root -g pracownicy -m 2770 "$BASE/Dokumenty"
install -d -o root -g ksiegowosc -m 2770 "$BASE/Faktury"
install -d -o root -g kadry      -m 2770 "$BASE/Kadry"

mk "$BASE/Dokumenty/Instrukcje/Zasady_pracy_zdalnej.txt"  610 $U1:pracownicy 'Zasady pracy zdalnej\n\n1. Praca zdalna wymaga zgody przelozonego.\n2. Dostep do udzialow tylko przez siec firmowa lub VPN.\n3. Hasla zmieniamy co 90 dni.'
mk "$BASE/Dokumenty/Instrukcje/Drukarka_biuro.txt"        402 $U2:pracownicy    'Drukarka w biurze: 192.168.1.40, kolejka "biuro". Papier A4 w szafce przy oknie.'
mk "$BASE/Dokumenty/Projekty/Oferta_klient_A_2023.csv"    355 $U1:pracownicy 'pozycja;ilosc;cena_netto\nUsluga serwisowa;12;450.00\nLicencja roczna;3;1800.00\nSzkolenie;2;900.00'
mk "$BASE/Dokumenty/Projekty/Harmonogram_Q1.csv"          190 $U1:pracownicy 'zadanie;termin;odpowiedzialny\nMigracja poczty;2024-02-15;jkowalski\nAudyt licencji;2024-03-01;anowak'
mk "$BASE/Dokumenty/Stare/hasla_stare.csv"                730 $U1:pracownicy 'system;login;haslo\nrouter-biuro;admin;Router2021!\nnas-zapas;backup;Zapas#2020\npoczta-test;test;Test1234'
mk "$BASE/Dokumenty/notatki_spotkanie.txt"                 21 $U2:pracownicy    'Spotkanie 14.10: omowic termin przegladu serwera plikow oraz kopie zapasowe.'

mk "$BASE/Faktury/2023/FV_2023_001.csv"                   600 $U2:ksiegowosc    'numer;kontrahent;kwota_brutto\nFV/2023/001;Kontrahent Alfa;5535.00'
mk "$BASE/Faktury/2023/FV_2023_014.csv"                   470 $U2:ksiegowosc    'numer;kontrahent;kwota_brutto\nFV/2023/014;Kontrahent Beta;1230.00'
mk "$BASE/Faktury/2024/FV_2024_003.csv"                   160 $U2:ksiegowosc    'numer;kontrahent;kwota_brutto\nFV/2024/003;Kontrahent Alfa;7380.00'
mk "$BASE/Faktury/Rozliczenie_VAT_2024.txt"                75 $U2:ksiegowosc    'Rozliczenie VAT za IV kwartal - przekazane do biura ksiegowego.'

mk "$BASE/Kadry/Lista_pracownikow.csv"                    300 $U3:kadry    'imie;nazwisko;stanowisko;data_zatrudnienia\nJan;Kowalski;Administrator IT;2019-03-01\nAnna;Nowak;Ksiegowa;2018-09-15\nMaria;Wisniewska;Kadry;2020-01-10'
mk "$BASE/Kadry/Urlopy_2024.csv"                          140 $U3:kadry    'pracownik;od;do\nJan Kowalski;2024-07-15;2024-07-26\nAnna Nowak;2024-08-05;2024-08-16'
mk "$BASE/Kadry/Wzor_umowy_o_prace.txt"                   820 $U3:kadry    'Wzor umowy o prace - do uzupelnienia danymi pracownika.'

# Daty katalogów (po utworzeniu plików, które by je "odświeżyły").
find "$BASE" -type d | while read -r d; do touch -d "$((RANDOM % 120 + 5)) days ago" "$d"; done
chmod -R g+rwX "$BASE"

if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
  echo ">> SELinux: etykieta udziałów + zapis"
  semanage fcontext -a -t samba_share_t "$BASE(/.*)?" 2>/dev/null \
    || semanage fcontext -m -t samba_share_t "$BASE(/.*)?"
  restorecon -R "$BASE"
  setsebool -P samba_export_all_rw on
else
  echo ">> SELinux wyłączony/niedostępny — pomijam etykiety"
fi

echo ">> /etc/samba/smb.conf"
if [ -f /etc/samba/smb.conf ] && [ ! -f /etc/samba/smb.conf.bak ]; then
  cp -a /etc/samba/smb.conf /etc/samba/smb.conf.bak
  echo "   (kopia zapasowa poprzedniej konfiguracji: /etc/samba/smb.conf.bak)"
fi
# map to guest = Never: nieudane logowania muszą dawać NT_STATUS_LOGON_FAILURE,
# bo po nich agent klasyfikuje authentication_failure.
cat > /etc/samba/smb.conf <<EOF
[global]
   workgroup = $HP_WORKGROUP
   server string = $HP_SERVER_STRING
   security = user
   map to guest = Never
   log file = /var/log/samba/log.smbd
   max log size = 5000
   log level = 1 auth:3 auth_audit:3
   load printers = no
   printing = bsd
   printcap name = /dev/null
   disable spoolss = yes

[Dokumenty]
   comment = Dokumenty wspolne
   path = $BASE/Dokumenty
   valid users = @pracownicy
   browseable = yes
   writable = yes
   create mask = 0660
   directory mask = 2770

[Faktury]
   comment = Ksiegowosc
   path = $BASE/Faktury
   valid users = @ksiegowosc
   browseable = yes
   writable = yes
   create mask = 0660
   directory mask = 2770

[Kadry]
   comment = Dzial kadr
   path = $BASE/Kadry
   valid users = @kadry
   browseable = yes
   writable = yes
   create mask = 0660
   directory mask = 2770
EOF

echo ">> Walidacja konfiguracji (testparm)"
testparm -s

echo ">> Firewall + usługi"
if ! firewall-cmd --state >/dev/null 2>&1; then
  systemctl enable --now firewalld
fi
firewall-cmd --add-service=samba --permanent
firewall-cmd --reload
systemctl enable --now smb nmb

echo
echo "Gotowe. Udziały: Dokumenty, Faktury, Kadry w $BASE (workgroup $HP_WORKGROUP)."
echo "Test z klienta:  smbclient //<IP>/Dokumenty -U jkowalski%'<haslo>' -c ls"
echo "Złe hasło (ma dać authentication_failure):  smbclient //<IP>/Dokumenty -U jkowalski%zle -c ls"
