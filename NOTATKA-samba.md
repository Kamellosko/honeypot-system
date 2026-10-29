# Notatka: co zrobić na Sambie (AlmaLinux 9.8)

Kolejność: **serwer → Samba → agent** (agent wykrywa udziały sam, ~61 s po starcie).

## 0. Przed uruchomieniem
- [ ] Wymyśl 3 hasła kont (słabe, ale wiarygodne, np. `Lato2024!`, unikalne dla tej maszyny).
- [ ] Zdecyduj o nazwach: workgroup (domyślnie `FIRMA`), hostname (`fs01`), domena (`firma.local`).
- [ ] Skrypty muszą być na maszynie (repo skopiowane), uruchamiasz jako root.

## 1. Samba (udziały, konta, pliki)
```sh
sudo SMB_USERS='jkowalski:<haslo1>:pracownicy anowak:<haslo2>:pracownicy,ksiegowosc mwisniewska:<haslo3>:pracownicy,kadry' \
     ./scripts/setup-samba-honeypot.sh
```
Skrypt: instaluje pakiety, tworzy grupy i konta, udziały `Dokumenty`, `Faktury`, `Kadry`
w `/srv/samba` (prawa `2770`, pliki z różnymi datami), etykiety SELinux, `smb.conf`,
firewall (tylko usługa `samba`), włącza `smb` i `nmb`. Usuwa też stary `public` i konto `decoy`.

## 2. Tożsamość maszyny
```sh
sudo HP_HOSTNAME=fs01 HP_DOMAIN=firma.local ./scripts/setup-persona.sh
```
Hostname, baner SSH, MOTD, katalogi domowe, kopia zapasowa (cron, niedziela 02:00), logrotate.

## 3. Wymagania agenta względem Samby (nie zmieniaj)
- `log file = /var/log/samba/log.%m`
- `log level = 1 auth:3 auth_audit:3`
- `map to guest = Never` (inaczej brak `NT_STATUS_LOGON_FAILURE` → brak `authentication_failure`)
- ścieżki udziałów: istniejące katalogi, **bez symlinków**, `available = yes`

## 4. Sprawdzenie (z innej maszyny)
```sh
nmap -sV -p- <IP_H>                                        # tylko SMB (+ SSH)
smbclient -L //<IP_H> -N                                   # lista udziałów
smbclient //<IP_H>/Dokumenty -U jkowalski%'<haslo1>' -c ls # logowanie OK
smbclient //<IP_H>/Dokumenty -U jkowalski%zle -c ls        # → authentication_failure
```
Na H: `testparm -s`, `systemctl status smb nmb`, `firewall-cmd --list-all` (bez 8443).
W API (przez tunel/na H): `curl --cacert certs/ca.crt https://127.0.0.1:8443/api/v1/events?limit=10`.

## 5. Zostaje do zrobienia ręcznie
- [ ] Hiperwizor: MAC producenta zwykłego sprzętu, ciągi DMI (patrz `REALIZM.md`).
- [ ] Sieć: osobny VLAN bez trasy do reszty sieci, ograniczony ruch wychodzący.
- [ ] Kopia logu poza maszynę: `scripts/sync-events.sh` (rsync po SSH, cron co 10 min).
- [ ] Rozwiązywanie problemów: brak logów Samby → sprawdź, czy `smb` działa i tworzy pliki w
  `/var/log/samba/`; agent nie widzi udziału → `testparm -s`, symlinki, SELinux (`restorecon -R /srv/samba`).
