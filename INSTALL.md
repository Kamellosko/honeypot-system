# Instalacja od zera: honeypot na AlmaLinux 9.8

Jedna maszyna (Alma, hostname `fs01`) robi wszystko: Samba-wabik, agent, serwer i dashboard.
Druga maszyna (Kali) tylko atakuje, żeby wygenerować zdarzenia.

```
Kali ──SMB/SSH──► Alma fs01 [ Samba │ agent sys-auditd │ serwer sysmon-collector + dashboard ]
Twój komputer ──SSH (tunel)──► dashboard na https://127.0.0.1:8443/
```

Polecenia oznaczone **[Alma]** wpisujesz na Almie, **[Kali]** na Kali, **[Host]** na swoim komputerze.

---

## 0. Maszyny wirtualne (VirtualBox)

### 0.1 Sieć host-only
**File → Tools → Network Manager → Host-only Networks → Create.** Zostaje `vboxnet0`, np. `192.168.56.1/24`, DHCP włączony.
Jeśli VirtualBox zgłasza brak uprawnień, na hoście:

```bash
sudo modprobe vboxnetadp vboxnetflt
echo '* 192.168.56.0/21' | sudo tee /etc/vbox/networks.conf
```

### 0.2 Alma
- Typ: Linux / Red Hat 64-bit, 2 CPU, 2–4 GB RAM, dysk 20 GB.
- **Adapter 1: NAT** (internet dla `dnf` i `mvn`).
- **Adapter 2: Host-only (`vboxnet0`)**: tędy łączy się Kali i Ty (SSH).
- ISO: AlmaLinux 9.8, instalacja **Minimal Install**. Utwórz użytkownika z uprawnieniami administratora (sudo) i ustaw hasło roota.

### 0.3 Kali
Adapter 1: NAT, Adapter 2: Host-only (`vboxnet0`), jak wyżej.

### 0.4 Po instalacji Almy
**[Alma]** Sprawdź adresy i zapisz IP z sieci `192.168.56.x`, to jest `<IP_ALMY>`:

```bash
ip -4 addr
```

Jeśli drugi interfejs nie ma adresu, włącz go (nazwę z `ip -4 addr`, np. `enp0s8`):

```bash
sudo nmcli device connect enp0s8
```

**[Host]** Od teraz możesz pracować przez SSH (wygodniejsze kopiowanie):

```bash
ssh <uzytkownik>@<IP_ALMY>
```

> Zrób **snapshot** Almy po tym kroku ("czysty system").

---

## 1. Pakiety **[Alma]**

```bash
sudo dnf install -y epel-release dnf-plugins-core
sudo dnf config-manager --set-enabled crb
sudo dnf install -y git gcc make curl-devel openssl-devel libtdb-devel java-21-openjdk-devel maven jq rsync
```

Maven musi używać Javy 21 (projekt kompiluje z `release 21`):

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
echo 'export JAVA_HOME=/usr/lib/jvm/java-21-openjdk' >> ~/.bashrc
java -version        # ma pokazać 21
```

Jeśli `java -version` pokazuje inną wersję: `sudo alternatives --config java` i wybierz 21.

## 2. Kod projektu **[Alma]**

Wariant A: z GitHuba (jeśli repo jest publiczne albo masz dostęp):

```bash
git clone -b afteraudit https://github.com/Kamellosko/honeypot-system.git ~/honeypot-system
```

Wariant B: kopia z Twojego komputera (**[Host]**, w folderze nadrzędnym projektu):

```bash
scp -r honeypot-system-skrypty <uzytkownik>@<IP_ALMY>:~/honeypot-system
```

**[Alma]** Wszystkie dalsze polecenia wykonuj w tym folderze i **nie rozdzielaj** `agent/`, `server/`, `dashboard/`, `scripts/`:

```bash
cd ~/honeypot-system
ls            # agent  dashboard  scripts  server ...
```

> Jeśli skopiowałeś folder z hosta, usuń stare artefakty, żeby zbudować wszystko świeżo:
> `rm -rf server/target server/certs agent/build`

## 3. Serwer i dashboard **[Alma]**

```bash
cd ~/honeypot-system/server
mvn -DskipTests package                    # -> target/honeypot-server.jar
./scripts/gen-certs.sh IP:127.0.0.1        # -> certs/server-keystore.p12, certs/ca.crt
cd ..
sudo ./scripts/install-server-service.sh
```

Sprawdź:

```bash
systemctl status sysmon-collector --no-pager
curl --cacert server/certs/ca.crt https://127.0.0.1:8443/api/v1/stats
```

Ma wrócić JSON z licznikami (same zera to normalne).

Jeśli `install-server-service.sh` skarży się na Javę: usługa potrzebuje `/usr/lib/jvm/java-21-openjdk/bin/java` (zainstalowane w kroku 1).

## 4. Samba (wabik) **[Alma]**

Wymyśl 3 hasła (słabe, ale wiarygodne, np. w stylu `Lato2024!`) i podstaw je w miejsce `HASLO1`, `HASLO2`, `HASLO3`.
**Nie zapisuj ich w repozytorium.**

```bash
cd ~/honeypot-system
sudo SMB_USERS='jkowalski:HASLO1:pracownicy anowak:HASLO2:pracownicy,ksiegowosc mwisniewska:HASLO3:pracownicy,kadry' \
     ./scripts/setup-samba-honeypot.sh
sudo HP_HOSTNAME=fs01 HP_DOMAIN=firma.local ./scripts/setup-persona.sh
```

Sprawdź:

```bash
systemctl status smb nmb --no-pager
sudo testparm -s | head -30
ls /srv/samba
sudo firewall-cmd --list-all        # ma być usługa samba, BEZ portu 8443
```

## 5. Agent **[Alma]**

```bash
cd ~/honeypot-system
sudo AGENT_ID=fs01 ./scripts/install-agent-service.sh ./agent
```

`AGENT_ID` musi mieć tylko znaki `A-Za-z0-9._-` (max 64), inaczej serwer odrzuci wszystkie raporty.

Sprawdź:

```bash
systemctl status sys-auditd --no-pager
sudo ls /var/lib/sys-auditd/            # snapshots  pending
```

Po około minucie agent powinien być widoczny jako online:

```bash
curl --cacert server/certs/ca.crt https://127.0.0.1:8443/api/v1/agents | jq .
```

Jeśli `make release` się nie zbuduje, zapisz pełny komunikat błędu (typowo brak `libtdb-devel` albo `curl-devel`).

> Zrób **snapshot** Almy ("system gotowy").

## 6. Test z Kali **[Kali]**

Podstaw `<IP_ALMY>`:

```bash
smbclient -L //<IP_ALMY> -N                                  # lista udziałów
smbclient //<IP_ALMY>/Dokumenty -U jkowalski%zle -c ls       # złe hasło
smbclient //<IP_ALMY>/Dokumenty -U jkowalski%'HASLO1' -c 'ls'
echo test > /tmp/x.txt
smbclient //<IP_ALMY>/Dokumenty -U jkowalski%'HASLO1' -c 'put /tmp/x.txt x.txt'
```

Zdarzenia na Almie **[Alma]**:

```bash
sudo tail -n 10 /var/lib/sysmon/events.jsonl | jq -c '{source,operation,analysis}'
sudo ls /var/lib/sys-auditd/pending | wc -l          # ma być ~0
```

Oczekiwane:
- `network / tcp_connection_observed` z IP Kali,
- `log / append` z błędem logowania po złym haśle,
- `share / create` po wgraniu pliku.

**Sprawdź ręcznie** po teście ze złym hasłem:

```bash
sudo grep -iE 'LOGON_FAILURE|WRONG_PASSWORD|NO_SUCH_USER' /var/log/samba/log.smbd | tail
```

Klasyfikacja `authentication_failure` rozpoznaje tylko `NT_STATUS_LOGON_FAILURE`. Jeśli w logu jest inny tekst
(np. `NT_STATUS_WRONG_PASSWORD`), daj znać: trzeba rozszerzyć listę w `hp_report_simple` (`agent/src/snapshot.c`).

## 7. Dashboard **[Host]**

```bash
ssh -L 8443:127.0.0.1:8443 <uzytkownik>@<IP_ALMY>
```

Zostaw to okno otwarte, w przeglądarce wejdź na `https://127.0.0.1:8443/` i zaakceptuj ostrzeżenie o certyfikacie
(albo zaimportuj `server/certs/ca.crt`). Powinieneś zobaczyć agenta `fs01` jako ONLINE i zdarzenia z testu.

---

## 8. Opcjonalnie

- **Kopia logu poza maszynę** (żeby przejęcie wabika nie skasowało dowodów):
  `sudo REMOTE=user@host:/sciezka/ ./scripts/sync-events.sh` i wpis w cronie co 10 minut.
- **Izolacja:** osobna sieć bez trasy do reszty. Po instalacji możesz odłączyć Adapter 1 (NAT).
- **Realizm VM:** MAC i ciągi DMI ustawia się w VirtualBoxie (`VBoxManage modifyvm ... --macaddress1`, `VBoxManage setextradata ... DmiSystemVendor`).

## 9. Rozwiązywanie problemów

| Objaw | Co sprawdzić |
|---|---|
| VM nie startuje: brak `vboxnet0` | punkt 0.1 |
| Agent offline na dashboardzie | `journalctl -u sys-auditd -n 50`, `ls /var/lib/sys-auditd/pending` (rosnąca kolejka = serwer nie odbiera) |
| Raporty w `*.rejected` | niepoprawny `AGENT_ID` albo zła koperta, zob. `server/docs/api.md` |
| TLS: błąd certyfikatu | CA zaufane? `ls /etc/pki/ca-trust/source/anchors/`, SAN musi zawierać `127.0.0.1`: `./scripts/gen-certs.sh IP:127.0.0.1`, potem `install-server-service.sh` |
| Samba: brak logowania | `testparm -s`, `getenforce`, `sudo restorecon -R /srv/samba` |
| Agent nie widzi udziału | `testparm -s`, ścieżki bez symlinków, `systemctl status smb` |
| Dashboard pusty | tunel SSH działa? `curl --cacert ... /api/v1/events?limit=5` na Almie |
