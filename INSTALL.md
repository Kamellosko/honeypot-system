# Instalacja od zera: honeypot na AlmaLinux 9.8 + test z Linux Mint

Wersja instrukcji, w której atakującym (maszyną testową) jest **Linux Mint XFCE** zamiast Kali.

Jedna maszyna (Alma, hostname `fs01`) robi wszystko: Samba-wabik, agent, serwer i dashboard.
Mint tylko łączy się do Samby i generuje zdarzenia.

```
Mint ──SMB/SSH──► Alma fs01 [ Samba │ agent sys-auditd │ serwer sysmon-collector + dashboard ]
Twój komputer ──SSH (tunel)──► dashboard na https://127.0.0.1:8443/
```

Polecenia oznaczone **[Alma]** wpisujesz na Almie, **[Mint]** na maszynie testowej z Mintem, **[Host]** na swoim komputerze (tym, na którym działa VirtualBox).

W przykładach adres Almy to `192.168.56.102`. U Ciebie może być inny: sprawdź `ip -4 addr` na Almie
(szukaj `192.168.56.x`) i podstaw własny.

---

## 0. Maszyny wirtualne (VirtualBox)

### 0.1 Sieć host-only **[Host]**
**File → Tools → Network Manager → Host-only Networks → Create.** Ma powstać `vboxnet0`, np. `192.168.56.1/24`, z włączonym DHCP.
Jeśli VirtualBox zgłasza brak uprawnień:

```bash
sudo modprobe vboxnetadp vboxnetflt
echo '* 192.168.56.0/21' | sudo tee /etc/vbox/networks.conf
```

### 0.2 Alma
- Typ: Linux / Red Hat 64-bit, 2 CPU, 2–4 GB RAM, dysk 20 GB.
- W kreatorze w polu **ISO Image** wskaż `AlmaLinux-9.8-x86_64-dvd.iso`.
- **Adapter 1: NAT** (internet dla `dnf` i `mvn`).
- **Adapter 2: Host-only Adapter, Name: `vboxnet0`**: tędy łączy się Mint i Ty (SSH).
  Ustawiasz w **Settings → Network → Adapter 2** przy wyłączonej maszynie i zatwierdzasz **OK**.
- Instalacja: utwórz użytkownika z uprawnieniami administratora (sudo).

### 0.3 Mint (maszyna testowa)
- Linux Mint XFCE, 1–2 CPU, 1–2 GB RAM, dysk 10–15 GB.
- Adapter 1: NAT, Adapter 2: Host-only `vboxnet0` (jak wyżej).
- W instalatorze pole "domain name" (jeśli się pojawi) zostaw puste.

### 0.4 Adresy IP
**[Alma]** po instalacji:

```bash
ip -4 addr
```

Mają być dwa interfejsy: `enp0s3` (`10.0.2.15`, NAT) i `enp0s8` (`192.168.56.x`, host-only).
Adres `192.168.56.x` to `<IP_ALMY>`. Jeśli `enp0s8` nie ma adresu albo go brak:

```bash
sudo nmcli device connect enp0s8
ip -4 addr
```

**[Mint]** to samo: `ip -4 addr` i zapisz swój adres `192.168.56.x` (`<IP_MINTA>`).

Adresy przydziela DHCP, więc po restarcie mogą się zmienić.

> Zrób **snapshot** Almy po tym kroku ("czysty system").

### 0.5 SSH z hosta (opcjonalnie, wygodne wklejanie poleceń)
**[Alma]**

```bash
sudo dnf install -y openssh-server
sudo systemctl enable --now sshd
```

**[Host]**

```bash
ssh <uzytkownik>@<IP_ALMY>
```

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

Wariant A: z GitHuba (repo musi być dostępne bez logowania):

```bash
git clone -b afteraudit3 https://github.com/Kamellosko/honeypot-system.git ~/honeypot-system
```

Wariant B: kopia z Twojego komputera. **[Host]**, w folderze nadrzędnym projektu:

```bash
scp -r honeypot-system-skrypty <uzytkownik>@<IP_ALMY>:~/honeypot-system
```

**[Alma]** Wszystkie dalsze polecenia wykonuj w tym folderze i **nie rozdzielaj** `agent/`, `server/`, `dashboard/`, `scripts/`:

```bash
cd ~/honeypot-system
ls            # agent  dashboard  scripts  server ...
```

> Po skopiowaniu z hosta usuń stare artefakty, żeby zbudować wszystko świeżo:
> `rm -rf server/target server/certs agent/build`

## 3. Serwer i dashboard **[Alma]**

Uwaga na składnię: `-DskipTests` pisze się **razem**, bez spacji po `-`.

```bash
cd ~/honeypot-system/server
mvn -DskipTests package                    # ma być BUILD SUCCESS, powstaje target/honeypot-server.jar
./scripts/gen-certs.sh IP:127.0.0.1        # powstają certs/server-keystore.p12 i certs/ca.crt
cd ..
sudo ./scripts/install-server-service.sh
```

(Tekst po `#` to komentarz, nie wpisuj go. Przy `Permission denied` uruchom skrypt przez `bash ./scripts/...`.)

Sprawdź:

```bash
systemctl status sysmon-collector --no-pager
curl --cacert server/certs/ca.crt https://127.0.0.1:8443/api/v1/stats
```

Ma być `active (running)` i JSON z licznikami (same zera to normalne; dziwne znaki po JSON-ie to tylko artefakt terminala).

## 4. Samba (wabik) **[Alma]**

Wymyśl 3 hasła (słabe, ale wiarygodne, w stylu `Lato2024!`) i podstaw je w miejsce `HASLO1`, `HASLO2`, `HASLO3`.
**Nie zapisuj ich w repozytorium.** Zapamiętaj `HASLO1`: użyjesz go w teście z Minta.
Żeby hasła nie trafiły do historii powłoki, możesz je zapisać w pliku (jeden wpis `login:haslo:grupy` na linię, uprawnienia 600) i podać `SMB_USERS_FILE=/ścieżka/plik` zamiast `SMB_USERS=...`. Usuń plik po instalacji.

```bash
cd ~/honeypot-system
sudo SMB_USERS='jkowalski:HASLO1:pracownicy anowak:HASLO2:pracownicy,ksiegowosc mwisniewska:HASLO3:pracownicy,kadry' \
     ./scripts/setup-samba-honeypot.sh
sudo HP_HOSTNAME=fs01 HP_DOMAIN=firma.local ./scripts/setup-persona.sh
```

Otwórz nowy terminal albo wpisz `exec bash`: prompt ma pokazywać `fs01`.

Panel `cockpit` (port 9090) nie pasuje do wabika, wyłącz go:

```bash
sudo firewall-cmd --permanent --remove-service=cockpit && sudo firewall-cmd --reload
```

Sprawdź:

```bash
systemctl status smb nmb --no-pager
sudo testparm -s | head -30
ls /srv/samba                        # Dokumenty  Faktury  Kadry
sudo firewall-cmd --list-all         # usługi: samba i ssh, BEZ portu 8443
```

Wymagania agenta względem Samby (skrypt je ustawia, nie zmieniaj ich ręcznie):
- `log file = /var/log/samba/log.smbd` i `log level = 1 auth:3 auth_audit:3`: bez tego w logu nie ma wpisów o logowaniach;
- `map to guest = Never`: bez tego nieudane logowania nie wyglądają jak błędy uwierzytelnienia;
- ścieżki udziałów muszą być istniejącymi katalogami, bez symlinków, z `available = yes`.

## 5. Agent **[Alma]**

```bash
cd ~/honeypot-system
sudo AGENT_ID=fs01 ./scripts/install-agent-service.sh ./agent
```

`AGENT_ID` ma zawierać tylko `A-Za-z0-9._-` (max 64 znaki), inaczej serwer odrzuci wszystkie raporty.

Sprawdź:

```bash
systemctl status sys-auditd --no-pager
sudo ls /var/lib/sys-auditd/            # snapshots  pending
```

Po około minucie agent ma być widoczny jako online:

```bash
curl --cacert server/certs/ca.crt https://127.0.0.1:8443/api/v1/agents | jq .
sudo ls /var/lib/sys-auditd/pending | wc -l          # ma być 0 (pusta kolejka)
```

Jeśli kolejka rośnie: `sudo journalctl -u sys-auditd -n 30 --no-pager`.

> Zrób **snapshot** Almy ("system gotowy").

## 6. Test z Minta **[Mint]**

Zainstaluj narzędzia:

```bash
sudo apt update && sudo apt install -y smbclient nmap
```

Test (podstaw `<IP_ALMY>` i `HASLO1`):

```bash
smbclient -L //<IP_ALMY> -N                                   # lista udziałów
smbclient //<IP_ALMY>/Dokumenty -U jkowalski%zle -c ls        # złe hasło
smbclient //<IP_ALMY>/Dokumenty -U 'jkowalski%HASLO1' -c ls   # dobre hasło
echo test > /tmp/x.txt
smbclient //<IP_ALMY>/Dokumenty -U 'jkowalski%HASLO1' -c 'put /tmp/x.txt x.txt'
```

Opcjonalnie w menedżerze plików Minta (Thunar): `smb://<IP_ALMY>/Dokumenty`.
Skan portów, który Alma zobaczy w sieci: `nmap -sV <IP_ALMY>`.

Zdarzenia na Almie **[Alma]**:

```bash
sudo tail -n 10 /var/lib/sysmon/events.jsonl | jq -c '{source,operation,analysis}'
sudo ls /var/lib/sys-auditd/pending | wc -l          # ma być ~0
```

Oczekiwane:
- `network / tcp_connection_observed` z adresem IP Minta,
- `log / append` z wpisem o złym haśle,
- `share / create` po wgraniu pliku.

Po teście ze złym hasłem sprawdź ręcznie:

```bash
sudo grep -iE 'LOGON_FAILURE|WRONG_PASSWORD|NO_SUCH_USER' /var/log/samba/log.smbd | tail
```

Klasyfikacja `authentication_failure` rozpoznaje tylko `NT_STATUS_LOGON_FAILURE`. Jeśli w logu jest inny tekst
(np. `NT_STATUS_WRONG_PASSWORD`), trzeba rozszerzyć listę w `hp_report_simple` (`agent/src/snapshot.c`).

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
- **Izolacja:** po instalacji możesz odłączyć Adapter 1 (NAT) w Almie.
- **Realizm VM:** MAC i ciągi DMI ustawia się w VirtualBoxie (`VBoxManage modifyvm ... --macaddress1`, `VBoxManage setextradata ... DmiSystemVendor`).

## 9. Rozwiązywanie problemów

| Objaw | Co sprawdzić |
|---|---|
| VM nie startuje: brak `vboxnet0` | punkt 0.1 |
| Alma nie ma adresu `192.168.56.x` | Adapter 2 = Host-only `vboxnet0`, potem `sudo nmcli device connect enp0s8` |
| `mvn` zgłasza brak `pom.xml` albo nieznaną opcję | jesteś w folderze `server`? flaga to `-DskipTests` bez spacji |
| Mint nie łączy się z Almą | oba w `vboxnet0`; `ping <IP_ALMY>` z Minta; `sudo firewall-cmd --list-all` na Almie (usługa `samba`) |
| Agent offline na dashboardzie | `journalctl -u sys-auditd -n 50`, rosnąca kolejka w `pending` = serwer nie odbiera |
| Raporty w `*.rejected` | niepoprawny `AGENT_ID` albo zła koperta, zob. `server/docs/api.md` |
| TLS: błąd certyfikatu | `ls /etc/pki/ca-trust/source/anchors/`, SAN musi zawierać `127.0.0.1`: `./scripts/gen-certs.sh IP:127.0.0.1`, potem `install-server-service.sh` |
| Samba: brak logowania | `testparm -s`, `getenforce`, `sudo restorecon -R /srv/samba` |
| Dashboard pusty | tunel SSH działa? `curl --cacert ... /api/v1/events?limit=5` na Almie |
