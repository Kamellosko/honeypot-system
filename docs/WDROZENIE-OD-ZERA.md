# Wdrożenie od zera na nowej maszynie (wariant „Dział Finansów")

Ta instrukcja prowadzi przez całość: od czystego hiperwizora do działającego wabika z agentem, dashboardem i testami.
Zbiera w jednym miejscu to, co powstawało po kawałku. Obowiązuje wariant z katalogu `samba_structure/`
(serwer plików działu finansów, konto-przynęta `backup_srv`, okruszek w ukrytym udziale). Starszy wariant `fs01`
(`INSTALL.md`, `setup-samba-honeypot.sh`) jest osobny i **nie wolno mieszać obu** na jednej maszynie.

Polecenia mają znacznik, na której maszynie się je wpisuje:

| Znacznik | Maszyna |
|---|---|
| **[Host]** | Twój komputer, na którym działa VirtualBox |
| **[Alma]** | wabik (AlmaLinux 9.8) |
| **[Test]** | maszyna „atakująca" (Linux Mint lub inna, z `smbclient`) |

Prompt zdradza, gdzie jesteś: `kamil@kamil-lp:~$` to host, `user@user-VirtualBox:~$` to maszyna testowa,
`[svc-admin@fs-finanse ~]$` to Alma jako administrator, a `[backup_srv@fs-finanse ~]$` to Alma w skórze „atakującego".
Komendy do serwera i agenta wpisuj tylko w oknie administratora.

## 0. Jak to działa

```
atakujący ──SMB/SSH──► Alma (fs-finanse)
                       ├─ Samba: udziały Wspolny, Finanse, Archiwum$, Zarzad + full_audit
                       ├─ sshd: konto-przynęta backup_srv (hasło leży w okruszku), admin svc-admin tylko kluczem
                       ├─ agent sys-auditd (C): pliki, logi, połączenia TCP → raporty HTTPS
                       └─ kolektor sysmon-collector (Java, 127.0.0.1:8443) → events.jsonl, /api/*, dashboard
Ty (host) ──ssh -L──► dashboard https://127.0.0.1:<port>/
```

Okruszek: hasło `backup_srv` leży w `Archiwum$/IT/kopia_zapasowa.sh`. Odczyt pliku (widoczny dzięki `full_audit`)
i późniejsze udane logowanie na `backup_srv` dają w `GET /api/attackers` poziom `confirmed`, czyli pewny atak.

## 1. Przygotowanie hiperwizora (VirtualBox)

### 1.1 Plan adresów

Wybierz sieć „firmową" dla wabika i trzymaj się jej. W przykładach jest domyślna sieć host-only VirtualBoxa;
jeśli ją zmienisz, podstaw swoje adresy wszędzie, gdzie widzisz `192.168.56.x`.

| Rola | Adres w przykładach |
|---|---|
| Host | `192.168.56.1` |
| Alma (wabik) | `192.168.56.102` (z DHCP; sprawdzisz `ip -4 addr`) |
| Maszyna testowa | `192.168.56.101` |
| „Stacje IT" w zasianej historii logowań | `192.168.56.20`, `.21`, `.35` (poza zakresem DHCP `.101`-`.254`, nie należą do żadnej maszyny) |

### 1.2 Sieć host-only

**File → Tools → Network Manager → Host-only Networks → Create.** Ma powstać `vboxnet0` z włączonym DHCP.
Gdy VirtualBox zgłasza brak uprawnień:

```bash
sudo modprobe vboxnetadp vboxnetflt
echo '* 192.168.56.0/21' | sudo tee /etc/vbox/networks.conf
```

Na hoście sprawdź, czy nie przekazuje ruchu do prawdziwej sieci (ma być `0`):

```bash
cat /proc/sys/net/ipv4/ip_forward
```

### 1.3 Maszyna Alma

- Typ: Linux / Red Hat 64-bit, **2 CPU, 4 GB RAM** (przy 2 GB swap się zapychał), dysk dynamiczny, im większy, tym
  mniej podejrzanie dla „serwera plików" (np. 100 GB; zajmuje tylko tyle, ile użyte).
- **Adapter 1: NAT** (tymczasowo, na instalację pakietów), **Adapter 2: Host-only `vboxnet0`**.
- W kreatorze w polu **ISO Image** wskaż `AlmaLinux-9.8-x86_64-dvd.iso`.
- Instalacja: wybierz **Minimal Install** (bez GUI). Gdy zainstalujesz „Server with GUI", GNOME zdradza wabik
  (`gnome-shell` w procesach), a usunięcie grupy poleceniem `dnf group remove` jest blokowane (chroni `dnf`, `sudo`, `yum`).
  Przy GUI skrypt z kroku 8 wyłącza je, ale czystsza jest instalacja bez niego.
- W instalatorze utwórz **konto tymczasowe** z uprawnieniami administratora (w tej instrukcji `user`). Zniknie w kroku 11.
- Nazwa hosta z instalatora nie ma znaczenia, skrypt ustawi własną.

### 1.4 Maszyna testowa

Dowolny Linux z `smbclient` (np. Linux Mint XFCE, 1-2 GB RAM). **Adapter 1: NAT, Adapter 2: Host-only `vboxnet0`**.
Po instalacji: `sudo apt install -y smbclient nmap`. Windows też się nada: `\\<IP_ALMY>\Wspolny` w Eksploratorze.

> Zrób **snapshot** Almy po instalacji systemu (nazwa np. „czysty-system"). Kolejne snapshoty: po kroku 7 i po kroku 9.

## 2. Klucz SSH administratora **[Host]**

Konto administratora `svc-admin` loguje się **tylko kluczem** (nie ma hasła do SSH), więc klucz musi istnieć, zanim
uruchomisz skrypt wabika. Sprawdź, czy już go masz:

```bash
cat ~/.ssh/id_ed25519.pub
```

Brak pliku (`No such file`)? Wygeneruj go (Enter na wszystkie pytania; hasło do klucza możesz ustawić, jeśli chcesz):

```bash
ssh-keygen -t ed25519
```

Wynik `cat` to **jedna linia** z trzech części (typ, klucz, komentarz), np.
`ssh-ed25519 AAAAC3Nza...IM2kP kamil@kamil-lp`. Skopiuj całą linię, wkleisz ją w kroku 6.
Kopiujesz wyłącznie plik z końcówką **`.pub`**. Plik `id_ed25519` bez `.pub` to klucz **prywatny**: nigdy go nie kopiuj
na Almę, do czatu ani do repozytorium.

## 3. Pierwsze połączenie z Almą

**[Alma]**, konsola VirtualBoxa, zaloguj się kontem tymczasowym i sprawdź adres:

```bash
ip -4 addr
```

Szukaj interfejsu z adresem z Twojej sieci host-only (`192.168.56.x`, zwykle `enp0s8`). Gdy nie ma adresu:
`sudo nmcli device connect enp0s8`. Zapisz ten adres, to `<IP_ALMY>`. Włącz SSH (w Minimal Install bywa wyłączony):

```bash
sudo dnf install -y openssh-server && sudo systemctl enable --now sshd
```

Od tej chwili pracuj z hosta przez SSH (wygodne wklejanie poleceń):

```bash
ssh user@<IP_ALMY>
```

## 4. Pakiety i kod **[Alma]**

```bash
sudo dnf install -y epel-release dnf-plugins-core
sudo dnf config-manager --set-enabled crb
sudo dnf install -y git gcc make curl-devel openssl-devel libtdb-devel java-21-openjdk-devel maven jq rsync
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
echo 'export JAVA_HOME=/usr/lib/jvm/java-21-openjdk' >> ~/.bashrc
java -version
```

Ostatnia komenda ma pokazać Javę 21 (przy innej: `sudo alternatives --config java`, wybierz 21).

```bash
git clone -b afteraudit5 https://github.com/Kamellosko/honeypot-system.git ~/hp
cd ~/hp
```

Wszystko poniżej wykonuj w `~/hp` jako konto tymczasowe, o ile nie napisano inaczej. Kopie z innego źródła (np. `rsync`
z hosta) działają tak samo, byle `agent/`, `server/`, `dashboard/`, `scripts/` i `samba_structure/` leżały obok siebie.

## 5. Serwer i dashboard **[Alma]**

```bash
cd ~/hp/server && mvn -q -DskipTests package && ./scripts/gen-certs.sh IP:127.0.0.1 && cd ..
sudo ./scripts/install-server-service.sh
```

`mvn` ma zakończyć się bez komunikatu (jest `target/honeypot-server.jar`), a `gen-certs.sh` utworzy `certs/` (certyfikat
ważny 10 lat). Instalator kopiuje pliki do `/opt/sysmon` i `/etc/sysmon`, tworzy usługę i **restartuje** ją.
Sprawdzenie:

```bash
systemctl is-active sysmon-collector
curl --cacert ~/hp/server/certs/ca.crt https://127.0.0.1:8443/api/stats
```

Ma być `active` i JSON z licznikami (same zera na początku to normalne).

## 6. Wabik: konfiguracja i skrypt **[Alma]**

### 6.1 Plik konfiguracji

```bash
cd ~/hp/samba_structure && cp honeypot.conf.example honeypot.conf && nano honeypot.conf
```

Zapis w `nano`: **Ctrl+O**, Enter, **Ctrl+X**. Plik jest w `.gitignore`, **nigdy go nie commituj**.

| Pole | Co wpisać |
|---|---|
| `HP_HOSTNAME` | nazwa serwera, np. `fs-finanse` |
| `HP_COMPANY` | nazwa firmy do MOTD (zostaw coś wiarygodnego, nie puste) |
| `HP_ADMIN_USER` | konto administratora, domyślnie `svc-admin` |
| `HP_ADMIN_PUBKEY` | **cała linia** klucza `.pub` z kroku 2, w cudzysłowie |
| `HP_SHELL_DECOY_PASS` | hasło SSH konta-przynęty `backup_srv`; trafia jawnie do pliku-okruszka, ma wyglądać ludzko |
| `HP_SAMBA_USERS` | pięć kont Samby w formacie `"login\|opis\|haslo"`; zmieniasz **tylko hasła** (ostatnia część) |
| `HP_LOGIN_HISTORY_IPS` | 2-3 wymyślone adresy „stacji IT" z **tej samej sieci co serwer**, poza zakresem DHCP, np. `( "192.168.56.20" "192.168.56.21" "192.168.56.35" )` |

Zasady dla haseł: ludzkie, ale nie ze słownika (`password`, `123456`, `Lato2024!`). **Zabronione znaki:** `|`, `"`, `$`
(psują konfigurację). Dozwolone m.in. litery, cyfry, `.`, `_`, `#`, `!`, `-`. Każde konto ma inne hasło.
Linia z zasianiem historii musi się nazywać dokładnie `HP_LOGIN_HISTORY_IPS` (łatwo zgubić `H`).

**Zapisz hasła na hoście** (menedżer haseł lub plik poza repozytorium), bo w kroku 11 usuwasz konfigurację z maszyny,
a skrypt ich nie wypisuje.

Sprawdź składnię i obecność pól, zanim uruchomisz skrypt:

```bash
bash -n honeypot.conf && grep -oE '^[A-Z_]+=' honeypot.conf | tr '\n' ' '
```

### 6.2 Uruchomienie

```bash
cd ~/hp && sudo ./samba_structure/setup-honeypot.sh
```

Skrypt instaluje pakiety, tworzy konta (`svc-admin`, `backup_srv`, pięć kont Samby), katalogi i pliki z datami rozłożonymi
w czasie, okruszek, `smb.conf` z `full_audit`, reguły `auditd`, konfigurację `sshd`, zasiewa historię logowań i ustawia
zaporę. Trwa kilka minut. **Krok „SELinux dla udziałów" nie wypisuje postępu przez 1-3 minuty. Nie przerywaj go Ctrl+C**
(przerwanie zostawia politykę w niepełnym stanie; gdy to zrobisz, uruchom skrypt ponownie, jest powtarzalny).
Zakończenie sygnalizuje napis `GOTOWE`.

### 6.3 Sprawdź logowanie administratora, zanim zamkniesz stare okno **[Host, nowe okno terminala]**

```bash
ssh svc-admin@<IP_ALMY>
```

Ma wpuścić **bez pytania o hasło** (kluczem) i pokazać baner oraz MOTD firmy. Jeśli nie wpuszcza, nie zamykaj sesji konta
tymczasowego, tylko popraw `HP_ADMIN_PUBKEY` i uruchom skrypt ponownie.

### 6.4 Hasło `svc-admin` do `sudo` **[Alma, konto tymczasowe]**

`svc-admin` nie ma hasła, więc `sudo` go nie wpuści. Nadaj hasło z konta tymczasowego. Służy ono tylko do `sudo`,
logowanie hasłem przez SSH dla tego konta pozostaje zablokowane:

```bash
sudo passwd svc-admin
```

Sprawdź w oknie `svc-admin`: `sudo whoami` ma zwrócić `root`.

## 7. Agent **[Alma]**

Agent instaluje się **po** wabiku (zasiana historia logów nie trafi wtedy do raportów jako zdarzenia):

```bash
cd ~/hp && sudo AGENT_ID=fs-finanse ./scripts/install-agent-service.sh ./agent
```

`AGENT_ID` dopuszcza `A-Za-z0-9._-` i do 64 znaków (inny znak: serwer odrzuci wszystkie raporty). Instalator buduje agenta
jako użytkownik wywołujący `sudo`, instaluje CA serwera w magazynie zaufania, instaluje usługę i ją **restartuje**.

```bash
systemctl is-active sys-auditd
```

Po około minucie agent jest `online`:

```bash
curl --cacert ~/hp/server/certs/ca.crt https://127.0.0.1:8443/api/agents | python3 -m json.tool
```

Zasada na później: gdy uruchamiasz instalator jako **inny** użytkownik niż właściciel repozytorium (np. jako `svc-admin`
na repozytorium konta tymczasowego), zbuduje się jako ten inny użytkownik i padnie na braku uprawnień. Wtedy wymuś
właściciela: `sudo bash -c 'export SUDO_USER=<wlasciciel>; cd <katalog repo> && AGENT_ID=... ./scripts/install-agent-service.sh ./agent'`.

## 8. Wygląd serwera **[Alma, przez SSH]**

```bash
cd ~/hp && sudo ./scripts/setup-realism.sh
```

Wyłącza środowisko graficzne (jeśli jest), ukrywa procesy innych użytkowników (`hidepid=2`), zmniejsza swappiness,
czyści swap i ukrywa MAC w adresie IPv6. Potem:

```bash
sudo reboot
```

Po restarcie sprawdź jako zwykły użytkownik, że `ps -e | wc -l` daje kilka procesów, a jako administrator:

```bash
systemctl is-active smb nmb sys-auditd sysmon-collector
```

Cztery razy `active`. Gdyby po restarcie nie dało się zalogować (rzadko, `hidepid` z `logind`), z konsoli VirtualBoxa usuń
z `/etc/fstab` linię zaczynającą się od `proc /proc` i wykonaj `mount -o remount,hidepid=0 /proc`.

## 9. Testy z maszyny testowej **[Test]**

Podstaw `<IP>` i hasła z kroku 6. Znak `$` w nazwie udziału wymaga apostrofów **wokół całej ścieżki**.

| # | Komenda | Oczekiwany wynik |
|---|---|---|
| 1 | `smbclient //<IP>/Wspolny -N -c ls` | dwa pliki (`INSTRUKCJA_dostepu.txt`, `ogloszenia.txt`) |
| 2 | `smbclient //<IP>/Finanse -U 'a.kowalska%HASLO' -c ls` | katalogi `Faktury`, `Rozliczenia_VAT`, `Budzet`... |
| 3 | `smbclient //<IP>/Finanse -U 'a.kowalska%zle' -c ls` | `NT_STATUS_LOGON_FAILURE` (zapis jako `authentication_failure`) |
| 4 | `smbclient '//<IP>/Archiwum$' -U 'a.kowalska%HASLO' -c 'get IT/kopia_zapasowa.sh /tmp/k.sh' && cat /tmp/k.sh` | skrypt z linią `PASS=` |
| 5 | `ssh backup_srv@<IP>` z hasłem z `PASS=` | wpuszcza; `ps -e \| wc -l` mały, `ls -a` pokazuje `.bash_history` |
| 6 | w tej sesji `sudo -l` lub `sudo whoami` | odmowa: konto-przynęta nie ma `sudo` (tak ma być) |

Na Almie (jako `svc-admin`) sprawdź wykrycie:

```bash
sudo curl --cacert /home/<wlasciciel-repo>/hp/server/certs/ca.crt https://127.0.0.1:8443/api/attackers | python3 -m json.tool | head -30
```

Adres maszyny testowej ma mieć `"confirmed": true` (udane logowanie `backup_srv`) i `"breadcrumb_read": true`
(odczyt okruszka). Zdarzenia z `audit.log` mają klasyfikację `samba_audit`, a ruch z hosta jest poziomem `suspicious`
lub `contact` (to Twoje własne logowania SSH i tunel, patrz niżej).

Twoje testy zostają w historii (`auth_failures`, `confirmed`, wpisy w dzienniku). Przed oddaniem wabika „do użytku"
wyczyść zdarzenia, żeby dziennik zawierał tylko prawdziwy ruch (kasuje wszystkie dotychczasowe zdarzenia, także testowe):

```bash
sudo systemctl stop sysmon-collector && sudo truncate -s 0 /var/lib/sysmon/events.jsonl && sudo systemctl start sysmon-collector
```

## 10. Dashboard **[Host]**

```bash
ssh -L 8443:127.0.0.1:8443 svc-admin@<IP_ALMY>
```

Okno zostaw otwarte, w przeglądarce na hoście otwórz `https://127.0.0.1:8443/`, zaakceptuj ostrzeżenie o własnym CA
i odśwież z pominięciem pamięci podręcznej (**Ctrl+F5**). `bind ... Address already in use` oznacza, że port 8443
na hoście jest zajęty (np. stary tunel): użyj innego, np. `-L 9443:127.0.0.1:8443` i adresu `https://127.0.0.1:9443/`.

Tunel i logowania administratora **są widoczne dla agenta** jako połączenia na porty 22 i 8443. Wabik ma stać
w izolowanej sieci, a własne wpisy rozpoznajesz po adresie hosta (`192.168.56.1`).

## 10a. Alarmy e-mail

Serwer wysyła mail, gdy adres IP wchodzi na poziom SKANER (`fast_enum`), BRUTE FORCE, PRZYNĘTA (próba logowania
na `backup_srv` albo odczyt pliku-przynęty) lub POTWIERDZONY. Pojedyncze nieudane logowania, sondy i nieistniejące konta
maila nie wysyłają (to głównie szum, np. Windows sam logujący się do udziału). Jeden IP dostaje mail tylko przy wejściu
na wyższy poziom; limit to 60 maili na godzinę, a zdarzenia z historii wczytanej przy starcie nie wysyłają maili.
W treści nie ma haseł. Domyślnie alarmy są wyłączone.

### 10a.1 Skrzynka w laboratorium **[Host]**

Poczta trafia do lokalnej skrzynki na hoście, czytanej Thunderbirdem; nic nie wychodzi do internetu.

```bash
cd ~/honeypot-system && sudo ./scripts/setup-mail-host.sh
```

Skrypt instaluje Postfix i Dovecot, przyjmuje pocztę tylko od wabika (`HP_IP`, domyślnie `192.168.56.6`) i z hosta,
udostępnia skrzynkę `~/Maildir` przez IMAP tylko na `127.0.0.1` i wysyła mail testowy (`OK: mail testowy jest w ...`).

Thunderbird: nowe konto pocztowe, adres `<login>@localhost`, **Konfiguruj ręcznie**:

| | Serwer | Port | Bezpieczeństwo | Uwierzytelnianie |
|---|---|---|---|---|
| IMAP | `localhost` | 143 | STARTTLS | zwykłe hasło (hasło konta na hoście) |
| SMTP | `localhost` | 25 | STARTTLS | brak (albo zwykłe hasło, jeśli „brak” niedostępne) |

Certyfikat jest samopodpisany: potwierdź wyjątek bezpieczeństwa.

### 10a.2 Włączenie na wabiku **[Alma]**

Dopisz na końcu `/etc/sysmon/collector.properties` (instalator serwera zachowuje linie `alert.*` przy aktualizacji):

```properties
alert.enabled=true
alert.smtp.host=192.168.56.1
alert.smtp.port=25
alert.from=honeypot@fs-finanse.local
alert.to=<login-na-hoscie>@localhost
```

```bash
sudo /usr/lib/jvm/java-21-openjdk/bin/java -jar /opt/sysmon/collector.jar --test-alert /etc/sysmon/collector.properties
sudo systemctl restart sysmon-collector
```

`--test-alert` wysyła jeden mail „[honeypot] test alarmu” i kończy się kodem 0. Błąd `Connection refused` albo timeout:
host nie słucha na `192.168.56.1:25` (sprawdź na hoście `ss -ltn | grep :25`) albo zapora hosta blokuje Almę.
Po restarcie w `journalctl -u sysmon-collector` jest linia `alert: mail via 192.168.56.1:25 to 1 recipient(s)`.

Opcjonalnie: `alert.smtp.starttls=true`, `alert.smtp.user=`, `alert.smtp.password=` (serwer wymagający logowania),
`alert.max_per_hour=60`, kilku odbiorców w `alert.to` po przecinku.

### 10a.3 Sieć docelowa

Zmieniasz tylko `alert.smtp.*`, `alert.from` i `alert.to`, potem restart usługi; kod się nie zmienia.
Najlepiej, gdy firmowy serwer pocztowy przyjmuje pocztę z IP wabika **bez hasła** (hasło w `collector.properties`
odczyta każdy, kto zdobędzie roota na wabiku). Przy samym Microsoft 365 administrator dodaje łącznik SMTP dla adresu
wabika albo stawia się przekaźnik jak w 10a.1. W zaporze sieci wabika zezwól na dokładnie jedno połączenie:
wabik → serwer pocztowy, port 25 lub 587.

## 11. Utwardzenie końcowe i sprzątanie

Robisz to **na końcu**, gdy wszystko działa i masz zapisane hasła. Kolejność ma znaczenie.

1. **Snapshot** Almy przed sprzątaniem (np. „przed-sprzataniem").
2. **Usuń `honeypot.conf` z maszyny.** Zawiera jawnie hasła wszystkich przynęt i hasło `backup_srv`:

   ```bash
   sudo shred -u /home/<konto-tymczasowe>/hp/samba_structure/honeypot.conf
   ```

3. **Usuń konto tymczasowe (`user`).** To konto z hasłem i `sudo` to otwarte drzwi z rootem do wabika: `user` to jedna
   z pierwszych nazw, które sprawdza każdy skaner SSH. W oknie `svc-admin` (po sprawdzeniu, że `sudo whoami` daje `root`):

   ```bash
   sudo passwd -l user && sudo gpasswd -d user wheel
   ```

   To blokuje hasło i odbiera `sudo`. Gdy repozytorium jest już niepotrzebne (punkt 4), usuń konto razem z katalogiem domowym:

   ```bash
   sudo userdel -r user
   ```

   Dopóki zostawiasz konto (np. do aktualizacji), **zawsze zablokuj mu hasło i `sudo`**, nigdy nie zostawiaj `123`.

4. **Usuń repozytorium i kopie z maszyny.** Katalog `~/hp` opisuje, jak zbudowany jest wabik (skrypty, `docs/`,
   `samba_structure/`). Atakujący z powłoką nie może go znaleźć:

   ```bash
   sudo rm -rf /home/<konto-tymczasowe>/hp /tmp/*.sh /tmp/snapshot*.c
   ```

   Po tym potrzebujesz źródeł na hoście do aktualizacji (rozdział 12). Kolektor i agent działają niezależnie od repozytorium
   (pliki w `/opt/sysmon`, `/etc/sysmon`, `/usr/local/sbin/sys-auditd`).

5. **Hiperwizor (maszyna wyłączona):**
   - **Adapter 1 (NAT): Not attached.** Znika `10.0.2.15` z `ip a`, która zdradza VirtualBoxa. Odłączaj dopiero po
     ostatniej instalacji pakietów.
   - Zakres sieci host-only zmień na „firmowy" (File → Tools → Network Manager) i zaktualizuj adresy w instrukcji.
   - **MAC i DMI** (ślady VirtualBoxa: prefiks `08:00:27`, producent i model): `VBoxManage modifyvm "<VM>" --macaddress2 <12 cyfr hex>`
     oraz `VBoxManage setextradata "<VM>" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "<producent>"`
     (i analogicznie `DmiSystemProduct`). **Nie testowane w tym projekcie.** Sprawdź w dokumentacji VirtualBoxa, zanim użyjesz.
     Część śladów (flaga hypervisora w CPU) i tak pozostaje widoczna dla roota.
   - RAM 4 GB. **Uptime:** nie wyłączaj Almy poleceniem „Shutdown", tylko zapisuj stan maszyny („Save the machine state"),
     bo wtedy uptime nie zeruje się, a po przywróceniu snapshotu cofa się do chwili jego zrobienia.

6. **Kopia dowodów poza maszynę (zalecana):** `scripts/sync-events.sh` kopiuje `events.jsonl` rsyncem na inny komputer.
   Klucz leży na wabiku, więc na odbiorcy ogranicz go w `authorized_keys`
   (`restrict,command="rrsync -wo /srv/honeypot-logs" ssh-ed25519 ...`) i rób tam własne, dzienne kopie, bo sam klucz
   mógłby nadpisać plik. Opis w nagłówku skryptu. **Nie testowane w tym projekcie.**

7. **Izolacja sieci.** Każde połączenie z portami 22, 139 i 445 jest dla agenta zdarzeniem (także Twoje i niewinnych
   komputerów). Trzymaj wabik w osobnej sieci bez zwykłych komputerów i bez trasy do reszty.

8. **Snapshot** końcowy („gotowy-wabik").

## 12. Aktualizacje po usunięciu repozytorium

Źródła trzymasz na hoście (repozytorium z GitHuba). Wgrywasz tylko to, co się zmieniło, przez `svc-admin`:

| Co | Jak |
|---|---|
| Dashboard (pliki statyczne) | **[Host]** `scp dashboard/* svc-admin@<IP>:/tmp/` ; **[Alma]** `sudo install -m 644 -t /opt/sysmon/dashboard /tmp/index.html /tmp/app.js /tmp/style.css` ; Ctrl+F5 w przeglądarce |
| Serwer (Java) | zbuduj jar na hoście (`cd server && mvn -q -DskipTests package`), `scp server/target/honeypot-server.jar svc-admin@<IP>:/tmp/` ; **[Alma]** `sudo install -m 644 /tmp/honeypot-server.jar /opt/sysmon/collector.jar && sudo systemctl restart sysmon-collector` |
| Agent (C) | kompilacja wymaga `gcc`, `make`, `libcurl`, `openssl`, `libtdb` w wersjach Almy 9. Najczystsze: buduj na osobnej maszynie Alma 9 (nie na wabiku) i wgraj binarkę: `sudo install -m 0700 agent /usr/local/sbin/sys-auditd && sudo systemctl restart sys-auditd` |

Kompilator na wabiku jest drobnym śladem; stąd zalecenie osobnej maszyny budującej. Skrypty instalacyjne
(`install-*.sh`) po usunięciu repozytorium nie są potrzebne do zwykłych aktualizacji.

## 13. Najczęstsze problemy

| Objaw | Przyczyna i rozwiązanie |
|---|---|
| `No match for argument: samba-vfs-modules` | pakiet nie istnieje w Almie 9 (nazwa z Debiana); w skrypcie na gałęzi `afteraudit5` jest już usunięty, w starszych usuń go z linii `dnf install` |
| `tree connect failed: NT_STATUS_UNSUCCESSFUL` przy każdym udziale | `full_audit` ma w `smb.conf` nazwy operacji nieznane w Samba 4.x (`opendir`, `mkdir`, `rmdir`, `rename`, `unlink`); poprawna lista jest w `setup-honeypot.sh`, w działającej konfiguracji: `sudo sed -i 's/^   full_audit:success = .*/   full_audit:success = connect disconnect fdopendir mkdirat unlinkat open openat read pread write pwrite renameat/' /etc/samba/smb.conf && sudo testparm -s >/dev/null && sudo systemctl restart smb nmb` |
| `NT_STATUS_LOGON_FAILURE` na prawidłowym koncie | złe hasło: `sudo smbpasswd <konto>` ustawia nowe |
| `Permission denied` przy `ssh backup_srv` | hasło konta różni się od `PASS=` w okruszku: `sudo passwd backup_srv` i wpisz **dokładnie** hasło z pliku |
| `sudo` jako `svc-admin` nie przyjmuje hasła | konto nie ma hasła do `sudo`: z konta tymczasowego `sudo passwd svc-admin` |
| `backup_srv nie jest w pliku sudoers` | tak ma być: konto-przynęta nie ma uprawnień administratora |
| `curl: error setting certificate file ...` | `~` wskazuje katalog zalogowanego konta, a repozytorium jest w innym: podaj pełną ścieżkę (`/home/<wlasciciel>/hp/server/certs/ca.crt`) i użyj `sudo` |
| `bind ... Address already in use` przy tunelu | port zajęty na hoście: `ss -ltnp \| grep 8443` albo inny port lokalny |
| Skrypt „zawisł" w kroku SELinux | to normalne (1-3 min), nie przerywaj |
| Nowy kod nie działa po instalatorze | starsze instalatory używały `enable --now`, które nie restartuje działającej usługi; obecne restartują |
| `make: Brak dostępu` w `agent/build` | katalog zrobił root; instalator przejmuje go przez `chown`, ręcznie: `sudo chown -R $USER: agent/build` |
| Dashboard pusty lub stare adresy | Ctrl+F5; API jest pod `/api/*` (bez `v1`); sprawdź `curl ... /api/stats` na Almie |
| `ip a` pokazuje `10.0.2.15` | karta NAT; odłącz Adapter 1 w VirtualBoxie |
| `last` pokazuje dziwne wpisy | skrypt na `afteraudit5` zasiewa poprawny `wtmp`; w starszych użyj poprawionej wersji |
| `dnf group remove "Server with GUI"` blokuje | grupa obejmuje `dnf`, `sudo`, `yum`; nie wymuszaj, użyj Minimal Install lub kroku 8 |

## 14. Czego ta instrukcja nie obejmuje i co niesprawdzone

- Całość nie była dotąd przejechana jednym ciągiem na zupełnie nowej maszynie: powstała ze składania kroków wykonywanych
  po kolei na jednej maszynie testowej. Pierwsze wdrożenie od zera potraktuj jako próbę i miej snapshoty.
- **Nie sprawdzone:** zmiana MAC i DMI w VirtualBoxie, `sync-events.sh`, `wsdd` z EPEL (opcjonalne), gość w `Wspolny`
  z nowymi Windowsami (domyślnie blokują logowanie gościa), konfiguracja `PasswordAuthentication` pod wpływem
  innych reguł `sshd`.
- Zakładamy jedną maszynę Alma 9.8 z VirtualBoxa. Na Almie 10 trzeba zbudować agenta z `FORTIFY_LEVEL=3` (patrz `agent/README.md`).
- Moduł audytu Samby wymaga wersji, w której `full_audit` zna nazwy `fdopendir`, `mkdirat`, `unlinkat`, `renameat`
  (Samba 4.23 na Almie 9.8 to potwierdza). Dla innej wersji sprawdź `strings /usr/lib64/samba/vfs/full_audit.so`.
- Agent i kolektor nie mają uwierzytelniania między sobą: chroni je nasłuch na `127.0.0.1`.
