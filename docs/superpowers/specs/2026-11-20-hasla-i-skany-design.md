# Etap 2: hasła z prób SSH i wykrywanie skanów portów

Data: 2026-11-20. Status: **do akceptacji**. Drugi z czterech etapów (1 schemat/wersja/dev, **2 hasła i skany**,
3 alerty e-mail, 4 podpisane wydania/autoupdate/instalator/testy/dashboard/hardening).
Opiera się na etapie 1: blok `event`, katalog typów, `hp_event_from_log` (`agent/src/event.c`).

## 1. Po co

Parytet z OpenCanary w dwóch miejscach, opisanych w `docs/POROWNANIE-OPENCANARY.md` (luki 2 i 3):
- **Hasła z prób logowania** dają wiedzę o kampaniach (jakie słowniki, jakie hasła). Prawdziwy `sshd` nie loguje
  próbowanych haseł, więc dziś mamy tylko `Failed password for NAME from IP`.
- **Skany portów** (nmap SYN/NULL/XMAS/FIN). Agent czyta połączenia przez `NETLINK_SOCK_DIAG`, więc nie widzi
  skanów SYN ani krótkich połączeń, a skan zamkniętych portów nie zostawia śladu.

Dane z tego etapu zasilą alerty (etap 3).

## 2. Cele, nie-cele, anty-cele

**Cele**
- Zdarzenie `auth.attempt` z próbowanym hasłem dla SSH, z IP, użytkownikiem i wynikiem.
- Zdarzenie `net.scan` po przekroczeniu progu, z IP źródłowym, liczbą portów, rodzajem skanu i oknem czasu.
- Persona honeypota bez zmian dla atakującego (prawdziwy `sshd`, port 22, brak zmiany bannera).

**Nie-cele**
- Hasła SMB (w SMB hasło nie istnieje w postaci jawnej; zostaje nazwa użytkownika, jak dziś). Skróty NTLM odłożone.
- Własna atrapa usługi SSH, osobny kolektor (OpenCanary), przechwytywanie pakietów przez `AF_PACKET`.
- Alerty (etap 3) i zmiany dashboardu poza ewentualnym pokazaniem nowych typów, jeśli to tanie.

**Anty-cele (porażka, nawet gdy technicznie działa)**
- Zapisanie hasła **udanego** logowania (konto `backup_srv`, prawdziwi użytkownicy).
- Pogorszenie logowania prawdziwych kont (hook PAM nie może blokować ani opóźniać uwierzytelniania).
- Zalanie serwera raportami przy skanie 65 535 portów (jeden `net.scan` na skanującego i okno).

## 3. Podejścia (wybrane przez właściciela: wariant A obu części)

**Hasła:** A hook PAM na prawdziwym `sshd` (wybrane); B osobny kolektor SSH na innym porcie (odpada: nie pokrywa portu 22).
**Skan:** A log zapory czytany przez agenta, próg po stronie agenta (wybrane); B `AF_PACKET` w agencie (odpada: więcej
kodu i uprawnień); C każdy pakiet jako raport, próg na serwerze (odpada: zalew).

## 4. Projekt

### 4.1 Hasła (propozycje wykonawcze oznaczone *moja decyzja*)

- Skrypt `scripts/hp-pam-log` (instalowany do `/usr/local/libexec/`), wywoływany z `pam_exec.so expose_authtok quiet`.
  Czyta hasło ze stdin, bierze `PAM_USER` i `PAM_RHOST` i wysyła linię do syslogu: `logger -p authpriv.info -t hp-pam`.
  Trafia do `/var/log/secure`, który agent już czyta. Hasło w linii jest kodowane base64 (hasła mogą zawierać
  spacje, cudzysłowy i znaki nowej linii). *Moja decyzja.*
- Hook jest wpięty tak, by uruchamiał się **tylko po nieudanym** sprawdzeniu hasła przez `pam_unix`
  (wzorzec `auth [success=1 default=ignore] pam_unix.so` i następny wpis `pam_exec`, który przy sukcesie jest pomijany).
  Dzięki temu hasło udanego logowania nigdy nie jest zapisywane. Dokładne wpięcie w stos PAM na AlmaLinux (`substack
  password-auth`) trzeba sprawdzić na prawdziwej maszynie (sekcja 6).
- Agent: nowy typ `auth.attempt` (kategoria `authentication`, severity `medium`, outcome `failure`) z blokiem
  `event.credential: {"password": "..."}` (`null` dla pozostałych typów). Linie `hp-pam:` są parsowane w `event.c`
  razem z istniejącym parserem `sshd`. Dla tej samej próby powstają dwa zdarzenia (`auth.failure` z logu sshd
  i `auth.attempt` z PAM); to świadome, bo to dwa niezależne źródła. *Moja decyzja.*
- Hasło nie trafia do pól tekstowych poza `credential.password` i surowej treści logu, którą agent wysyła już dziś.
- Zmiana schematu jest **addytywna w v2** (opcjonalne `credential`), `VERSION` rośnie do 0.3.0. *Moja decyzja.*

### 4.2 Skany

- Reguły: `firewall-cmd --set-log-denied=all` (firewalld loguje odrzucone pakiety do dziennika jądra, na Almie
  `/var/log/messages`, który agent już czyta). Bez własnych reguł `nftables`. Dotyczy to tylko pakietów do zamkniętych
  portów, co jest właściwym sygnałem skanu; skan otwartych portów 22/139/445 nadal widać jako `net.connection`.
- Agent: parser linii zapory (`SRC=`, `DPT=`, flagi TCP) w `event.c`, stan w pamięci: tablica `src IP -> zbiór portów
  docelowych` z oknem czasu. Po przekroczeniu progu agent wysyła **jedno** `net.scan` na skanującego i okno, potem
  wycisza go do końca okna. Rodzaj skanu z flag: SYN, NULL, XMAS, FIN, `unknown`.
- Próg i okno: domyślnie 10 różnych portów w 10 s, zmienne w konfiguracji agenta. *Moja decyzja.*
- Typ `net.scan`: kategoria `network`, severity `medium`, `outcome: unknown`, `src.ip` ustawione, `dst.port` `null`;
  liczba portów i rodzaj skanu w nowym polu `event.detail` (obiekt). *Moja decyzja.*
- Ograniczenie stanu: tablica ma stały górny rozmiar (np. 1024 źródeł); po przepełnieniu najstarsze wpisy są wypierane.

### 4.3 Serwer i dokumentacja

- `EventValidator`: dozwolone typy `auth.attempt`, `net.scan`; walidacja `credential` i `detail`. Zły kształt w v2 daje 400,
  jak dotąd. Statystyki `by_event_type` obejmują nowe typy bez zmian.
- `ReportStore`: `net.scan` liczy się do wykrywania atakującego (`fast_enum` w `/api/attackers` już istnieje; nie dublować).
- Aktualizacja: `docs/schema/event-v2.schema.json`, `server/docs/api.md`, `DOKUMENTACJA-TECHNICZNA.md`,
  `agent/README.md`, `README.md`, instalator (`samba_structure/setup-honeypot.sh`: PAM i `set-log-denied`).

## 5. Testy

- C: parser linii `hp-pam:` (zwykłe hasło, hasło z spacją i `=`, puste hasło, uszkodzony base64) i linii zapory (SYN, NULL,
  XMAS, FIN, IPv6 pominięte lub obsłużone jawnie); próg skanu (9 portów brak zdarzenia, 10 portów jedno, dalsze porty w oknie
  nie dają drugiego, po oknie znów można); przepełnienie tablicy źródeł.
- Test negatywny hasła: linia z udanym logowaniem (`Accepted password`) **nie** może wytworzyć `auth.attempt`.
- Serwer: v2 z `auth.attempt` i `net.scan` przyjęty, zły `credential` odrzucony; przykłady w `server/examples/` przechodzą
  test schematu.
- Test na prawdziwej Almie (sonda akceptacyjna): zły login istniejący użytkownik, nieistniejący użytkownik, dobre hasło
  (brak wpisu), logowanie kluczem (brak wpisu), `nmap -sS` na zamknięte porty (jedno `net.scan`).

## 6. Do sprawdzenia przy wykonaniu (`zakładam`, nie `sprawdzone`)

- Czy PAM przekazuje hasło także dla nieistniejącego użytkownika w `sshd` z `UsePAM yes`.
- Jak wpiąć warunek „tylko po porażce" w stos `sshd` na AlmaLinux 9/10 (substack) tak, by nie zepsuć logowania.
- Czy `firewalld --set-log-denied` na Almie zapisuje do `/var/log/messages` (a nie tylko do dziennika journald) i w jakim
  formacie, oraz czy SELinux nie blokuje `logger` w hooku.
- Formaty linii zapory dla NULL/XMAS/FIN w `LOG` firewalld.

## 7. Zostawione wykonawcy

- Dokładne nazwy pól `credential` i `detail`, układ tablicy źródeł skanu, sposób konfiguracji progu.
- Czy dashboard pokazuje `auth.attempt` i `net.scan` (tylko jeśli zmiana mała).

## 8. Ryzyka

- Zapisywane hasła mogą należeć do prawdziwych ludzi, którzy pomylili cel (literówka, nie ten host). Hasła są przechowywane
  tylko na serwerze honeypota i dostępne dla jego administratora; zabezpiecz magazyn tak jak raporty z treścią plików.
- Hook PAM działa w ścieżce uwierzytelniania; błąd skryptu nie może zmieniać wyniku (`optional`, `quiet`, brak `requisite`).
