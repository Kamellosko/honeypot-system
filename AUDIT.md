# Audyt repozytorium — Honeypot System

Data: 2026-10-23. Audyt tylko do odczytu, żaden kod nie został zmieniony.

**Co robi to repo:** honeypot na jednej maszynie. Prawdziwa Samba i SSH są wabikiem. Agent w C (zamrożony, nie jest zmieniany) pilnuje udziału i logów, wysyła raporty po HTTPS do serwera Java na `127.0.0.1:8443`. Serwer zapisuje je do pliku `events.jsonl`, a dashboard pokazuje je w przeglądarce.

**Założone obciążenie:** jeden agent. Mało zdarzeń na co dzień, ale w ataku mogą przyjść serie raportów, także duże (wrzucony plik).

**Jak sprawdzano:** punkty 1–3 zweryfikowano uruchomieniem lub czytając kod agenta. Reszta pochodzi z czytania kodu, część od agentów pomocniczych. Wnioski niezgodne z kodem nie trafiły do raportu (sekcja "Czego nie wpisano").

## Spis

| # | Priorytet | Problem |
|---|-----------|---------|
| 1 | Do naprawy od razu | Jeden odrzucony raport zatrzymuje cały agent |
| 2 | Do naprawy od razu | Raport ginie, gdy zapis się nie uda |
| 3 | Do naprawy od razu | Pusty `dashboard.dir=` wystawia katalog roboczy serwera |
| 4 | Do naprawy od razu | Każdy odczyt dashboardu czyta cały plik pod blokadą zapisu |
| 5 | Powinno się naprawić | Dokumentacja opisuje stary układ dwóch maszyn |
| 6 | Powinno się naprawić | Zapis bez `fsync`, a agent już skasował kopię |
| 7 | Powinno się naprawić | Skrypt Samby może odciąć SSH |
| 8 | Powinno się naprawić | Hasło keystore: dwie nazwy zmiennej i `sudo` |
| 9 | Powinno się naprawić | Dwa miejsca w `innerHTML` bez escape |
| 10 | Powinno się naprawić | Okno "online" jest za wąskie |
| 11 | Powinno się naprawić | Szum z loopbacka w dzienniku |
| 12 | Powinno się naprawić | Sekrety zostają na honeypocie |
| 13 | Powinno się naprawić | Brak testów logiki dedup i zapisu |
| 14 | Warto zrobić | Martwe i zdublowane pliki |
| 15 | Warto zrobić | Drobne błędy dashboardu |
| 16 | Warto zrobić | Drobne rzeczy w skryptach instalacyjnych |

## Do naprawy od razu

### 1. Jeden odrzucony raport zatrzymuje cały agent
Pliki: [port.c:33-88](agent/src/port.c#L33-L88), [ReportHandler.java](server/src/main/java/pl/honeypot/server/api/ReportHandler.java)

- **Co to jest:** Agent wysyła pliki z kolejki jeden po drugim. Plik kasuje dopiero po odpowiedzi 2xx.
- **Problem:** Przy innej odpowiedzi agent przerywa pętlę i za 5 s próbuje tego samego pliku. Żaden następny raport nie wychodzi. Serwer odrzuca duże raporty: test z ~2 MB dał HTTP 400, bo domyślny limit Javalina (1 MB) jest zamieniany w 400 przez `catch` w `read()`. Atakujący wrzuca binarkę 3 MB, jej raport (base64) jest większy, i od tej chwili nic nie dochodzi. Po 90 s dashboard pokazuje agenta jako offline.
- **Fix:** W `Main` ustaw `config.http.maxRequestSize` na np. 64 MB. W `ReportHandler` nie zwracaj 4xx dla niczego, co agent mógłby wysłać. Jeśli raport jest naprawdę zepsuty, zapisz go do `rejected.jsonl` i odpowiedz 202.
- **Jeśli pominiemy:** Jeden duży upload na wabik wycisza całą detekcję.

### 2. Raport ginie, gdy zapis się nie uda
Plik: [ReportStore.java:97-100](server/src/main/java/pl/honeypot/server/store/ReportStore.java#L97-L100)

- **Co to jest:** Serwer odpowiada "duplikat" (200), gdy już widział `report_id`.
- **Problem:** Dodaje `report_id` do zbioru `seen` przed zapisem. Jeśli zapis rzuci wyjątek (dysk pełny), agent dostaje 500 i ponawia. Ponowienie trafia na "duplikat", dostaje 200 i kasuje raport, który nigdy nie trafił na dysk.
- **Fix:** Najpierw sprawdź `seen.contains`, potem `log.append`, dopiero po sukcesie `seen.add`. Wszystko pod tą samą blokadą.
- **Jeśli pominiemy:** Raporty giną dokładnie wtedy, gdy dysk się zapełnia, a więc w ataku.

### 3. Pusty `dashboard.dir=` wystawia katalog roboczy serwera
Pliki: [Main.java](server/src/main/java/pl/honeypot/server/Main.java), [ServerConfig.java](server/src/main/java/pl/honeypot/server/ServerConfig.java)

- **Co to jest:** Dokumentacja i komentarz w `server.properties` mówią: "puste = nie serwuj dashboardu".
- **Problem:** `Path.of("")` to katalog roboczy i `isDirectory` daje `true`. W teście plik z katalogu startowego zwrócił HTTP 200. Pod systemd katalogiem roboczym jest `/`, więc serwer oddawałby pliki czytelne dla użytkownika `honeypot`.
- **Fix:** Traktuj pustą wartość jak brak katalogu: `!dir.isBlank() && Files.isDirectory(dir)`. Popraw komentarz w `server.properties` i dokumenty.
- **Jeśli pominiemy:** Literówka w konfiguracji ujawnia pliki systemowe przez HTTP.

### 4. Każdy odczyt dashboardu czyta cały plik pod blokadą zapisu
Pliki: [ReportStore.java:141](server/src/main/java/pl/honeypot/server/store/ReportStore.java#L141), [JsonlLog.java:81-103](server/src/main/java/pl/honeypot/server/store/JsonlLog.java#L81-L103), [EventsQueryHandler.java](server/src/main/java/pl/honeypot/server/api/EventsQueryHandler.java)

- **Co to jest:** Dashboard co 4 s pyta o zdarzenia.
- **Problem:** `read()` parsuje cały `events.jsonl` (z base64 plików, po kilka MB na raport) pod tą samą blokadą, której potrzebuje każdy zapis. `limit` działa dopiero po wczytaniu. Bez `limit` odpowiedź zawiera całą historię. Po kilku dużych uploadach POST-y agenta czekają na przeglądanie pliku i przekraczają 30 s limitu agenta.
- **Fix:** Trzymaj w pamięci kolejkę ostatnich ~500 zdarzeń bez ciężkich pól (`content_changes.blocks`, `content`). Zwracaj ją, domyślny `limit` 200, maksimum 1000. Pełne dowody zostają w pliku.
- **Jeśli pominiemy:** Im więcej dowodów, tym wolniej działa serwer, aż agent zaczyna tracić dostawy.

## Powinno się naprawić

### 5. Dokumentacja opisuje stary układ dwóch maszyn
Pliki: [INSTALL.md](INSTALL.md) (linie ok. 16-23, 59, 107, 133, 148, 263-290), [server/README.md](server/README.md), `server/docs/deploy-two-machines.md`

- **Co to jest:** Instrukcje instalacji.
- **Problem:** Każą ustawić `server.bind=0.0.0.0`, otworzyć 8443 w firewallu i kopiować `ca.crt` na drugą maszynę. Kto pójdzie za INSTALL.md, wystawia niezabezpieczone API z dowodami, które honeypot ma ukrywać.
- **Fix:** Przepisz INSTALL.md pod jedną maszynę: bind `127.0.0.1`, brak reguły dla 8443, `sudo cp ca.crt .../anchors/ && update-ca-trust`, dashboard przez tunel SSH. Usuń `deploy-two-machines.md`. Zmień domyślny bind w `ServerConfig` z `0.0.0.0` na `127.0.0.1`.
- **Jeśli pominiemy:** Następna instalacja według dokumentu zepsuje założenie "widać tylko SSH i Sambę".

### 6. Zapis bez `fsync`, a agent już skasował kopię
Plik: [JsonlLog.java:42, 66-74](server/src/main/java/pl/honeypot/server/store/JsonlLog.java#L66-L74)

- **Co to jest:** Serwer dopisuje linię do pliku i odpowiada 201.
- **Problem:** Dane nie są wymuszone na dysk. Po awarii zasilania traci się raport, który agent już usunął. Ucięta linia bez `\n` skleja się z następną i `read()` pomija obie.
- **Fix:** Pisz przez `FileChannel` z `APPEND` i `force(false)`. Przy starcie dopisz `\n`, jeśli plik nie kończy się nowym wierszem.
- **Jeśli pominiemy:** Rzadko, ale po awarii giną najświeższe ślady ataku.

### 7. Skrypt Samby może odciąć SSH
Plik: [setup-samba-honeypot.sh](scripts/setup-samba-honeypot.sh) (sekcja firewalla)

- **Co to jest:** Skrypt zostawia w firewallu tylko usługi `ssh` i `samba` i usuwa wszystkie porty.
- **Problem:** Gdy `sshd` nasłuchuje na innym porcie niż 22, kolejne logowania są zablokowane. Skrypt używa też strefy domyślnej, a nie strefy interfejsu z sesją SSH. Usuwa przy tym `dhcpv6-client`.
- **Fix:** Odczytaj port przez `sshd -T | awk '/^port /{print $2}'` i zostaw go. Weź strefę z `firewall-cmd --get-active-zones`. Nie ruszaj `dhcpv6-client`.
- **Jeśli pominiemy:** Na zdalnej maszynie można stracić dostęp.

### 8. Hasło keystore: dwie nazwy zmiennej i `sudo`
Pliki: [gen-certs.sh](server/scripts/gen-certs.sh) (`KEYSTORE_PASSWORD`), [install-server-service.sh](scripts/install-server-service.sh) (`KEYSTORE_PASS`)

- **Co to jest:** Dwa skrypty podają to samo hasło różnymi zmiennymi.
- **Problem:** Ustawisz `KEYSTORE_PASSWORD=x` dla certów, uruchomisz instalator przez `sudo`, a ten (przez `env_reset`) wpisze domyślne `changeit`. Serwer nie wstanie ("keystore password was incorrect"). Plik z hasłem jest chwilę czytelny dla wszystkich, zanim zadziała `chmod`.
- **Fix:** Jedna nazwa zmiennej. Instalator niech sprawdzi hasło przez `openssl pkcs12 -noout -passin`. Dodaj `umask 077` przed zapisem pliku.
- **Jeśli pominiemy:** Serwer nie startuje, a komunikat nie wskazuje przyczyny.

### 9. Dwa miejsca w `innerHTML` bez escape
Plik: [app.js](dashboard/app.js) (ok. linii 81 i 118)

- **Co to jest:** Dashboard wstawia dane z raportów do HTML. Większość pól przechodzi przez `esc()`.
- **Problem:** `metadata.old_size`/`new_size` i `a.status` nie. Agent wysyła rozmiary jako liczby, więc zwykły atak tego nie wykorzysta. Lokalny proces może jednak wysłać sfałszowany raport (POST /events nie wymaga uwierzytelnienia).
- **Fix:** Opakuj oba w `esc()`, a status w `class="status-${esc(a.status)}"`.
- **Jeśli pominiemy:** Skrypt wykonałby się w przeglądarce analityka. Ryzyko niskie, naprawa to dwa słowa.

### 10. Okno "online" jest za wąskie
Pliki: [ReportStore.java](server/src/main/java/pl/honeypot/server/store/ReportStore.java) (`ONLINE_AFTER = 90 s`), [heartbeat.c:10-17](agent/src/heartbeat.c#L10-L17)

- **Co to jest:** Agent jest "online", jeśli raport dotarł w ciągu 90 s.
- **Problem:** Heartbeat idzie co 51–69 s, a pierwszy dopiero po 51–69 s od startu. Jedno spóźnione wysłanie przekreśla 90 s i dashboard pokazuje "offline" przy żywym agencie.
- **Fix:** `ONLINE_AFTER` na 180 s (trzy heartbeaty).
- **Jeśli pominiemy:** Fałszywe alarmy "offline".

### 11. Szum z loopbacka w dzienniku
Plik: [connections.c:59-84](agent/src/connections.c#L59-L84)

- **Co to jest:** Agent zgłasza każde nowe połączenie TCP do portu z nasłuchem.
- **Problem:** Serwer słucha na `127.0.0.1:8443`, więc połączenia z przeglądarki, z tunelu SSH i czasem własne dostawy agenta pojawiają się jako `tcp_connection_observed` z `peer.ip=127.0.0.1`. Każde takie zdarzenie to kolejna dostawa i szansa na następne.
- **Fix:** Agenta nie ruszamy. W dashboardzie (i w `stats`) ukryj zdarzenia sieciowe z loopbackiem jako peer.
- **Jeśli pominiemy:** Prawdziwe połączenia atakujących toną w śmieciach.

### 12. Sekrety zostają na honeypocie
Pliki: [gen-certs.sh](server/scripts/gen-certs.sh), [setup-samba-honeypot.sh](scripts/setup-samba-honeypot.sh)

- **Co to jest:** Maszyna ma być łatwa do włamania.
- **Problem:** `ca.key` i `server.key` leżą w `server/certs/`, a CA jest zaufane w całym systemie (`update-ca-trust`). Włamywacz może wystawić zaufany certyfikat dla dowolnej domeny na tej maszynie. Hasło `Decoy123!` jest w repo. Skrypt generuje też nowe CA przy każdym uruchomieniu i psuje zaufanie.
- **Fix:** Po eksporcie `.p12` usuń `ca.key` i `server.key`. Hasło wabika generuj losowo (`openssl rand -base64 18`). Nie generuj CA, jeśli już istnieje.
- **Jeśli pominiemy:** Przejęcie honeypota daje atakującemu zaufane certyfikaty.

### 13. Brak testów logiki dedup i zapisu
Katalog: `server/src/test/` (tylko `.gitkeep`)

- **Co to jest:** Deduplikacja, walidacja koperty i odbudowa stanu z pliku.
- **Problem:** Błąd z punktu 2 i kolejność "zapis, potem `seen`" nie mają testu, który by padł.
- **Fix:** Jeden test `ReportStore`: wymuszony błąd `append` nie może zablokować ponowienia. Drugi: duplikat zwraca 200 i nie dopisuje wiersza.
- **Jeśli pominiemy:** Poprawka z punktu 2 może się zepsuć przy następnej zmianie.

## Warto zrobić

### 14. Martwe i zdublowane pliki
Pliki: `docker-compose.yml`, `server/Dockerfile`, `server/deploy/honeypot-server.service`, `agent/agent_impl/`

- **Co to jest:** Pozostałości po poprzednich koncepcjach.
- **Problem:** Compose to atrapy `sleep infinity` i nginx na 8080 bez API. `Dockerfile` kopiuje nieistniejący `config/sensors.json` i wystawia port 8000. Jednostka w `deploy/` ma `ExecStart=/usr/bin/java`, czyli to samo, co przy Javie 17 dało błąd, a skrypt instalacyjny i tak generuje własną jednostkę. `agent_impl` nie ma żadnych odwołań w repo.
- **Fix:** Usuń compose, Dockerfile i `deploy/honeypot-server.service`. `agent_impl` to katalog agenta, więc decyzja należy do właściciela.
- **Jeśli pominiemy:** Ktoś uruchomi nieaktualny plik i zmarnuje czas.

### 15. Drobne błędy dashboardu
Pliki: [app.js](dashboard/app.js), [index.html](dashboard/index.html), [style.css](dashboard/style.css)

- **Co to jest:** Odświeżanie co 4 s i tabela zdarzeń.
- **Problem:** Lista agentów przebudowuje `<select>` co 4 s i zamyka rozwijaną listę. `refresh()` nie ma straży przed nakładaniem się zapytań. Tabela z 7 kolumnami nie ma przewijania w poziomie na wąskim ekranie. Wiersze nie są dostępne z klawiatury.
- **Fix:** Przebudowuj `<select>` tylko, gdy lista agentów się zmieniła. Dodaj `if (busy) return`. Owiń tabelę w `overflow-x:auto`.
- **Jeśli pominiemy:** Niewygodne korzystanie, bez wpływu na dane.

### 16. Drobne rzeczy w skryptach instalacyjnych
Pliki: [install-agent-service.sh](scripts/install-agent-service.sh), [install-server-service.sh](scripts/install-server-service.sh)

- **Co to jest:** Instalacja usług.
- **Problem:** Jednostka agenta nie czeka na `honeypot-server.service`. Domyślne `AGENT_ID` z `hostname -s` to tu `localhost`. `make` jako root zostawia w repo katalog `build/` należący do roota. `grep -q` pod `pipefail` może dać fałszywe "to nie Java 21". Ponowne uruchomienie nadpisuje ręcznie zmieniony `server.properties`.
- **Fix:** W drop-inie dodaj `After=` i `Wants=honeypot-server.service`. Wymagaj jawnego `AGENT_ID`. Sprawdzaj wersję Javy przez `ver=$(... || true)`.
- **Jeśli pominiemy:** Mało groźne, ale łatwo o pomyłkę przy ponownej instalacji.

## Czego nie wpisano

- **"Raport bez `report_id` omija dedup":** `ReportHandler` odrzuca go kodem 400 przed magazynem, więc to nie występuje.
- **"`map to guest = Bad User` zamienia każde złe hasło w gościa":** nieprawda. Dla istniejącego konta (`decoy`) złe hasło daje `NT_STATUS_LOGON_FAILURE`. Gościem zostaje tylko nieistniejąca nazwa użytkownika (np. `admin`) i dla niej błędu logowania nie ma. To wybór projektowy.
- **POST /events bez uwierzytelnienia:** nie da się tu dodać nagłówka z tajnym kluczem, bo zamrożony agent go nie wyśle. Ogranicza to dopiero limit rozmiaru (punkt 1) i bind na loopback.

## Podsumowanie

**Werdykt:** najpierw punkty 1–4. Punkty 1 i 2 mogą po cichu wyciąć cały strumień zdarzeń. Punkt 3 to realna dziura konfiguracji.

**Lean:** około -100 linii (compose, Dockerfile, jednostka z `deploy/`), `agent_impl` osobno. Zależności: 0.

**Nie sprawdzono:**
- reszty kodu agenta poza `port.c`, `connections.c`, `heartbeat.c`, `config.c` (agent zamrożony),
- skryptów na prawdziwej AlmaLinux 9.8 (firewalld, SELinux, `semanage` nigdy nie były tu uruchomione),
- twierdzenia, że bez `allow_smbd_anon_write` SELinux zablokuje zapis gościa,
- konfiguracji TLS (wersje protokołu, szyfry).

Skrypt instalacji agenta przejrzano ręcznie, bo agent pomocniczy zatrzymał się na filtrze bezpieczeństwa.
