Program jest usługą użytkową dla AlmaLinux 9.8 i 10: wykrywa udziały Samby, obserwuje pliki i logi, przechowuje migawki, generuje JSON oraz wysyła raporty przez zweryfikowane HTTPS. Nie jest modułem jądra ani biblioteką do bezpośredniego linkowania. Do integracji z innym systemem służy odbiornik raportów HTTPS.

## 1. Zawartość

| Ścieżka | Przeznaczenie |
| --- | --- |
| `src/`, `include/` | Implementacja C i publiczne deklaracje |
| `tests/` | Testy jednostkowe, awarii, HTTPS i właściwości ELF |
| `third_party/cJSON/` | Biblioteka używana przez testy, z oryginalnymi informacjami licencyjnymi |
| `packaging/` | Jednostka systemd i przykład nadpisania parametrów |
| `Makefile` | Budowanie, testowanie, instalacja i czyszczenie |
| `../docs/dzialanie-systemu.md` | Szczegółowy opis działania agenta, schematu raportów i znanych ograniczeń |

Pakiet nie zawiera binariów, symboli diagnostycznych, zebranych logów, migawek, kolejki raportów ani lokalnych ustawień narzędzi programistycznych.

## 2. Wymagania i kompilacja

Zalecane środowisko: AlmaLinux 9.8 lub 10, GNU make >= 4.3, GCC i glibc, Linux z obsługą `openat2`. Na Almie 9 (GCC 11) Makefile domyślnie używa `_FORTIFY_SOURCE=2`; na nowszym kompilatorze zbuduj z `FORTIFY_LEVEL=3`.

```sh
sudo dnf install gcc make binutils libcurl-devel openssl-devel libtdb-devel samba ca-certificates python3 openssl
make
make check
make release
make check-release
```

Biblioteki systemowe: libcurl, libcrypto, libtdb i pthread. Python oraz program `openssl` służą testom. Jeżeli menedżer pakietów nie znajduje zależności, sprawdź repozytoria pakietów deweloperskich właściwe dla swojej instalacji; nie zastępuj bibliotek przypadkowymi nagłówkami lub plikami z innego systemu.

Wyniki:

- `build/honeypot` — program do prac deweloperskich;
- `build/release/honeypot` — binarium produkcyjne bez symboli diagnostycznych;
- `build/release/honeypot.debug` — pasujące symbole diagnostyczne, uprawnienia 0600;
- `build/release/honeypot.full` — pełny lokalny wariant diagnostyczny.

`make check-release` obejmuje istniejące testy, w tym I/O, migawki, awarie zapisu, czyszczenie buforów i 126 przypadków odtworzenia pliku z diffu. Kontroluje też PIE, pełne RELRO, niewykonywalny stos, ochronę stosu, FORTIFY i zgodność oddzielnych symboli diagnostycznych. Test HTTPS wymaga lokalnych gniazd i może jawnie zgłosić `SKIP`, jeśli środowisko je blokuje. `SKIP` nie oznacza sprawdzonej komunikacji TLS.

```sh
make clean
```

Usuwa wyłącznie wygenerowany katalog `build/`.

## 3. Konfiguracja agenta i odbiornika

Program może wystartować bez argumentów. Domyślne wartości znajdują się w `include/config.h`:

| Makro | Domyślnie |
| --- | --- |
| `AGENT_ID` | `"alma10-01"` |
| `DEST_IP` | `"127.0.0.1"` |
| `DEST_PORT` | `443` |
| `HEARTBEAT_INTERVAL` | `60` sekund |

Administrator może nadpisać identyfikator i cel przez `--id`, `--ip`, `--port`. Nie ma argumentu CLI zmieniającego katalog stanu ani monitorowane źródła.

Przykład wartości kompilacyjnych — adres `192.0.2.10` jest przykładowy, zastąp go adresem własnego odbiornika:

```sh
make clean
make release CPPFLAGS='-DAGENT_ID=\"agent-01\" -DDEST_IP=\"192.0.2.10\" -DDEST_PORT=443 -DHEARTBEAT_INTERVAL=60'
make check-release CPPFLAGS='-DAGENT_ID=\"agent-01\" -DDEST_IP=\"192.0.2.10\" -DDEST_PORT=443 -DHEARTBEAT_INTERVAL=60'
```

Wszystkie kolejne wywołania `make` dla tej wersji wykonuj z takimi samymi `CPPFLAGS`; po zmianie wartości wykonaj `make clean`.

Aktualna implementacja heartbeat dodaje ±15% do bazowego interwału. To faktyczne zachowanie kodu przekazanego w pakiecie.

Odbiornik musi obsłużyć `POST https://IP:PORT/events`, JSON schema_version 1 i odpowiedzieć końcowym kodem HTTP 2xx dopiero po przyjęciu raportu. Certyfikat musi mieć zaufany łańcuch i adres IP odbiornika w SAN. Weryfikacja TLS pozostaje włączona. Odbiornik nie jest częścią projektu. Domyślny cel to loopback; bez lokalnego odbiornika raporty pozostają w kolejce.

Deduplicuj raporty po `report_id`; transmisja może być ponawiana. Raporty zawierają treści plików i logów — zabezpiecz odbiornik i jego magazyn danych.

## 4. Instalacja i usługa systemd

Najpierw sprawdź instalację do katalogu tymczasowego, bez uruchamiania usługi:

```sh
make install DESTDIR=/tmp/sys-auditd-stage
```

Dla własnych ustawień kompilacyjnych dodaj do tego polecenia te same `CPPFLAGS` co podczas budowania. Plik `honeypot.debug` zachowaj prywatnie, osobno dla każdej wdrażanej wersji; nie jest automatycznie instalowany.

Na docelowym serwerze, po zakończeniu testów i przygotowaniu odbiornika:

```sh
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now sys-auditd.service
sudo systemctl status sys-auditd.service
```

`make install` wybiera wersję produkcyjną i sam nie uruchamia usługi. Instaluje:

- `/usr/local/sbin/sys-auditd` — 0700, root:root;
- `/etc/systemd/system/sys-auditd.service` — 0600, root:root;
- `/var/lib/sys-auditd` — 0700, root:root, stan i trwała kolejka raportów.

Przy niestandardowych `CPPFLAGS` upewnij się, że instalujesz wcześniej zbudowaną wersję z tymi samymi ustawieniami. Przykład nadpisania parametrów usługi znajduje się w `packaging/sys-auditd.conf.example`.

Usługa uruchamia się automatycznie po włączeniu jej przez `systemctl enable`, startuje po sieci i jest restartowana przy awarii. `SIGTERM` i `SIGINT` kończą pracę z zachowaniem zatwierdzonej kolejki. Diagnostyka konsolowa jest wyciszona; obserwuj status systemd, heartbeat oraz raporty o lukach obserwacji. Samo `active` nie potwierdza wykrycia wszystkich źródeł ani dostarczenia raportów.

## 5. Mapa kodu i zasady dalszych zmian

- `main.c` — cykl życia, sygnały, wątek wysyłający i odświeżanie źródeł.
- `config.c` — parametry startowe, natywny parser Samby i źródła logów.
- `monitor.c` — rekursywne inotify i blokowy odczyt logów.
- `snapshot.c` — migawki, dowody z logów, trwałe raporty i aktualizacja baz porównawczych.
- `diff.c` — natywny tekstowy LCS z ograniczeniem kosztu; większe rdzenie zmian otrzymują kompletny hunk zastępczy.
- `io.c` — kontrolowane otwieranie plików, uprawnienia, pełne zapisy i synchronizacja.
- `protocol.c` — kodowanie JSON/base64, znaczniki czasu i identyfikatory raportów.
- `port.c` — strumieniowe HTTPS i usuwanie raportu dopiero po potwierdzeniu.
- `network.c`, `connections.c`, `heartbeat.c` — kontekst IP/ARP, obserwacja TCP i żywotność.

Zachowuj prefiks `hp_`, dwie spacje wcięcia i sprawdzanie błędów. Nie zmieniaj źródeł cJSON razem z kodem agenta. Generator raportów danego magazynu ma jednego autora; wątek wysyłający czyta wyłącznie zatwierdzone pliki. Nie osłabiaj weryfikacji TLS, ograniczeń ścieżek ani zasady zatwierdzania raportu przed aktualizacją migawki. Treści logów i plików wymazuj z własnych buforów przez `explicit_bzero` przed ich zwolnieniem.

## 6. Ograniczenia i testy na serwerze

Parser nie odtwarza całej semantyki Samby: obsługuje statyczny podzbiór `smb.conf`, lokalne konta tdbsam v4 lub smbpasswd oraz wybrane podstawienia `[homes]`. Nieobsługiwane konfiguracje i źródła muszą być widoczne w raportach statusu. Restrykcyjne otwieranie ścieżek odrzuca symlinki, także w systemowych plikach include. Szczegóły i limity są w `../docs/dzialanie-systemu.md`.

Obserwacja TCP korzysta z okresowych migawek tabeli gniazd. Może pominąć krótkie połączenia i nie dowodzi wywołania `accept()`. Adres MAC z lokalnej pamięci ARP jest kontekstem, nie dowodem sprawstwa; dla zdalnego klienta może być niedostępny.

Przed wdrożeniem sprawdź na docelowej Almie: rzeczywistą konfigurację Samby i `[homes]`, rotację logów rsyslog, SELinux w trybie enforcing, akceptację i odrzucanie certyfikatów, brak odbiornika, zapełnienie dysku oraz restart usługi. Projekt nie konfiguruje Samby, audytu, rsyslog ani SELinux automatycznie. Stan zawiera migawki i raporty, więc nie usuwaj go podczas aktualizacji; przed migracją wykonaj prywatną kopię.

Lokalne testy i zabezpieczenia ELF nie zastępują weryfikacji środowiska produkcyjnego.
