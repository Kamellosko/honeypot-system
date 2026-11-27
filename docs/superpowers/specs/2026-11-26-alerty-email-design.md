# Etap 3: alarmy e-mail

Data: 2026-11-26. Status: **zaakceptowany w rozmowie, do przeglądu**. Trzeci z czterech etapów po 20 listopada
(1 schemat/wersja/dev, 2 hasła i nmap, **3 alerty e-mail**, 4 wydania/autoupdate/instalator).

## 1. Po co

Dziś o ataku wiadomo tylko wtedy, gdy ktoś akurat patrzy na dashboard. Dodatkowo `events.jsonl` leży na wabiku,
więc atakujący z rootem może skasować ślady. Mail wysłany w chwili ataku wychodzi poza maszynę: nawet po wyczyszczeniu
logów zostaje adres IP, czas i powód alarmu.

## 2. Cele, nie-cele, anty-cele

**Cele**
- Mail, gdy adres IP osiąga poziom zagrożenia wart reakcji (tabela w p. 4).
- Konfiguracja serwera pocztowego wyłącznie w `collector.properties`, bez zmian kodu przy przejściu z laboratorium
  do sieci docelowej.
- Polecenie testowe wysyłające jeden mail próbny.

**Nie-cele**
- Powiadomienia przez Slack/Teams/webhook.
- Panel loginów, GeoIP, podpisane wydania (etap 4).

**Anty-cele** (porażka, nawet jeśli „działa”)
- Zasypanie skrzynki: mail za każdą pojedynczą nieudaną próbę albo za historię wczytaną przy starcie.
- Alarmy z szumu sieci lokalnej (Windows sam łączy się z udziałem kontem pracownika i dostaje `NT_STATUS_LOGON_FAILURE`).
- Hasła w mailu (także próbowane przez atakującego: w sieci lokalnej to może być prawdziwe hasło pracownika).
- Przyjmowanie raportów od agenta blokowane przez wolny lub niedostępny serwer pocztowy.

## 3. Ograniczenia

- Alma nie ma internetu (tylko sieć host-only, NAT odłączony) i ma tak zostać.
- Laboratorium: maile trafiają do **lokalnej skrzynki na hoście** (Postfix + Dovecot) czytanej Thunderbirdem.
  Wysyłka przez Gmail do skrzynki uczelnianej została odrzucona przez użytkownika jako zbyt pracochłonna
  (Microsoft 365 blokuje SMTP AUTH, Gmail wymaga osobnego konta z hasłem aplikacji; adres `@id.gle` nie może być
  nadawcą: `SPF -all`, DMARC `p=reject`).
- Jar serwera budujemy na hoście (Maven na Almie nie ma dostępu do repozytorium), więc nowa zależność jest
  wkładana do zacienionego (shaded) jara.

## 4. Kiedy idzie mail

Poziomy oceny (`/api/attackers`), od najwyższego:

| Poziom | Kiedy | Mail |
|---|---|---|
| `confirmed` (POTWIERDZONY) | udane logowanie na konto-przynętę | tak |
| **`bait` (PRZYNĘTA), nowy** | dowolna próba logowania na konto-przynętę (`backup_srv`, z `detection.confirm.accounts`) albo odczyt pliku-przynęty | tak |
| `brute_force` | 5+ nieudanych logowań w 10 min | tak |
| `fast_enum` (SKANER) | `net.scan` od agenta albo 3+ porty w 60 s | tak |
| `suspicious` | pojedyncze nieudane logowanie, sonda SSH, nieistniejące konto | nie |
| `contact` | samo połączenie | nie |

Odczyt pliku-przynęty dziś daje tylko `suspicious`; przechodzi na `bait`. Próba na `backup_srv` jest rozpoznawana
po nazwie użytkownika w `event.user.name` zdarzeń `auth.failure`, `auth.invalid_user` i `auth.attempt`.

Zasady (zmiana z 2026-11-27: **mail zbiorczy co minutę** zamiast jednego maila na IP i poziom):
- Każde zdarzenie od adresu, który w chwili zdarzenia jest na poziomie z kolumny „tak”, trafia do bufora alarmów.
  Co `3600 / alert.max_per_hour` sekund (domyślnie 60 s) serwer wysyła **jeden** mail ze wszystkim z bufora;
  pusty bufor = brak maila. Ataki trwające godzinę dają najwyżej 60 maili.
- Wejście adresu na wyższy poziom niż poprzednio widziany jest w mailu oznaczone „NOWY POZIOM”.
  Atakujący wracający po przerwie znów trafia do maili (nie ma pamięci „już zgłoszony” blokującej wysyłkę).
- Adresy `suspicious` i `contact` nie trafiają do bufora (szum z Windowsów i pojedyncze próby).
- Zdarzenia wczytywane z `events.jsonl` przy starcie nie trafiają do bufora; ustawiają tylko poziom „widziany”,
  więc po restarcie dalszy atak nie jest oznaczany jako „NOWY POZIOM”.
- Nieudana wysyłka: zawartość bufora zostaje i idzie w następnym mailu; bufor ma limit 1000 adresów
  (nadmiar liczony i zgłaszany jako „pominięto N”).
- Adresy loopback są pomijane (jak dziś w ocenie atakujących).

## 5. Treść maila

- Temat: `[honeypot <agent_id>] <N> atakujących, <M> zdarzeń (<HH:mm>–<HH:mm>)`.
- Treść (zwykły tekst), dla każdego adresu od najgroźniejszego: IP, poziom po polsku, „NOWY POZIOM” jeśli dotyczy,
  zdarzenia z tego okresu zliczone po typie i serwisie (np. `12× SMB · nieudane logowanie  konta: administrator, a.kowalska`,
  do 5 nazw kont), liczniki łączne z `/api/attackers`; na końcu wskazówka, jak otworzyć dashboard (tunel SSH).
- Nigdy: hasła (`event.credential`), surowa treść logów.

## 6. Architektura

```
agent → POST /api/events → ReportStore.index() → ocena atakującego
                                         └─ zdarzenie od groźnego IP → AlertService.activity(notice)  (bez blokowania)
AlertService: bufor per IP + zegar co 60 s → jeden mail zbiorczy → Mailer (Jakarta Mail, SMTP)
```

- `ReportStore` po każdym `index()` dla każdego dotkniętego IP na poziomie z `ALERT_LEVELS` przekazuje `AlertNotice`
  (widok atakującego, czy to nowy poziom, bieżące zdarzenie bez hasła). W trakcie wczytywania historii przekazywanie jest wyłączone.
- `AlertService` sumuje zdarzenia w buforze (krótka sekcja krytyczna, bez I/O) i co interwał wysyła jeden mail
  z wątku zegara. Błąd wysyłki: wpis w logu usługi, bufor wraca i idzie w następnym mailu.
- `Mailer`: Jakarta Mail (implementacja Eclipse Angus). STARTTLS i logowanie opcjonalne.
- `alert.enabled=false` (domyślnie): nic nie jest wysyłane, ocena działa jak dotąd.

## 7. Konfiguracja (`collector.properties`)

```properties
alert.enabled=true
alert.smtp.host=192.168.56.1      # laboratorium: przekaźnik Postfix na hoście
alert.smtp.port=25
alert.smtp.starttls=false
alert.smtp.user=                  # puste = bez logowania
alert.smtp.password=
alert.from=honeypot@fs-finanse.local   # laboratorium: dowolny, poczta nie wychodzi poza host
alert.to=pawel@localhost               # skrzynka alarmowa; można kilka, po przecinku
alert.max_per_hour=60
```

Polecenie testowe: `java -jar collector.jar --test-alert /etc/sysmon/collector.properties` wysyła jeden mail próbny
i kończy się kodem 0 (wysłano) lub 1 (błąd z opisem).

## 8. Laboratorium: lokalna skrzynka na hoście

```
serwer Java (Alma) ─SMTP 25─► Postfix na hoście (192.168.56.1) ─► Maildir użytkownika ─IMAP 127.0.0.1─► Dovecot ─► Thunderbird
```

- Postfix: dostarczanie tylko lokalne (`relayhost` pusty, `default_transport = error`, więc nic nie wychodzi
  do internetu), `home_mailbox = Maildir/`, `inet_interfaces` = `127.0.0.1, 192.168.56.1`,
  `mynetworks` = `127.0.0.0/8, 192.168.56.6/32` (nie otwarty przekaźnik).
- Dovecot: IMAP tylko na `127.0.0.1`, `mail_location = maildir:~/Maildir`, logowanie hasłem konta systemowego.
- Thunderbird: nowe konto IMAP `localhost:143`, użytkownik systemowy hosta.
- Zapora hosta: port 25 tylko z `192.168.56.6`.
- Instrukcja krok po kroku w dokumentacji wdrożenia; instalację na hoście wykonuje użytkownik.

## 9. Sieć docelowa

Zmiana tylko w `collector.properties` (adres, port, TLS, ewentualnie login) i restart usługi. Typowe przypadki:
firmowy serwer pocztowy przyjmujący pocztę z IP wabika bez hasła (zalecane), łącznik SMTP w Microsoft 365
ustawiony przez administratora, albo przekaźnik jak w laboratorium. Zapora sieci wabika: dokładnie jedno połączenie
wabik → serwer pocztowy (25/587). Hasło SMTP na wabiku to ryzyko (root może je odczytać), więc jeśli logowanie jest
konieczne, osobne konto z prawem wysyłki tylko do skrzynki alarmowej.

## 10. Podejścia rozważone

| Podejście | Za | Przeciw | Decyzja |
|---|---|---|---|
| A. Gmail jako nadawca przez przekaźnik na hoście | maile także na telefonie | osobne konto Gmail z 2FA i hasłem aplikacji; tworzenie konta sprawiało kłopoty | porzucone (za dużo pracy) |
| **B. Skrzynka lokalna (Postfix + Dovecot) + Thunderbird** | nic nie wychodzi z komputera, bez kont zewnętrznych i internetu | alarm widoczny tylko na tym komputerze | **wybrane** |
| Wysyłka z konta studenckiego (Microsoft 365) | jedno konto | SMTP AUTH wyłączone, OAuth wymaga administratora uczelni | niemożliwe |
| Bezpośrednio do MX bez logowania | bez konta | port 25 często blokowany, brak SPF/DMARC → spam/odrzucenie | zawodne |
| Webhook/Slack | prosty kod | użytkownik chce maile | nie |

## 11. Decyzje pozostawione wykonawcy

- Dokładne odstępy ponowień i rozmiar kolejki (rozsądne wartości, stałe w kodzie).
- Układ tekstu maila w granicach p. 5.
- Rozbicie na klasy w `pl.honeypot.server.alert` (np. `AlertService`, `Mailer`, `AlertConfig`).
- Testy: reguły i limity bez sieci (atrapa `Mailer`), wysyłka SMTP przeciw lokalnemu serwerowi testowemu, jeśli tani.
