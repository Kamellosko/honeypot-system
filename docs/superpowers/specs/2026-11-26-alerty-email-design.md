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

Zasady:
- Mail przy **wejściu** adresu na poziom z kolumny „tak” lub wyższy niż poprzednio zgłoszony. Ten sam IP na tym samym
  lub niższym poziomie nie dostaje kolejnego maila.
- Limit globalny: 60 maili na godzinę (średnio jeden na minutę); nadmiar jest liczony i zgłaszany w następnym wysłanym mailu („pominięto N”).
- Zdarzenia wczytywane z `events.jsonl` przy starcie nie wysyłają maili, ale ustawiają poziom „już zgłoszony”,
  żeby restart nie powtarzał alarmów.
- Adresy loopback są pomijane (jak dziś w ocenie atakujących).

## 5. Treść maila

- Temat: `[honeypot <agent_id>] <POZIOM> <IP>`, np. `[honeypot fs-finanse] BRUTE FORCE 192.168.56.4`.
- Treść (zwykły tekst): poziom i powód po polsku, liczniki z `/api/attackers` (nieudane logowania, w 10 min,
  porty, sonda, nieistniejące konta), pierwsze i ostatnie wystąpienie, do 10 ostatnich zdarzeń z tego IP
  (czas, typ, serwis, konto, port), wskazówka jak otworzyć dashboard (tunel SSH).
- Nigdy: hasła (`event.credential`), surowa treść logów.

## 6. Architektura

```
agent → POST /api/events → ReportStore.index() → ocena atakującego
                                         └─ zmiana poziomu → AlertService.offer(snapshot)  (bez blokowania)
AlertService: kolejka (ograniczona) + 1 wątek → reguły/limity → Mailer (Jakarta Mail, SMTP)
```

- `ReportStore` po każdym `index()` sprawdza, czy poziom danego IP wzrósł ponad ostatnio zgłoszony; jeśli tak,
  przekazuje migawkę (dane z `AttackerView` + ostatnie zdarzenia) do `AlertService`. W trakcie wczytywania historii
  przy starcie przekazywanie jest wyłączone.
- `AlertService` działa w osobnym wątku z ograniczoną kolejką; pełna kolejka = mail pominięty i policzony.
  Błąd wysyłki: 3 próby z odstępem (np. 30 s, 2 min, 10 min), potem wpis w logu usługi.
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
