# Alarmy e-mail (etap 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serwer wysyła jeden mail, gdy adres IP wchodzi na poziom zagrożenia wart reakcji (skaner, brute force, przynęta, potwierdzony), bez zasypywania skrzynki i bez blokowania przyjmowania raportów.

**Architecture:** `ReportStore` po każdym przyjętym raporcie liczy poziom dotkniętych adresów i przy wzroście ponad ostatnio zgłoszony woła `AlertSink`. `AlertService` (osobny wątek, ograniczona kolejka, limit na godzinę, ponowienia) formatuje mail i wysyła go przez `Mailer` (Jakarta Mail/Angus, zwykłe SMTP). Przy wczytywaniu historii poziomy są oznaczane jako „zgłoszone” bez wysyłki.

**Tech Stack:** Java 21, Javalin, Jackson, JUnit 5, `org.eclipse.angus:angus-mail` 2.0.3 (nowa zależność, w zacienionym jarze).

**Spec:** `docs/superpowers/specs/2026-11-26-alerty-email-design.md`

## Global Constraints

- Mail tylko dla poziomów `fast_enum`, `brute_force`, `bait`, `confirmed`; nigdy dla `suspicious` i `contact`.
- Kolejność poziomów: `confirmed`(5) > `bait`(4) > `brute_force`(3) > `fast_enum`(2) > `suspicious`(1) > `contact`(0).
- Ten sam IP dostaje mail tylko przy poziomie wyższym niż ostatnio zgłoszony; spadek i powrót nie wysyła ponownie.
- Limit `alert.max_per_hour` (domyślnie 60); nadmiar liczony i zgłaszany w następnym mailu jako „pominięto N”.
- Historia wczytana przy starcie nie wysyła maili, ale ustawia poziom „już zgłoszony”.
- Loopback pomijany (jak dziś `isLoopback`).
- W mailu nigdy: `event.credential` (hasła) ani surowe `content`.
- Temat: `[honeypot <agent_id>] <ETYKIETA> <IP>`; etykiety: `confirmed`=POTWIERDZONY, `bait`=PRZYNĘTA, `brute_force`=BRUTE FORCE, `fast_enum`=SKANER.
- `alert.enabled=false` domyślnie: zero wysyłki, zero wątków.
- Klucze konfiguracji: `alert.enabled`, `alert.smtp.host`, `alert.smtp.port` (25), `alert.smtp.starttls` (false), `alert.smtp.user`, `alert.smtp.password`, `alert.from`, `alert.to` (lista po przecinku), `alert.max_per_hour` (60).
- Kolejka 100 pozycji; ponowienia po 30 s, 2 min, 10 min, potem wpis w logu.
- Testy serwera: `cd server && mvn -q test` (kod wyjścia 0).

## Review Focus

- Restart serwera z historią zawierającą brute force: zero maili po starcie, a nowa próba z tego IP na tym samym poziomie też nie wysyła (test w Task 1).
- IP spada z `brute_force` do `suspicious` (okno 10 min mija) i wraca: brak drugiego maila (Task 1).
- Serwer pocztowy nie odpowiada: `insert()` wraca natychmiast; przy pełnej kolejce zgłoszenie jest liczone jako pominięte, nie blokuje (Task 2).
- Raport `auth.attempt` z hasłem od atakującego: hasło nie trafia do treści maila (Task 2).
- `alert.to` z kilkoma adresami i spacjami (`a@x, b@y`): oba odbiorcy dostają mail (Task 3).

---

### Task 1: Eskalacja w `ReportStore` (poziom `bait`, powiadomienia)

**Files:**
- Create: `server/src/main/java/pl/honeypot/server/store/AlertSink.java`
- Create: `server/src/main/java/pl/honeypot/server/store/AlertNotice.java`
- Modify: `server/src/main/java/pl/honeypot/server/store/ReportStore.java` (AttackerState, `index`, `insert`, `rebuild`, `attackers()`, `rank`)
- Modify: `dashboard/app.js` (wpis `bait` w `THREATS`)
- Test: `server/src/test/java/pl/honeypot/server/store/ReportStoreAlertTest.java`

**Interfaces:**
- Produces:
  - `public interface AlertSink { void escalated(AlertNotice notice); }`
  - `public record AlertNotice(String agentId, ReportStore.AttackerView attacker, String reason, List<AlertNotice.Recent> recent)` z `public record Recent(String at, String type, String service, String user, Integer port)`; `recent` najnowsze na początku, maks. 10.
  - `ReportStore.setAlertSink(AlertSink sink)` (domyślnie brak, czyli nic nie wysyła).
  - `ReportStore.ALERT_LEVELS = Set.of("fast_enum", "brute_force", "bait", "confirmed")`.
  - Nowy poziom `"bait"` w `AttackerView.threat` i nowe pole `@JsonProperty("decoy_attempt") boolean decoyAttempt` na końcu `AttackerView`.

- [ ] **Step 1: Napisz testy w `ReportStoreAlertTest`** (wzoruj pomocnik `report(...)` na `ReportStoreEventTest`; sink zbiera `List<AlertNotice>`)

```java
@Test void bruteForceSendsOneNotice()            // 5x auth.failure z 203.0.113.9 -> 1 notice, threat "brute_force", agentId "a1"
@Test void sixthFailureDoesNotResend()           // 6x -> nadal 1 notice
@Test void suspiciousDoesNotNotify()             // 1x auth.failure, 1x net.probe -> 0 notices
@Test void netScanNotifiesFastEnum()             // typedEvent("net.scan", ip) -> 1 notice "fast_enum"
@Test void decoyAccountAttemptIsBait()           // auth.failure z user.name "backup_srv" (confirmAccounts=Set.of("backup_srv")) -> threat "bait", decoyAttempt true, 1 notice
@Test void breadcrumbReadIsBait()                // content z markerem -> "bait"
@Test void escalationBruteThenConfirmedSendsTwo()// 5x failure, potem content "Accepted password for backup_srv from IP" -> 2 notices, druga "confirmed"
@Test void replayedHistoryDoesNotNotifyAndIsRemembered()
    // zapisz 5x failure do JsonlLog, nowy ReportStore na tym samym pliku + sink -> 0 notices;
    // potem insert 6. failure -> nadal 0 notices
@Test void loopbackNeverNotifies()               // 5x failure z 127.0.0.1 -> 0 notices
@Test void noticeHasRecentEventsWithoutPassword()
    // auth.attempt z credential {"password":"Tajne123"} + 4x failure -> recent.size()==5, recent.get(0) najnowszy,
    // żadne pole Recent nie zawiera "Tajne123"
```

- [ ] **Step 2: Uruchom, ma nie przejść**

Run: `cd server && mvn -q test -Dtest=ReportStoreAlertTest`
Expected: błąd kompilacji (brak `AlertSink`, `setAlertSink`).

- [ ] **Step 3: Zaimplementuj**

- `AttackerState`: `boolean decoyAttempt`, `String alertedLevel` (null = nic), `Deque<AlertNotice.Recent> recent` (maks. 10, najnowszy na początku).
- `decoyAttempt = true`, gdy `event.type` ∈ {`auth.failure`, `auth.invalid_user`, `auth.attempt`} i `event.user.name` ∈ `confirmAccounts`; IP z `event.src.ip`.
- Wydziel `private String threatOf(AttackerState s, Instant now)` z obecnego `attackers()`; nowa kolejność: `confirmed` → `bait` (`decoyAttempt || breadcrumbRead`) → `brute_force` → `fast_enum` → `suspicious` (bez `breadcrumbRead`) → `contact`. `rank("bait") = 4`, `confirmed = 5`.
- `index(JsonNode n, boolean notify)`: zbiera dotknięte IP (każde wywołanie `attacker(...)` dodaje do lokalnego zbioru); na końcu dla każdego liczy `threatOf(s, at)` (`at` = `received_at` raportu); jeśli poziom ∈ `ALERT_LEVELS` i `rank > rank(alertedLevel)`: ustaw `alertedLevel`, a gdy `notify && sink != null` zbuduj `AlertNotice` i wywołaj `sink.escalated(...)` (pod lockiem; sink nie może blokować, patrz Task 2).
- `rebuild()` woła `index(n, false)`, `insert()` woła `index(stamped, true)`.
- `Recent` budowany z `event` (typ, serwis, `user.name`, `src.port`) i `received_at`; nigdy z `credential` ani `content`.
- `reason` po polsku: `fast_enum` „skan portów albo 3+ porty w minutę”, `brute_force` „5+ nieudanych logowań w 10 min”, `bait` „próba logowania na konto-przynętę albo odczyt pliku-przynęty”, `confirmed` „udane logowanie na konto-przynętę”.
- `dashboard/app.js`: w `THREATS` dodaj `bait: { label: "PRZYNĘTA", tone: "danger", hint: "próba na konto-przynętę albo odczyt pliku-przynęty" }` między `confirmed` a `brute_force`; w `renderAttackers` sygnał `if (a.decoy_attempt) signals.push("próba na konto-przynętę")`.

- [ ] **Step 4: Uruchom wszystkie testy serwera**

Run: `cd server && mvn -q test`
Expected: kod wyjścia 0 (stare testy `ReportStoreEventTest` też przechodzą; tam, gdzie oczekiwały `suspicious` dla `breadcrumb_read`, popraw na `bait`).

- [ ] **Step 5: Commit**

```bash
git add server/src dashboard/app.js
git commit -m "Serwer: poziom bait i powiadomienia o eskalacji atakujacego"
```

---

### Task 2: `AlertService`, konfiguracja i treść maila

**Files:**
- Create: `server/src/main/java/pl/honeypot/server/alert/AlertConfig.java`
- Create: `server/src/main/java/pl/honeypot/server/alert/Mailer.java`
- Create: `server/src/main/java/pl/honeypot/server/alert/AlertFormatter.java`
- Create: `server/src/main/java/pl/honeypot/server/alert/AlertService.java`
- Test: `server/src/test/java/pl/honeypot/server/alert/AlertServiceTest.java`, `AlertConfigTest.java`

**Interfaces:**
- Consumes: `AlertSink`, `AlertNotice` (Task 1).
- Produces:
  - `public record AlertConfig(boolean enabled, String host, int port, boolean starttls, String user, String password, String from, List<String> to, int maxPerHour)` z `public static AlertConfig from(Properties p)`; przy `enabled=true` brak `host`, `from` albo pustego `to` → `IllegalArgumentException` z nazwą klucza.
  - `public interface Mailer { void send(String subject, String body) throws Exception; }`
  - `AlertFormatter.subject(AlertNotice n)`, `AlertFormatter.body(AlertNotice n, long skipped)` (statyczne, zwracają `String`).
  - `public final class AlertService implements AlertSink, AutoCloseable` z konstruktorem `AlertService(AlertConfig cfg, Mailer mailer, Clock clock)`, metodą `start()` (uruchamia wątek-demon) i pakietową `boolean deliver(AlertNotice n)` (jedna synchroniczna próba: limit godzinowy + wysyłka; `true` = wysłane).

- [ ] **Step 1: Napisz testy**

```java
// AlertConfigTest
@Test void defaultsWhenDisabled()        // pusty Properties -> enabled false, port 25, starttls false, maxPerHour 60
@Test void parsesRecipientList()         // alert.to=" a@x.pl, b@y.pl " -> List.of("a@x.pl","b@y.pl")
@Test void enabledWithoutHostFails()     // alert.enabled=true bez alert.smtp.host -> IllegalArgumentException, message zawiera "alert.smtp.host"

// AlertServiceTest (FakeMailer zapisuje (subject, body); Clock.fixed / przestawiany)
@Test void subjectFormat()               // notice brute_force 192.168.56.4 agent fs-finanse -> "[honeypot fs-finanse] BRUTE FORCE 192.168.56.4"
@Test void bodyHasReasonCountsAndRecent()// body zawiera reason, "nieudane logowania", IP, typ z recent
@Test void hourlyLimitCountsSkipped()    // maxPerHour=2, 3x deliver -> 2 wysłane, trzeci false;
                                         // zegar +61 min, deliver -> body zawiera "pominięto 1"
@Test void offerNeverBlocksWhenQueueFull()
    // Mailer blokujący (CountDownLatch), start(), 150x escalated(...) wraca w < 1 s
@Test void bodyNeverContainsPassword()   // Recent z user "x", body nie zawiera żadnego pola credential (brak takiego pola w Recent)
```

- [ ] **Step 2: Uruchom, ma nie przejść**

Run: `cd server && mvn -q test -Dtest='AlertServiceTest,AlertConfigTest'`
Expected: błąd kompilacji.

- [ ] **Step 3: Zaimplementuj**

- `escalated(n)`: `queue.offer(n)` na `ArrayBlockingQueue(100)`; `false` → `skipped.incrementAndGet()`. Nigdy nie czeka.
- Wątek (`start()`, demon, nazwa `alert-mailer`): `take()` → `deliver`; przy wyjątku `Mailer.send` ponowienia po 30 s, 2 min, 10 min (`Thread.sleep`), potem `System.err` z IP i poziomem.
- Limit: okno przesuwne 1 h po znacznikach czasu wysłanych maili (`Deque<Instant>`, `clock`); przekroczenie → `skipped++`, `false`.
- `body`: polskie etykiety, liczniki z `AttackerView` (`auth_failures`, `failures_10m`, `distinct_ports`, `probed`, `invalid_users`, `decoy_attempt`, `breadcrumb_read`), `first_seen`, `last_seen`, lista `recent` (czas, typ, serwis, konto, port), stopka `Dashboard: ssh -L 8443:127.0.0.1:8443 <admin>@<wabik> -> https://127.0.0.1:8443/`; jeśli `skipped > 0` linia `Uwaga: pominięto N alarmów (limit na godzinę albo pełna kolejka).` i zerowanie licznika po wysłaniu.
- `close()`: przerywa wątek.

- [ ] **Step 4: Uruchom testy**

Run: `cd server && mvn -q test`
Expected: kod wyjścia 0.

- [ ] **Step 5: Commit**

```bash
git add server/src
git commit -m "Serwer: AlertService (kolejka, limit, ponowienia) i tresc maila"
```

---

### Task 3: Wysyłka SMTP (`SmtpMailer`)

**Files:**
- Modify: `server/pom.xml` (zależność `org.eclipse.angus:angus-mail:2.0.3`)
- Create: `server/src/main/java/pl/honeypot/server/alert/SmtpMailer.java`
- Test: `server/src/test/java/pl/honeypot/server/alert/SmtpMailerTest.java`

**Interfaces:**
- Consumes: `AlertConfig`, `Mailer` (Task 2).
- Produces: `public final class SmtpMailer implements Mailer` z konstruktorem `SmtpMailer(AlertConfig cfg)`.

- [ ] **Step 1: Napisz test z atrapą serwera SMTP** (w teście: `ServerSocket` na porcie 0, wątek odpowiadający `220`, `250` na EHLO/MAIL/RCPT, `354` na DATA, `250` po `.`, `221` na QUIT; zapisuje komendy i treść)

```java
@Test void sendsToAllRecipients()   // to=List.of("a@x.pl","b@y.pl") -> komendy zawierają "RCPT TO:<a@x.pl>" i "RCPT TO:<b@y.pl>",
                                     // DATA zawiera "Subject: [honeypot" (temat UTF-8 zakodowany wg RFC 2047 dopuszczalny)
@Test void plainSmtpWithoutAuth()   // user puste -> brak komendy "AUTH"
@Test void connectionRefusedThrows()// port zamknięty -> send() rzuca wyjątek (AlertService go ponowi)
```

- [ ] **Step 2: Uruchom, ma nie przejść**

Run: `cd server && mvn -q test -Dtest=SmtpMailerTest`
Expected: błąd kompilacji.

- [ ] **Step 3: Zaimplementuj** `SmtpMailer`: `jakarta.mail.Session` z `mail.smtp.host/port`, `mail.smtp.starttls.enable/required` = `starttls`, `mail.smtp.auth` = niepusty `user`, `mail.smtp.connectiontimeout`/`timeout` = 10000; `MimeMessage` z `setSubject(subject, "UTF-8")`, `setText(body, "UTF-8")`, nadawca `from`, odbiorcy `to`; `Transport.send` (z hasłem, gdy `user` niepusty).

- [ ] **Step 4: Uruchom testy i zbuduj jar**

Run: `cd server && mvn -q test && mvn -q -DskipTests package && unzip -l target/honeypot-server.jar | grep -c 'jakarta/mail'`
Expected: testy kod 0; licznik > 0.

- [ ] **Step 5: Commit**

```bash
git add server/pom.xml server/src
git commit -m "Serwer: wysylka alarmow przez SMTP (Jakarta Mail)"
```

---

### Task 4: Podłączenie, `--test-alert`, instalator i dokumentacja

**Files:**
- Modify: `server/src/main/java/pl/honeypot/server/ServerConfig.java` (pole `AlertConfig alert`, `AlertConfig.from(p)` w `load`)
- Modify: `server/src/main/java/pl/honeypot/server/Main.java`
- Modify: `scripts/install-server-service.sh` (zachowanie linii `alert.*`)
- Modify: `docs/WDROZENIE-OD-ZERA.md` (nowy rozdział „Alarmy e-mail”)
- Test: `server/src/test/java/pl/honeypot/server/VersionTest.java` bez zmian; nowy `server/src/test/java/pl/honeypot/server/ServerConfigAlertTest.java`

**Interfaces:**
- Consumes: `AlertConfig.from`, `AlertService`, `SmtpMailer`, `ReportStore.setAlertSink`.

- [ ] **Step 1: Test konfiguracji**

```java
@Test void loadsAlertSection()  // plik properties z keystore (tymczasowy plik) i alert.enabled=true, host, from, to -> cfg.alert().enabled()
@Test void alertDisabledByDefault() // bez kluczy alert.* -> cfg.alert().enabled() == false
```

- [ ] **Step 2: Uruchom, ma nie przejść**

Run: `cd server && mvn -q test -Dtest=ServerConfigAlertTest`
Expected: błąd kompilacji (`alert()`).

- [ ] **Step 3: Zaimplementuj**

- `ServerConfig.load`: `AlertConfig.from(p)`.
- `Main`: `args[0] == "--test-alert"` → wczytaj `args[1]`, wyślij `SmtpMailer.send("[honeypot] test alarmu", ...)`, wypisz wynik, `System.exit(0|1)`; przy `alert.enabled=false` wypisz to i `exit(1)`. Zwykły start: gdy `cfg.alert().enabled()`, `new AlertService(cfg.alert(), new SmtpMailer(cfg.alert()), Clock.systemUTC())`, `start()`, `reports.setAlertSink(service)`; log jednej linii z hostem i liczbą odbiorców.
- `install-server-service.sh`: przed zapisem `collector.properties` zachowaj `grep '^alert\.' /etc/sysmon/collector.properties` (jeśli plik istnieje) i dopisz te linie po nowej treści.
- `WDROZENIE-OD-ZERA.md`, nowy rozdział po „Dashboard”: host `sudo ./scripts/setup-mail-host.sh`, konto w Thunderbirdzie (IMAP localhost:143 STARTTLS, SMTP localhost:25 STARTTLS, wyjątek certyfikatu), na Almie dopisanie kluczy `alert.*` do `/etc/sysmon/collector.properties` (`alert.smtp.host=192.168.56.1`, `alert.to=<login>@localhost`), `sudo systemctl restart sysmon-collector`, test `sudo -u sysmon /usr/lib/jvm/java-21-openjdk/bin/java -jar /opt/sysmon/collector.jar --test-alert /etc/sysmon/collector.properties`; akapit „sieć docelowa” wg p. 9 specyfikacji.

- [ ] **Step 4: Testy i weryfikacja na Almie** (wymaga tymczasowego `sudo` na `user@192.168.56.6`)

Run: `cd server && mvn -q test && mvn -q -DskipTests package`, wgraj jar i `dashboard/` jak w rozdziale 12 instrukcji, dopisz `alert.*`, restart, `--test-alert`.
Expected: `--test-alert` kod 0 i mail „[honeypot] test alarmu” w Thunderbirdzie; 5 błędnych haseł SMB z Kali → jeden mail `[honeypot fs-finanse] BRUTE FORCE 192.168.56.4`; restart `sysmon-collector` → żadnego nowego maila.

- [ ] **Step 5: Commit**

```bash
git add server/src scripts/install-server-service.sh docs/WDROZENIE-OD-ZERA.md
git commit -m "Alarmy e-mail: konfiguracja, --test-alert, instalator i instrukcja"
```
