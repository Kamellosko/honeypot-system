# Projekt: Rozproszony system honeypotów z detekcją i tarpitem

Dokument zbiera koncepcję, architekturę, cykle życia, protokół komunikacji oraz plan pracy
dla zespołu 3-osobowego (3 × 48 h = 144 h, ~12 tygodni, 4 h/tydz. na osobę).

---

## 1. Koncepcja

System składa się z wielu **honeypotów** (maszyn/usług-wabików), które wykrywają próby ataku
i raportują je do centralnego **serwera** z **dashboardem**. Serwer koreluje zdarzenia z wielu
źródeł i rozsyła z powrotem wskaźniki zagrożeń (IoC), dzięki czemu cała sieć może zablokować
atakującego, zanim dotrze on do kolejnych węzłów.

Dodatkowo honeypoty stosują **tarpitting** — celowo spowalniają i wiążą połączenia napastnika,
marnując jego czas i zasoby.

### Kluczowa granica projektowa: obrona, nie odwet

Pierwotny pomysł zakładał „kontratak" / zalewanie atakującego ruchem. Zostało to świadomie
odrzucone, z powodów **praktycznych**, nie tylko formalnych:

- Adres, który widzi honeypot, to prawie zawsze **cudza przejęta maszyna** (bot, VPS, proxy,
  wyjście VPN), a nie komputer napastnika. Kontratak uderza w ofiarę pośrednią.
- Adres źródłowy jest **trywialny do sfałszowania** — napastnik może podać adres, który chce,
  żeby system zaatakował, zamieniając go we własną broń.
- Nieautoryzowany ruch wymierzony w cudzy system jest nielegalny również jako „odwet".

**Rozwiązanie:** ten sam cel (uprzykrzyć życie napastnikowi, związać jego zasoby) osiąga się
**odwracając kierunek** — nie system zalewa napastnika, lecz napastnik grzęźnie w lepkim
honeypocie. System nigdy nie inicjuje ruchu w stronę atakującego; tylko leniwie odpowiada na
połączenia, które ten sam nawiązał.

---

## 2. Architektura

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Honeypot #1    │     │  Honeypot #2    │     │  Honeypot #3    │
│ ┌─────────────┐ │     │ ┌─────────────┐ │     │ ┌─────────────┐ │
│ │ Agent (C)   │ │     │ │ Agent (C)   │ │     │ │ Agent (C)   │ │
│ │ usługi-wabik│ │     │ │ usługi-wabik│ │     │ │ usługi-wabik│ │
│ └──────┬──────┘ │     │ └──────┬──────┘ │     │ └──────┬──────┘ │
└────────┼────────┘     └────────┼────────┘     └────────┼────────┘
         │                       │                        │
         │   zdarzenia (JSON/TLS, tylko wychodzące)       │
         └───────────────────────┼────────────────────────┘
                                  ▼
                      ┌───────────────────────┐
                      │   Serwer centralny    │
                      │  Kolektor (Java)      │  ← odbiera, waliduje
                      │  Korelacja + baza     │  ← łączy zdarzenia z wielu źródeł
                      │  Dashboard (web)      │  ← mapa, oś czasu, alerty
                      └───────────────────────┘
```

### Podział ról języków

- **C (niski poziom)** — tam, gdzie powstaje sygnał: surowe gniazda, nasłuch pakietów,
  czytanie nagłówków TCP/IP, mechanika tarpitu na gorącej ścieżce. Agent ma być lekki i szybki.
- **Java (wysoki poziom)** — tam, gdzie sygnał nabiera sensu: korelacja, baza, REST API,
  dashboard, integracje. Liczy się produktywność i ekosystem bibliotek.

> **Uwaga o JNI:** agent i serwer to osobne procesy na osobnych maszynach, więc komunikują się
> przez sieć (HTTP/socket), a **nie** przez JNI. JNI łączy C i Javę *w jednym procesie*. Jeśli
> zaliczenie wymaga pokazania mostu C↔Java, naturalne miejsce to funkcja wydajnościowa po stronie
> serwera wołana z Javy (np. parser nagłówka pakietu albo szybki lookup GeoIP) — decyzja do podjęcia
> świadomie na starcie, nie doklejana na siłę.

### Zasady bezpieczeństwa architektury

- **Komunikacja jednokierunkowa:** to **agent zawsze inicjuje** połączenie do serwera.
  Serwer nigdy nie łączy się do honeypota ani nie wystawia do niego portu — honeypot jest
  z założenia kompromitowalny, więc nie może być furtką do centrum dowodzenia.
- **Przepływ danych w górę:** z honeypota wypływają tylko logi. Przekazanie czegoś „w dół"
  (np. listy blokad IoC) odbywa się jako **odpowiedź na zapytanie zainicjowane przez agenta**
  (agent sam pyta „masz nowe blokady?"), nie jako połączenie przychodzące.
- **Zabezpieczenie kanału:** minimum na demo = TLS + token; docelowo **mTLS** (wzajemne
  uwierzytelnianie certyfikatami agent↔serwer).

---

## 3. Cykl życia — stan spoczynku (brak ataku)

Kluczowe rozróżnienie: **„cicho" ≠ „martwo".** Brak ataków nie oznacza braku aktywności —
przez sieć stale płynie **heartbeat (puls)**, żeby odróżnić zdrowy spokój od awarii/ubicia agenta.

**Fazy:**
1. **Bootstrap** — agent startuje, podnosi porty-wabiki, (docelowo) handshake mTLS, rejestruje się.
2. **Nasłuch bezczynny** — agent czeka; brak ruchu = brak zdarzeń (poprawne, bo honeypot nie ma
   legalnego ruchu — każde trafienie jest z definicji podejrzane).
3. **Heartbeat** — co ~30 s lekki komunikat „żyję, 0 zdarzeń, uptime N".
4. **Nadzór liveness (serwer)** — odświeżanie „last_seen"; **cisza zdarzeń + obecny puls = zdrowo**.
5. **Steady state** — pętla: nasłuch → puls → status zielony, aż do ataku lub awarii.

**Dashboard w spoczynku** pokazuje *zdrowie, nie zdarzenia*: lista czujników (zielone), czas
ostatniego pulsu, licznik zdarzeń = 0, uptime.

**Stany graniczne:**
- Pierwszy pakiet → wyjście ze spoczynku (patrz niżej).
- Brak pulsu (np. 3 z rzędu) → **nie spoczynek**, lecz awaria albo ubicie agenta → status żółty/czerwony.

---

## 4. Cykl życia — stan ataku

Kluczowe rozróżnienie: **pojedynczy pakiet ≠ atak.** Internet nieustannie „puka"; alert wyzwala
dopiero **wzorzec** (wiele połączeń z jednego IP w krótkim czasie, skan kolejnych portów,
sygnatura exploita).

**Fazy:**
1. **Pierwszy kontakt** — pakiet na port-wabik; agent zapisuje surowe trafienie (IP, port, czas, payload).
2. **Rozpoznanie wzorca** — reguła „N połączeń w T s", skan portów, dopasowanie payloadu → awans
   do rangi *zdarzenia bezpieczeństwa*.
3. **Eskalacja** — zdarzenie wysłane natychmiast, poza rytmem heartbeatu; czujnik na dashboardzie
   zmienia kolor.
4. **Korelacja (serwer)** — łączenie zdarzeń z wielu czujników (to samo IP na wielu węzłach =
   celowany atak, nie przypadkowy skan), wzbogacenie GeoIP/ASN, oś czasu, poziom pewności.
5. **Reakcja — rozesłanie IoC** — serwer generuje „blokuj IP X" i rozsyła do **wszystkich**
   czujników, także nietkniętych → tarcza rozpięta zawczasu.
6. **Tarpit / obserwacja (opcjonalnie)** — podtrzymanie połączenia napastnika, logowanie jego
   komend (wywiad) i marnowanie jego czasu.
7. **Wygaszanie** — trafienia ustają, incydent zamknięty (w historii), IoC trzymane jeszcze przez
   jakiś czas; powrót do spoczynku.

**Dashboard podczas ataku** *opowiada incydent*: kolor czujnika, zapełniająca się oś czasu, karta
IP (GeoIP/ASN, porty, payload, pierwszy/ostatni kontakt), wyróżnienie „to samo IP na N czujnikach",
status reakcji („IoC rozesłany o 14:03:21").

**Punkty do przemyślenia:**
- **Próg czułości** — za niski = fałszywe alarmy; za wysoki = przegapiony atak „low-and-slow".
- **Atak na agenta** — jeśli agent zamilknie w trakcie incydentu, **brak heartbeatu sam staje się
  alarmem** („czujnik padł podczas ataku" — to podejrzane, nie neutralne).

**Diagram stanów:** `idle → detecting → alerting → responding → idle`

---

## 5. Tarpit — „uprzykrzanie" zgodne z prawem

Istota: honeypot odpowiada napastnikowi **ślamazarnie i w nieskończoność**, trzymając jego
połączenie zajęte. We wszystkich technikach **honeypot nigdy nie inicjuje ruchu** — tylko
leniwie odpowiada.

**Techniki:**
- **TCP tarpit** — okno TCP niemal zerowe, dane bajt po bajcie; skaner wisi minutami (np. endlessh).
- **Nieskończona odpowiedź aplikacyjna** — fałszywy HTTP/SSH ciągnący odpowiedź bez końca.
- **Labirynt treści** — generowane strony z linkami do kolejnych generowanych stron (pułapka na boty).
- **Fałszywa lepka usługa** — udawany SSH/baza przyjmująca każde hasło po długiej zwłoce; przy
  okazji logująca komendy napastnika.

**Przykładowe zdarzenie tarpitu (do raportowania):**

```json
{
  "msg_type": "event",
  "sensor_id": "sensor-01",
  "timestamp": "2026-10-02T14:07:33Z",
  "event_type": "tarpit_active",
  "src_ip": "203.0.113.45",
  "dst_port": 22,
  "held_duration_sec": 252,
  "bytes_dribbled": 48,
  "commands_logged": ["uname -a", "cat /etc/passwd"]
}
```

**Efektowna metryka na dashboard:** *„łączny czas napastnika zmarnowany: 3 h 14 min; 27 połączeń
uwięzionych; 0 pakietów wysłanych ofensywnie"* — wymierny efekt „uprzykrzania", w pełni defensywny.

**Wątek inżynieryjny:** trzymanie wielu połączeń kosztuje też nas (pamięć, deskryptory) → tarpit
robi się lekki: jeden proces obsługujący wiele wiszących połączeń (asynchroniczne I/O).

---

## 6. Komunikacja agent → serwer

### Pojęcia

- **Honeypot** — cała zwabiająca maszyna/usługa.
- **Agent** — proces *na* honeypocie; jedyny element rozmawiający z serwerem.
- **Serwer** — centrum: odbiera, koreluje, karmi dashboard.

### Typy wiadomości

| # | Typ | Kierunek | Częstotliwość |
|---|-----|----------|---------------|
| 1 | Rejestracja | agent → serwer | raz, przy starcie |
| 2 | Heartbeat | agent → serwer | cyklicznie (~30 s) |
| 3 | Zdarzenie bezpieczeństwa | agent → serwer | asynchronicznie, przy incydencie |
| 4 | Pobranie IoC | agent pyta, serwer odpowiada | okresowo |

### Wybór transportu

- **HTTP(S)/REST — rekomendowane dla projektu studenckiego.** Prostsze w debugowaniu, współgra
  z dashboardem, łatwe TLS, szybkie dowiezienie end-to-end.
- **Surowe TCP z własnym protokołem** — niższy narzut, naturalny strumień, ale sami obsługujecie
  ramkowanie, reconnect, parsowanie (więcej pracy). Sensowne, jeśli chcecie wyeksponować C.

Format treści: **JSON** niezależnie od transportu.

### Kontrakt wiadomości (ZAMROZIĆ W TYGODNIU 1)

Wspólne pole `msg_type` pozwala serwerowi jednym wejściem rozróżniać komunikaty.

**Zdarzenie:**
```json
{
  "msg_type": "event",
  "sensor_id": "sensor-01",
  "timestamp": "2026-10-02T14:03:21Z",
  "event_type": "port_scan",
  "src_ip": "203.0.113.45",
  "dst_ports": [22, 23, 80, 443],
  "payload": "SSH-2.0-libssh...",
  "severity": "medium"
}
```

**Heartbeat:**
```json
{
  "msg_type": "heartbeat",
  "sensor_id": "sensor-01",
  "timestamp": "2026-10-02T14:03:00Z",
  "events_since_last": 0,
  "uptime_sec": 86400
}
```

### Sekwencja (każda strzałka wychodzi od agenta)

```
AGENT (na honeypocie)                         SERWER (dashboard)
  │ 1. handshake TLS/mTLS            ─────────► │
  │ 2. POST /register  {sensor-01}   ─────────► │  status = online
  │ 3. POST /heartbeat (co 30 s)     ─────────► │  odśwież last_seen → zielony
  │        ... spoczynek, pętla pulsu ...       │
  │ 4. [atak!] POST /events {scan}   ─────────► │  korelacja, alert, czerwony
  │ 5. GET /ioc  "masz blokady?"     ─────────► │
  │                                  ◄───────── │  zwraca [IP X, ...]
  │   dokłada do lokalnej listy blokad          │
```

---

## 7. Role w zespole

- **Osoba A — Agent / czujniki (C):** przechwytywanie, detekcja, heartbeat, drugi wabik (fałszywy
  SSH), mechanika tarpitu, egzekwowanie blokad.
- **Osoba B — Serwer / korelacja (Java):** kolektor, baza, REST API, silnik korelacji, generowanie
  i serwowanie IoC, agregacja metryk tarpitu.
- **Osoba C — Dashboard + bezpieczeństwo + DevOps:** interfejs web, warstwa mTLS, konteneryzacja
  labu, harness symulujący ataki.

---

## 8. Plan pracy (3 × 48 h = 144 h, ~12 tygodni)

Zasada nadrzędna: **działające MVP rdzenia w tygodniu 6**. Rozszerzenia (tarpit, mTLS, korelacja)
dobudowywane na stabilnym rdzeniu. **Dwie integracje** zamiast jednej na końcu.

### Faza 0 — Fundamenty (Tydz. 1–2, 24 h)
- **Wspólnie:** zamrożenie schematu wiadomości JSON i kontraktu transportu (jednostronicowy
  „API contract", nieruszalny bez zgody trójki).
- **A (8 h):** szkielet agenta w C — port-wabik, log trafień na stdout.
- **B (8 h):** szkielet kolektora — `POST /events`, zapis do bazy (SQLite), schemat bazy.
- **C (8 h):** szkielet dashboardu na sztucznych danych + pierwszy `docker-compose`.

### Faza 1 — Warstwy bazowe na atrapach (Tydz. 3–5, 36 h)
- **A (12 h):** detekcja skanu (N/T), serializacja JSON, realna wysyłka, heartbeat co 30 s.
- **B (12 h):** zapis zdarzeń i pulsów, agregacja po IP, `GET /sensors` i `GET /events`, liveness.
- **C (12 h):** dashboard na żywym API (status, oś czasu, top IP), konteneryzacja agenta i serwera.

### Faza 2 — Integracja I (Tydz. 6, 12 h) — cała trójka
- Pełny przepływ A→B→C na czystym HTTP (bez TLS), łatanie niespójności kontraktu.
- **KAMIEŃ MILOWY: działające MVP rdzenia** — siatka bezpieczeństwa; od teraz reszta to bonus.

### Faza 3 — Rozszerzenia (Tydz. 7–10, 48 h)
- **A (16 h):** drugi czujnik (fałszywy SSH, 5 h), mechanika tarpitu (7 h), egzekwowanie blokad (4 h).
- **B (16 h):** silnik korelacji + GeoIP/ASN (7 h), generowanie i serwowanie IoC (5 h),
  metryki tarpitu (4 h).
- **C (16 h):** warstwa mTLS (7 h, **dowieźć wcześnie** — A i B przełączają na to komunikację),
  harness ataków (5 h), rozbudowa dashboardu — licznik tarpitu, karta IP (4 h).

### Faza 4 — Integracja II (Tydz. 11, 12 h) — cała trójka
- Pełna pętla z mTLS + rozsyłaniem IoC + tarpitem + wieloma czujnikami; harness przeciw całości,
  pomiary (zdarzenia/s, liczba utrzymanych połączeń).
- **KAMIEŃ MILOWY: pełny system end-to-end.**

### Faza 5 — Domknięcie (Tydz. 12, 12 h)
- Dokumentacja (architektura, kontrakt API, diagram stanów, uzasadnienie „tarpit zamiast
  kontrataku"), przygotowanie demo, zapas na poślizgi.

### Budżet na osobę

| Faza | A (C) | B (Java) | C (web/sec) |
|------|:-----:|:--------:|:-----------:|
| 0 Fundamenty | 8 | 8 | 8 |
| 1 Baza | 12 | 12 | 12 |
| 2 Integracja I | 4 | 4 | 4 |
| 3 Rozszerzenia | 16 | 16 | 16 |
| 4 Integracja II | 4 | 4 | 4 |
| 5 Domknięcie | 4 | 4 | 4 |
| **Razem** | **48** | **48** | **48** |

---

## 9. Zależności między osobami (typowe zatory)

- **B przed C** (warstwa bazowa): dashboard potrzebuje API serwera → C najpierw na sztucznych
  danych, potem na żywym API.
- **C (mTLS) przed Integracją II:** A i B przełączają komunikację na certyfikaty dopiero, gdy C je
  dostarczy → mTLS dowieźć na początku fazy rozszerzeń.
- **B (IoC) przed A (egzekwowanie blokad):** agent nie ma czego pobierać, dopóki serwer nie serwuje
  listy → krótka synchronizacja w połowie fazy 3.

---

## 10. Trzy rzeczy, które decydują o powodzeniu

1. **Zamrożony kontrakt wiadomości w tygodniu 1** — bez tego praca równoległa na atrapach jest
   niemożliwa.
2. **Dwie integracje zamiast jednej** — grupy integrujące dopiero na końcu zwykle nie zdążają.
3. **MVP w tygodniu 6** — granica między „działający projekt + rozszerzenia" a „trzy niedokończone
   kawałki".
