# Koncept systemu — w skrócie

## Idea
Stawiamy **fałszywy serwer plików małej firmy** (Samba, AlmaLinux) i patrzymy, co z nim robi atakujący.
Nikt uprawniony nie ma powodu tam zaglądać, więc **każdy kontakt z tą maszyną jest podejrzany**,
a wszystko, co zostanie zarejestrowane, jest cennym dowodem. System niczego nie blokuje i nie atakuje
z powrotem — **obserwuje i zapisuje dowody**.

## Trzy części

```
  ATRAKCJA            OBSERWATOR                 ARCHIWUM I WIDOK
  (wabik)             (agent w C)                (serwer Java + dashboard)

  Samba z udziałami   widzi pliki, logi,         przyjmuje raporty, usuwa
  Dokumenty, Faktury, połączenia; każde          duplikaty, zapisuje do pliku,
  Kadry, kontami      zdarzenie zamienia         pokazuje na żywo w przeglądarce
  i „firmowymi"       w raport i wysyła
  plikami
```

1. **Wabik** — maszyna wygląda jak zwykły, trochę zaniedbany serwer firmy: nazwy, konta ze słabymi hasłami,
   pliki z datami sprzed lat, przynęty typu „stare hasła". Ma przyciągać i wyglądać wiarygodnie.
2. **Agent** (`sys-auditd`) — cichy proces na tej samej maszynie, ukryty pod nazwą usługi systemowej.
   Nie ocenia ataku, tylko **zbiera fakty**.
3. **Serwer + dashboard** — odbiera fakty, trwale je przechowuje i pokazuje analitykowi.

## Co agent obserwuje (trzy „zmysły")
| Zmysł | Co widzi | Po co |
|---|---|---|
| **Pliki** w udziałach | utworzenie, zmiana (z diffem), usunięcie, zmiana nazwy, zmiana uprawnień | *co* atakujący zrobił z danymi |
| **Logi** (Samba, SSH, system) | nieudane i udane logowania, inne wpisy | *jak* próbował wejść |
| **Połączenia TCP** | kto (adres IP) połączył się z naszymi usługami | *skąd* przyszedł |

Do tego **heartbeat** (sygnał życia co ~minutę) — jeśli zamilknie, ktoś mógł wyłączyć agenta.

## Jak płyną dane
1. Coś się dzieje (ktoś podmienia plik, zgaduje hasło, łączy się).
2. Agent zapisuje **raport** na dysku, zanim cokolwiek zrobi dalej — dowód nie ginie przy awarii.
3. Osobny wątek wysyła raport do serwera przez **zaszyfrowane, zweryfikowane HTTPS**. Gdy serwer nie odpowiada,
   raporty czekają w kolejce i są ponawiane.
4. Serwer zapisuje raport (jedna linia JSON na zdarzenie), potwierdza odbiór i pomija powtórki.
5. Dashboard co kilka sekund pokazuje agenta (online/offline), liczniki i listę zdarzeń z podglądem surowego raportu.
6. Kopia pliku ze zdarzeniami jest cyklicznie wysyłana na **inną maszynę**, żeby przejęcie wabika nie skasowało dowodów.

## Zasady projektowe
- **Obrona, nie odwet.** System tylko przyjmuje ruch; nigdy nie atakuje ani nie skanuje nikogo.
- **Dowód ponad wszystko.** Najpierw trwały zapis, potem wysyłka; zmiana pliku jest raportowana *przed* aktualizacją stanu
  odniesienia. Lepiej mieć duplikat niż dziurę.
- **Uczciwość co do własnych ograniczeń.** Gdy agent czegoś nie widzi (przepełnienie, brak logu, błąd), sam to zgłasza
  jako `observation_gap` zamiast milczeć.
- **Fakty, nie oskarżenia.** Raport nie wskazuje sprawcy (`actor: null`); adres IP i MAC to kontekst do oceny przez człowieka.
- **Odporność na sabotaż.** Agent działa jako root z minimalnymi uprawnieniami systemowymi, nie wykonuje nic z wnętrza
  udziałów, nie podąża za symlinkami, a TLS nie da się wyłączyć.
- **Izolacja.** Maszyna ma stać w osobnym VLAN-ie, bez trasy do reszty sieci; panel dostępny tylko przez tunel SSH.

## Czego system (jeszcze) nie robi
- Nie koreluje zdarzeń ani nie wykrywa wzorców (np. „20 prób logowania z jednego IP") — to robi analityk.
- Nie widzi samego **odczytu/pobrania** plików (Samba nie ma włączonego audytu operacji na plikach).
- Nie uwierzytelnia agentów wobec serwera (token / mTLS to plan, nie stan obecny).

Szczegóły techniczne i lista luk: `NOTATKA-dzialanie-systemu.md`.
