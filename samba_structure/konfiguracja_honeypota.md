# Konfiguracja honeypota (SSH + Samba)

Plan konfiguracji honeypota opartego tylko na SSH i Sambie: co skonfigurować i na czym to polega, bez komend. Cel: maszyna ma wyglądać jak zwykły, używany serwer firmowy i nie zdradzać, że jest pułapką.

## 1. Tożsamość serwera

- **Wymyśl historię i trzymaj się jej.** Na przykład: serwer plików działu finansów fikcyjnej firmy. Wszystko, co atakujący zobaczy, powinno do niej pasować.
- **Nazwa hosta** zgodna z rolą, np. `fs-finanse` albo `backup-srv01`, a nie domyślna nazwa systemu.
- **Strefa czasowa i język polski**, spójne z resztą sieci.
- **Sprzęt nie może zdradzać maszyny wirtualnej.** Zmień adres MAC na prefiks prawdziwego producenta i podmień w ustawieniach VM dane producenta i modelu, np. Dell PowerEdge.

## 2. Użytkownicy

- **Dwa rodzaje kont.** Część kont ma dostęp do SSH (powłokę), a część tylko do Samby. Prawdziwe firmy często tak mają.
- **Realistyczne nazwy:** `a.kowalska`, `m.nowak`, `backup_srv`, `administrator`. Do tego pełne imię i nazwisko w opisie konta.
- **Hasła słabe, ale ludzkie**, w stylu `Kowalska2024!` czy `Finanse123`, a nie `admin/admin`. Każde konto może mieć inne hasło.
- **Hasła przynęt powinny występować w popularnych słownikach**, żeby atak słownikowy miał szansę je trafić.

## 3. Samba

- **Opis serwera** (`server string`) pasujący do historii, np. „Serwer plików – Dział Finansów”.
- **Widoczność w otoczeniu sieciowym Windowsów.** Włącz rozgłaszanie NetBIOS i dodatkowo WS-Discovery (`wsdd`), bo nowe Windowsy korzystają głównie z tego drugiego.
- **Logowanie uwierzytelniania.** Samba może zapisywać każde udane i nieudane logowanie z loginem i IP (`auth_audit`). To dane dla agenta.
- **Logowanie operacji na plikach.** Moduł `full_audit` zapisuje, kto otworzył, skasował, utworzył plik albo zmienił jego nazwę. Logi idą do sysloga, skąd agent je czyta.

Udziały na różnych poziomach dostępu:

| Udział | Dostęp | Rola przynęty |
| --- | --- | --- |
| Publiczny | Gość, tylko odczyt | Pierwsza przynęta, dostępna dla każdego |
| Działowy | Wymaga hasła | Główna zawartość „firmowa” |
| Ukryty administracyjny (nazwa z `$`) | Niewidoczny na liście | Kusi tych, którzy wiedzą, czego szukać |
| Zablokowany | Widoczny, „Odmowa dostępu” | Zachęca do zdobywania haseł |

## 4. SSH

- **Logowanie hasłem włączone.** Bez tego boty i atakujący od razu odpuszczają.
- **Banner przed logowaniem** zgodny z historią, np. ostrzeżenie „Dostęp tylko dla upoważnionych pracowników”. Prawdziwe firmy tak robią.
- **Komunikat po zalogowaniu (MOTD)**, np. informacja od działu IT o planowanej przerwie czy kopiach zapasowych. Wygląda to na żywy serwer.
- **Szczegółowe logowanie (`LogLevel VERBOSE`).** Daje więcej informacji o próbach logowania dla agenta.
- **Rejestrowanie wpisywanych komend.** Zwykły sshd tego nie robi, więc służy do tego auditd (zapis każdego uruchomionego programu) albo zapis sesji terminala. Widzisz wtedy, co atakujący robił po zalogowaniu.

## 5. Zawartość plików

- **Struktura katalogów jak w firmie:** podział na lata, archiwum, katalogi „do sprawdzenia”, kopie plików z dopiskami typu „final_v2”.
- **Prawdziwa treść:** faktury, zestawienia, notatki, arkusze z fikcyjnymi, ale sensownymi danymi.
- **Różne daty plików**, rozłożone na miesiące albo lata.
- **Metadane dokumentów** (autor, firma) zgodne z historią, a nie z Twoim komputerem.

## 6. Okruszki, czyli ślady prowadzące dalej

- **Dane do SSH ukryte w Sambie**, np. w skrypcie kopii zapasowych albo pliku konfiguracyjnym, a nie w pliku „hasla.txt”. Kiedy ktoś ich użyje, masz dowód, że przeczytał plik.
- **Historia poleceń (`.bash_history`)** kont-przynęt z realistycznymi komendami: łączenie się z bazą, kopiowanie backupu na inny serwer.
- **Znane hosty SSH (`known_hosts`)** i pliki konfiguracyjne wskazujące na inne, nieistniejące serwery. Sugerują, że to część większej infrastruktury.
- **Zwykły bałagan w katalogach domowych:** pliki konfiguracyjne edytora, cache, kilka rzeczy w „Pobranych”.

## 7. Oznaki życia

- **Historia logowań** w systemie z różnych dni i adresów z Twojej sieci.
- **Zadania cykliczne (cron)**, które co jakiś czas tworzą kopie zapasowe, dopisują pliki i zmieniają daty modyfikacji, żeby serwer wyglądał na używany.
- **Stare, zrotowane logi** w systemie, czyli ślad, że serwer działa od dawna.
- **Rzadkie restarty**, bo długi uptime wygląda naturalnie.

## 8. Agent

- **Źródła danych:** logi uwierzytelniania SSH, logi `auth_audit` i `full_audit` Samby oraz log komend (auditd).
- **Nazwa i lokalizacja bez skojarzeń z honeypotem.** Agent powinien wyglądać jak zwykła usługa systemowa.
- **Wykrywanie użycia „okruszków”.** Logowanie przez SSH danymi z pliku w Sambie agent może oznaczać jako pewny atak.
