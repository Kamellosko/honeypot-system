# Honeypot: fałszywy serwer plików z monitoringiem

Maszyna AlmaLinux udaje zwykły serwer plików małej firmy (Samba). Agent `sys-auditd` (C) obserwuje udziały,
logi i połączenia TCP, a raporty wysyła przez HTTPS do kolektora (Java), który zapisuje je i pokazuje na dashboardzie.
System niczego nie blokuje, tylko zbiera dowody.

## Gdzie co jest

| Ścieżka | Zawartość |
|---|---|
| [`docs/DOKUMENTACJA-TECHNICZNA.md`](docs/DOKUMENTACJA-TECHNICZNA.md) | **pełna dokumentacja techniczna** (architektura, agent, protokół, serwer, dashboard, wabik, bezpieczeństwo, testy, limity) z fragmentami kodu |
| [`docs/WDROZENIE-OD-ZERA.md`](docs/WDROZENIE-OD-ZERA.md) | **pełna instrukcja wdrożenia na nowej maszynie** (wariant „Dział Finansów": klucz SSH, serwer, persona, agent, testy, sprzątanie, usunięcie konta tymczasowego) |
| [`INSTALL.md`](INSTALL.md) | instalacja od zera krok po kroku (Alma + maszyna testowa) |
| [`docs/PRZEGLAD.md`](docs/PRZEGLAD.md) | jak to działa, w skrócie |
| [`docs/dzialanie-systemu.md`](docs/dzialanie-systemu.md) | opis techniczny, parametry, znane luki |
| [`docs/projekt_honeypot.md`](docs/projekt_honeypot.md) | pierwotna koncepcja i plan projektu |
| [`agent/`](agent/README.md) | agent w C (źródła, testy, usługa systemd) |
| [`server/`](server/README.md) | serwer w Javie, API ([`server/docs/api.md`](server/docs/api.md)), wykrywanie atakujących ([`attacker-detection.md`](server/docs/attacker-detection.md)), certyfikaty |
| [`docs/schema/event-v2.schema.json`](docs/schema/event-v2.schema.json) | JSON Schema bloku `event` (schema v2); wersja projektu w pliku `VERSION`; od 0.3.0 także `auth.attempt` (hasła z prób SSH) i `net.scan` |
| `dashboard/` | statyczny dashboard serwowany przez serwer |
| `scripts/` | instalatory usług, konfiguracja Samby i tożsamości maszyny, kopia logu |
| [`samba_structure/`](samba_structure/ustalenia-konfiguracja.md) | alternatywna persona „Dział Finansów" (SSH + Samba z `full_audit`, okruszek `backup_srv`); zastępuje `setup-samba-honeypot.sh` i `setup-persona.sh` |

## Szybki start

Jedna maszyna (Alma 9.8), kolejność: serwer, Samba, agent. Szczegóły i komendy w [`INSTALL.md`](INSTALL.md) (wariant `fs01`); dla wariantu „Dział Finansów” użyj [`docs/WDROZENIE-OD-ZERA.md`](docs/WDROZENIE-OD-ZERA.md).
Dashboard otwierasz tunelem SSH: `ssh -L 8443:127.0.0.1:8443 <user>@<host>` i `https://127.0.0.1:8443/`.

Maszyna ma stać w izolowanej sieci. Każdy kontakt z portami 22, 139 i 445 jest dla agenta zdarzeniem.
