# Ustalenia — konfiguracja honeypota (SSH + Samba), Dział Finansów

Pełny zapis decyzji z przeglądu `konfiguracja_honeypota.md` punkt po punkcie.
Realizacja: `honeypot.conf` (wartości) + `setup-honeypot.sh` (skrypt).

## Struktura
- `honeypot.conf` — wszystkie wartości (legenda, konta, hasła, udziały, IP). **Nie commitować** (hasła); w repo tylko `honeypot.conf.example`.
- `setup-honeypot.sh` — czyta `honeypot.conf` i zakłada całość. Bez wartości na sztywno. Uruchamiać jako root na AlmaLinux 9.

## 1. Tożsamość
- Legenda: serwer plików **Działu Finansów**.
- Hostname `fs-finanse`. Strefa `Europe/Warsaw`, locale `pl_PL.UTF-8`.
- Nazwa firmy: **placeholder** w conf (uzupełnić).
- Ukrycie VM: **pomijamy** (serwery i tak są wirtualizowane).

## 2. Użytkownicy (6 person + 1 realny admin)
- `svc-admin` — **prawdziwy admin, key-only SSH**, nie przynęta (zarządzanie + tunel dashboardu). Nigdy nie generuje nieudanego logowania.
- `backup_srv` — **1 konto SSH-shell (przynęta)**; jego hasło = „okruszek".
- `a.kowalska`, `m.nowak`, `k.wisniewska`, `p.zielinski`, `administrator` — **tylko Samba** (`/sbin/nologin`).
- Hasła person: **wiarygodne i trudniejsze**, nie pod rockyou (serwer PL). Główna droga wejścia = okruszek, nie brute-force. Każde udane logowanie na te konta = atakujący.

## 3. Samba
- `server string` = „Serwer plików – Dział Finansów".
- Widoczność: NetBIOS + **`wsdd`** (WS-Discovery). Szum Windowsów **nie może lecieć jako atak** (patrz detekcja, A).
- **`full_audit`** włączony → `/var/log/samba/audit.log` (agent skanuje `/var/log/samba/*`). Daje widoczność odczytów/pobrań.
- Logowanie auth (login+IP) przez `log level auth:3`; `map to guest = Never` (złe hasło → `NT_STATUS_LOGON_FAILURE`).
- Udziały: `Wspolny` (gość RO, z ograniczeniami), `Finanse` (hasło/@finanse), `Archiwum$` (ukryty, browseable=no), `Zarzad` (widoczny, odmowa dostępu).

## 4. SSH
- Logowanie hasłem **włączone** (przynęta + telemetria nieudanych).
- Banner przed logowaniem + MOTD (notka IT).
- `LogLevel VERBOSE`.
- Rejestrowanie komend: **auditd → syslog** (`/var/log/messages`, agent czyta).
- `svc-admin` key-only (Match User), `PermitRootLogin no`.

## 5. Zawartość plików
- Pliki **txt/csv** (podpunkt „metadane w dokumencie" odpada — txt/csv ich nie ma).
- Kategorie: `Faktury`, `Rozliczenia_VAT`, `Zestawienia`, `Budzet`, `Umowy`, `archiwum`, `do_sprawdzenia`.
- Podział na lata `2022/2023/2024`, daty rozłożone (`touch -d`), treść fikcyjna, bez prawdziwych danych.

## 6. Okruszki
- Hasło `backup_srv` ukryte w `Archiwum$/IT/kopia_zapasowa.sh` (musi pasować do realnego hasła konta).
  - ⚠️ Uwaga reachability: `Archiwum$` wymaga `@finanse`, więc okruszek osiągalny dopiero po złamaniu konta persony. Do ewentualnej zmiany (kopia w `Wspolny`/gość).
- `.bash_history` + `.ssh/known_hosts` w domu `backup_srv` (komendy do `db-fin01`, `nas-arch01`).
- „Bałagan": `.viminfo`, `.lesshst`, pusty `.cache`, 1–2 pliki w `Pobrane`.

## 7. Oznaki życia
- Cron **nie rusza monitorowanych udziałów** (inaczej fałszywe `file_change`). Świeżość plików ustawiana **raz przy instalacji**; benign aktywność cron poza udziałami.
- Historia logowań: **tylko udane**, konta z powłoką (`svc-admin`, `backup_srv`), kilka wewnętrznych IP.
  - `wtmp`/`lastlog` (binarne) — agent ślepy, 100% bezpieczne.
  - `/var/log/secure` tylko „Accepted", zasiane **przed startem agenta** → w najgorszym razie `unknown`, nigdy atak.
  - **Nigdy** fałszywych nieudanych logowań.
- Zrotowane logi `.gz` — agent pomija archiwa, bezpieczne.
- Restarty/uptime — operacyjne, nic w skrypcie.

## 8. Agent (zamrożony — nie zmieniamy kodu)
- Routing logów do plików agenta: SSH→`secure` (jest), `full_audit`→`/var/log/samba/audit.log`, auditd→`messages`.
- Nazwa `sys-auditd` zostaje (neutralna).
- **Wykrywanie użycia okruszka = osobne zadanie po stronie SERWERA (Java)**: korelacja „odczyt `kopia_zapasowa.sh` (full_audit) → udane SSH jako `backup_srv`" = pewny atak. Poza tym skryptem.

## Do zrobienia później (poza skryptem Samby)
- Serwer: korelacja okruszka (pkt 8) → poziom „confirmed".
- Serwer: przestrojenie `fast_enum` na „wiele portów z jednego IP" (A), żeby aktywny Windows nie był skanem.
- Hardening + egress (bo `backup_srv` daje realny shell).
