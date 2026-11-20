# Sonda akceptacyjna etapu 2 (hasła SSH i skany portów)

Wykonaj na **prawdziwej maszynie AlmaLinux 9/10** (honeypot z agentem `sys-auditd` i serwerem). Lokalnie, bez Almy,
nie da się tego sprawdzić. Do zapisu wyników: polecenie, wersja agenta (`/usr/local/sbin/sys-auditd --version` albo
`agent_version` z raportu) i wynik.

**Przed zmianą PAM** trzymaj otwartą drugą sesję root (SSH kluczem `svc-admin` albo konsola). Zły wpis w `/etc/pam.d/sshd`
może zablokować logowanie. Przywrócenie: `cp /etc/pam.d/sshd.hp-orig /etc/pam.d/sshd`.

## Krok A: spike (zanim włączysz `HP_PAM_HOOK=yes`)

| # | Pytanie | Jak sprawdzić | Wynik |
|---|---|---|---|
| A1 | Jak wygląda prawdziwa linia zapory? | `firewall-cmd --get-log-denied` (ma być `all`); z drugiej maszyny `nmap -sS -p 1-20 <ip>`; `grep -m3 'SRC=' /var/log/messages` | porównaj z liniami testowymi w `agent/tests/scan_test.c` (5. pole ma być `kernel:`, są `SRC=`, `DST=`, `PROTO=TCP`, `DPT=`, flagi po `RES=`); **różnice opisz, nie zgaduj** |
| A2 | Jak wyglądają linie dla NULL / XMAS / FIN? | `nmap -sN`, `-sX`, `-sF` na zamknięte porty, jak wyżej | zapisz po jednej linii na rodzaj |
| A3 | Czy `pam_exec` dopisuje bajt NUL po haśle? | hook ma obsłużyć oba warianty (test `scripts/tests/pam_log_test.sh`); zwróć uwagę, czy w `/var/log/secure` hasło nie ma doklejonego znaku | |
| A4 | Czy PAM dostaje hasło dla **nieistniejącego** użytkownika? | po włączeniu hooka: `ssh nieistnieje@<ip>` ze złym hasłem, potem `grep hp-pam /var/log/secure \| tail -1` | jest linia (hasło zapisane) albo brak linii (udokumentuj) |
| A5 | Czy SELinux nie blokuje `logger`/`pam_exec`? | `ausearch -m avc -ts recent \| grep -i -E 'hp-pam\|logger'` | brak odmów |

## Krok B: włączenie i sonda

1. W `honeypot.conf` ustaw `HP_PAM_HOOK=yes` i uruchom `setup-honeypot.sh`. Skrypt zrobi kopię `/etc/pam.d/sshd.hp-orig`.
2. Z drugiej maszyny wykonaj poniższe i porównaj z oczekiwanym wynikiem.

| # | Działanie | Oczekiwane |
|---|---|---|
| B1 | `ssh jkowalski@<ip>` ze **złym** hasłem (istniejące konto) | w `/var/log/secure` linia `hp-pam: u=... h=<ip> p=...`; na serwerze raport `auth.attempt` z poprawnym hasłem (`credential.password`) i osobny `auth.failure` |
| B2 | `ssh nieistnieje@<ip>` ze złym hasłem | jak B1, albo (jeśli A4 = brak) udokumentowane odstępstwo |
| B3 | `ssh jkowalski@<ip>` z **dobrym** hasłem | **brak** linii `hp-pam:` (anty-cel: hasło udanego logowania nie może się zapisać) |
| B4 | logowanie kluczem (`svc-admin`) | działa i **brak** linii `hp-pam:` |
| B5 | `nmap -sS -p 1-100 <ip>` z drugiej maszyny | dokładnie **jedno** `net.scan` (`event.detail.ports >= 10`, `scan: syn`), **brak** osobnych raportów z linii zapory w tym czasie |
| B6 | `smbclient //<ip>/Dokumenty -U jkowalski%zle -c ls` | `auth.failure` z `service: smb` jak dotąd; brak `auth.attempt` (SMB nie przekazuje hasła jawnego) |
| B7 | podrobiona linia: `ssh 'hp-pam: u=YQ== h=1.2.3.4 p=YQ=='@<ip>` | zwykły `auth.failure`, **brak** `auth.attempt` z hasłem `a` |
| B9 | co znika po wpięciu (podstawka `password-auth` zastąpiona blokiem `pam_unix`/`pam_exec`/`pam_deny`) | porównaj `/etc/pam.d/password-auth` z `/etc/pam.d/sshd`: czy występują `pam_sss`, `pam_faildelay`, `pam_faillock`, `pam_env`; czas odpowiedzi na złe hasło przed i po (`time ssh ...`) | zapisz, co zniknęło; konta spoza `/etc/passwd` (SSSD) nie zalogują się; decyzja właściciela, czy to akceptowalne |
| B10 | UDP/ICMP/broadcast w logu zapory (`nmap -sU`, ruch NetBIOS) | liczba raportów `log.entry` z linii `kernel:` w czasie testu | zero (konsumowane), `net.scan` tylko dla TCP |
| B8 | po testach: `ssh svc-admin@<ip>` w nowej sesji | logowanie nadal działa (PAM niezepsuty) |

Jeśli któryś wiersz (B3, B4, B8 w szczególności) nie przechodzi: przywróć `/etc/pam.d/sshd.hp-orig`, **nie wdrażaj** wariantu
zapisującego hasła zawsze i opisz wynik.

## Wyniki (uzupełnij po wykonaniu)

Nie wykonano jeszcze. Ten dokument powstał przy implementacji bez dostępu do Almy.
