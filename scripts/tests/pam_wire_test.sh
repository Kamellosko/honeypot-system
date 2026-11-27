#!/bin/sh
# Test scripts/hp-pam-wire na kopiach typowego /etc/pam.d/sshd (nic nie dotyka prawdziwego PAM).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WIRE="$HERE/../hp-pam-wire"
TMP=$(mktemp -d /tmp/hp-pam-wire-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
fail() { echo "FAIL: $1"; exit 1; }

mk() {
  cat > "$1" <<'PAM'
#%PAM-1.0
auth       substack     password-auth
auth       include      postlogin
account    required     pam_sepermit.so
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
PAM
}

# swieza konfiguracja: wpiete, kopia zapasowa identyczna z oryginalem, +3 linie, kolejnosc modulow zachowana
F="$TMP/sshd"; mk "$F"; cp "$F" "$TMP/orig"
sh "$WIRE" "$F" >/dev/null || fail "fresh: exit $?"
cmp -s "$F.hp-orig" "$TMP/orig" || fail "fresh: backup differs from original"
[ "$(wc -l < "$F")" = "$(( $(wc -l < "$TMP/orig") + 3 ))" ] || fail "fresh: line count"
grep -q 'hp-pam-hook' "$F" || fail "fresh: marker missing"
[ "$(grep -c 'pam_exec.so expose_authtok quiet seteuid /usr/local/libexec/hp-pam-log' "$F")" = 1 ] || fail "fresh: pam_exec line"
[ "$(grep -c 'substack' "$F")" = 0 ] || fail "fresh: substack line should be replaced"
grep -q 'success=2' "$F" || fail "fresh: success=2 skip missing"

# ponowne uruchomienie: bez zmian (idempotentne), kopia nietknieta
cp "$F" "$TMP/after1"; cp "$F.hp-orig" "$TMP/bak1"
sh "$WIRE" "$F" >/dev/null || fail "rerun: exit $?"
cmp -s "$F" "$TMP/after1" || fail "rerun: file changed"
cmp -s "$F.hp-orig" "$TMP/bak1" || fail "rerun: backup changed"

# plik zmieniony po przywroceniu (np. aktualizacja pakietu): kopia musi pochodzic z BIEZACEGO pliku, nie ze starej kopii
F2="$TMP/sshd2"; mk "$F2"; sh "$WIRE" "$F2" >/dev/null || fail "stale: first wire"
mk "$F2"; echo 'session    optional     pam_added_by_update.so' >> "$F2"   # przywrocony + zmieniony przez admina
sh "$WIRE" "$F2" >/dev/null || fail "stale: second wire exit $?"
grep -q 'pam_added_by_update.so' "$F2" || fail "stale: current content lost (wired from stale backup)"
grep -q 'pam_added_by_update.so' "$F2.hp-orig" || fail "stale: backup not refreshed from current file"

# brak dokladnie jednej linii substack: plik bez zmian, kod 1
F3="$TMP/sshd3"; printf '#%%PAM-1.0\nauth required pam_deny.so\n' > "$F3"; cp "$F3" "$TMP/o3"
sh "$WIRE" "$F3" >/dev/null 2>&1; rc=$?
[ "$rc" = 1 ] || fail "no-match: exit $rc, want 1"
cmp -s "$F3" "$TMP/o3" || fail "no-match: file changed"
F4="$TMP/sshd4"; mk "$F4"; echo 'auth       substack     password-auth' >> "$F4"; cp "$F4" "$TMP/o4"   # dwie linie
sh "$WIRE" "$F4" >/dev/null 2>&1; rc=$?
[ "$rc" = 1 ] && cmp -s "$F4" "$TMP/o4" || fail "two-matches: exit $rc or file changed"

# brak argumentu / brak pliku: kod != 0
sh "$WIRE" >/dev/null 2>&1 && fail "no-arg should fail"
sh "$WIRE" "$TMP/nonexistent" >/dev/null 2>&1 && fail "missing file should fail"
echo "PASS pam_wire"
