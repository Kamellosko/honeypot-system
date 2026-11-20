#!/bin/sh
# Test hooka PAM scripts/hp-pam-log: logger podmieniony stubem, sprawdzamy argumenty i kod wyjscia.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/../hp-pam-log"
TMP=$(mktemp -d /tmp/hp-pam-test-XXXXXX)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"
cat > "$TMP/bin/logger" <<'STUB'
#!/bin/sh
for a in "$@"; do printf '%s\n' "$a"; done > "$HP_LOGGER_OUT"
cat > "$HP_LOGGER_OUT.stdin"
exit "${HP_LOGGER_RC:-0}"
STUB
chmod +x "$TMP/bin/logger"
export PATH="$TMP/bin:$PATH" HP_LOGGER_OUT="$TMP/out"
fail() { echo "FAIL: $1"; exit 1; }

# check <stdin-printf-format> <PAM_USER> <PAM_RHOST> <expected message> <name>
# Wiadomosc idzie na stdin loggera, nie w argv (argv czyta kazdy lokalny uzytkownik z /proc/<pid>/cmdline).
check() {
  rm -f "$TMP/out" "$TMP/out.stdin"
  out=$(printf "$1" | PAM_USER="$2" PAM_RHOST="$3" sh "$SCRIPT" 2>&1); rc=$?
  [ "$rc" = 0 ] || fail "$5: exit $rc"
  [ -z "$out" ] || fail "$5: unexpected output: $out"
  [ "$(sed -n 1p "$TMP/out")" = "-p" ] && [ "$(sed -n 2p "$TMP/out")" = "authpriv.info" ] || fail "$5: priority args"
  [ "$(sed -n 3p "$TMP/out")" = "-t" ] && [ "$(sed -n 4p "$TMP/out")" = "hp-pam" ] || fail "$5: tag args"
  [ "$(wc -l < "$TMP/out")" = 4 ] || fail "$5: logger argv must hold only -p/-t options, got: $(cat "$TMP/out")"
  [ "$(cat "$TMP/out.stdin")" = "$4" ] || fail "$5: got '$(cat "$TMP/out.stdin")' want '$4'"
}

check 'hunter2'     bob 203.0.113.9 'u=Ym9i h=203.0.113.9 p=aHVudGVyMg==' "plain password"
check 'hunter2\0'   bob 203.0.113.9 'u=Ym9i h=203.0.113.9 p=aHVudGVyMg==' "NUL-terminated password"
check 'a"b c=d'     bob 203.0.113.9 'u=Ym9i h=203.0.113.9 p=YSJiIGM9ZA==' "quote, space and equals"
check ''            bob 203.0.113.9 'u=Ym9i h=203.0.113.9 p=' "empty password"
check 'hunter2'     bob ''          'u=Ym9i h= p=aHVudGVyMg==' "missing rhost"
check 'hunter2'     bob '1.2.3.4 x' 'u=Ym9i h=1.2.3.4x p=aHVudGVyMg==' "whitespace stripped from rhost"
check 'ab\n'        bob 203.0.113.9 'u=Ym9i h=203.0.113.9 p=YWIK' "trailing newline kept"

# haslo dluzsze niz 1024 bajty jest obcinane do 1024 (base64: 1368 znakow)
rm -f "$TMP/out"
head -c 5000 /dev/zero | tr '\0' 'A' | PAM_USER=bob PAM_RHOST=1.2.3.4 sh "$SCRIPT" || fail "long: exit"
p=$(sed 's/.* p=//' "$TMP/out.stdin")
[ "${#p}" = 1368 ] || fail "long password: base64 length ${#p}, want 1368"

# blad loggera nie zmienia wyniku (hook PAM nie moze psuc logowania) i nic nie wypisuje
rm -f "$TMP/out"
out=$(printf 'x' | HP_LOGGER_RC=1 PAM_USER=bob PAM_RHOST=1.2.3.4 sh "$SCRIPT" 2>&1); rc=$?
[ "$rc" = 0 ] && [ -z "$out" ] || fail "logger failure: rc=$rc out='$out'"

echo "PASS pam_log"
