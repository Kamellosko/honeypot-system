#!/usr/bin/env bash
# Generate a local CA and a server certificate for the honeypot receiver.
#
# The C agent verifies the TLS chain AND the receiver IP/host in the certificate
# SAN, and that verification cannot be disabled agent-side. So the server needs
# a cert whose SAN contains exactly the address the agent connects to, and the
# agent must trust the CA that signed it.
#
# Usage:
#   scripts/gen-certs.sh [SAN ...]
#
# Each SAN is "IP:1.2.3.4" or "DNS:host.example". With no arguments it defaults
# to IP:127.0.0.1 (local testing, matches the agent's default
# DEST_IP). Pass the real address when the agent runs on another host, e.g.:
#   scripts/gen-certs.sh IP:192.0.2.10
#   scripts/gen-certs.sh IP:127.0.0.1 DNS:collector.lab
#
# Outputs (under certs/, git-ignored):
#   ca.crt               - give this to the agent:  SSL_CERT_FILE=.../ca.crt
#   ca.key               - CA private key (keep local)
#   server.crt/.key      - server leaf cert and key
#   server-keystore.p12  - PKCS12 keystore the Java server loads
#
# Keystore password: $KEYSTORE_PASSWORD (default "changeit"); must match
# server.keystore.password in config/server.properties.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="certs"
PASS="${KEYSTORE_PASSWORD:-changeit}"
DAYS="${CERT_DAYS:-825}"

if [ "$#" -eq 0 ]; then
  set -- IP:127.0.0.1
fi

# Build the subjectAltName line from the arguments.
SAN=""
for entry in "$@"; do
  case "$entry" in
    IP:*|DNS:*) ;;
    *) echo "error: SAN entries must look like IP:1.2.3.4 or DNS:host, got '$entry'" >&2; exit 1;;
  esac
  SAN="${SAN:+$SAN,}$entry"
done

mkdir -p "$OUT"

echo ">> CA"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$DAYS" \
  -subj "/CN=Fleet Monitoring CA" \
  -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

echo ">> server key + CSR"
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=monitoring receiver" \
  -keyout "$OUT/server.key" -out "$OUT/server.csr" 2>/dev/null

echo ">> server cert (SAN: $SAN)"
EXT="$OUT/server.ext"
cat > "$EXT" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF
openssl x509 -req -in "$OUT/server.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/server.crt" -days "$DAYS" -sha256 -extfile "$EXT" 2>/dev/null

echo ">> PKCS12 keystore"
openssl pkcs12 -export \
  -inkey "$OUT/server.key" -in "$OUT/server.crt" -certfile "$OUT/ca.crt" \
  -name server -passout "pass:$PASS" \
  -out "$OUT/server-keystore.p12"

rm -f "$OUT/server.csr" "$OUT/server.ext" "$OUT/ca.srl"
# The CA cert is trusted system-wide on the host, so anyone who can read ca.key
# could mint certificates for any name. Drop it unless asked to keep it.
if [ "${KEEP_CA_KEY:-no}" != "yes" ]; then
  rm -f "$OUT/ca.key"
  echo ">> ca.key usunięty (KEEP_CA_KEY=yes zachowuje; nowy cert wymaga ponownego uruchomienia skryptu)"
fi
chmod 600 "$OUT"/*.key "$OUT"/*.p12 2>/dev/null || true

echo
echo "Done. Files in $(pwd)/$OUT:"
echo "  server-keystore.p12  -> config/server.properties: server.keystore (pass: $PASS)"
echo "  ca.crt               -> run the agent with: SSL_CERT_FILE=$(pwd)/$OUT/ca.crt"
