#!/usr/bin/env sh
# Creates a JKS truststore from your XT CA certificates for chain validation.
# Usage:
#   ./scripts/create-truststore.sh
#   ./scripts/create-truststore.sh /path/to/xtcacert.cer /path/to/xtsubcacert.cer /path/to/xtcert.cer
#
# Output: config/truststore.jks (default password: changeit)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYSTORE="${KEYSTORE:-$PROJECT_DIR/config/truststore.jks}"
STORE_PASS="${STORE_PASS:-trustsign}"

if [ $# -ge 3 ]; then
  XTCA="$1"
  XTSUBCA="$2"
  XTCERT="$3"
else
  XTCA="${XTCA:-$HOME/Documents/xtcacert.cer}"
  XTSUBCA="${XTSUBCA:-$HOME/Documents/xtsubcacert.cer}"
  XTCERT="${XTCERT:-$HOME/Documents/xtcert.cer}"
fi

for f in "$XTCA" "$XTSUBCA" "$XTCERT"; do
  if [ ! -f "$f" ]; then
    echo "Missing: $f"
    exit 1
  fi
done

mkdir -p "$(dirname "$KEYSTORE")"

# Create JKS and import root CA first, then sub CA, then cert (order can help with chain building)
keytool -importcert -alias xtca -file "$XTCA" -keystore "$KEYSTORE" -storepass "$STORE_PASS" -noprompt
keytool -importcert -alias xtsubca -file "$XTSUBCA" -keystore "$KEYSTORE" -storepass "$STORE_PASS" -noprompt
keytool -importcert -alias xtcert -file "$XTCERT" -keystore "$KEYSTORE" -storepass "$STORE_PASS" -noprompt

echo "Created $KEYSTORE (password: $STORE_PASS)"
echo "Add to config.json: \"truststore\": { \"path\": \"config/truststore.jks\", \"password\": \"$STORE_PASS\", \"enablePathValidation\": true }"
