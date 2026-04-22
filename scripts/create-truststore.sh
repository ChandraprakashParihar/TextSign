#!/usr/bin/env sh
# Creates a truststore from a CA chain for certificate path validation.
# Usage:
#   ./scripts/create-truststore.sh
#   ./scripts/create-truststore.sh /path/to/root-ca.cer /path/to/intermediate-ca.cer /path/to/sub-ca.cer
#
# Output: config/truststore.jks (default password: trustsign)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYSTORE="${KEYSTORE:-$PROJECT_DIR/config/truststore.jks}"
STORE_PASS="${STORE_PASS:-trustsign}"

if [ $# -ge 3 ]; then
  ROOT_CA="$1"
  INTERMEDIATE_CA="$2"
  SUB_CA="$3"
else
  ROOT_CA="${ROOT_CA:-$HOME/Documents/root-ca.cer}"
  INTERMEDIATE_CA="${INTERMEDIATE_CA:-$HOME/Documents/intermediate-ca.cer}"
  SUB_CA="${SUB_CA:-$HOME/Documents/sub-ca.cer}"
fi

for f in "$ROOT_CA" "$INTERMEDIATE_CA" "$SUB_CA"; do
  if [ ! -f "$f" ]; then
    echo "Missing: $f"
    exit 1
  fi
done

mkdir -p "$(dirname "$KEYSTORE")"

# Recreate store to avoid stale/duplicate aliases from previous chains.
rm -f "$KEYSTORE"

# Import chain as trust anchors: root -> intermediate -> sub CA.
keytool -importcert -alias root-ca -file "$ROOT_CA" -keystore "$KEYSTORE" -storepass "$STORE_PASS" -storetype PKCS12 -noprompt
keytool -importcert -alias intermediate-ca -file "$INTERMEDIATE_CA" -keystore "$KEYSTORE" -storepass "$STORE_PASS" -storetype PKCS12 -noprompt
keytool -importcert -alias sub-ca -file "$SUB_CA" -keystore "$KEYSTORE" -storepass "$STORE_PASS" -storetype PKCS12 -noprompt

echo "Created $KEYSTORE (password: $STORE_PASS, type: PKCS12)"
echo "Add to config.json: \"truststore\": { \"path\": \"truststore.jks\", \"password\": \"$STORE_PASS\", \"type\": \"PKCS12\", \"enablePathValidation\": true }"
