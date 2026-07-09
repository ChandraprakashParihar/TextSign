#!/usr/bin/env bash
# Installs TrustSign as a macOS LaunchDaemon that starts at boot (before login)
# and restarts on crash. Run from the extracted client folder:
#   sudo ./service/macos/install-service.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo ./service/macos/install-service.sh"
  exit 1
fi

cd "$(dirname "$0")/../.."
APP_DIR="$(pwd)"

JAR=""
for f in trustsign-*-all.jar trustsign*.jar; do
  if [ -f "$f" ]; then JAR="$f"; break; fi
done
if [ -z "$JAR" ]; then
  echo "No trustsign JAR found in $APP_DIR"
  exit 1
fi

if [ ! -f "config/config.json" ]; then
  echo "Missing config/config.json. Set it up before installing the service."
  exit 1
fi

JAVA_BIN="$(command -v java || true)"
if [ -x "$APP_DIR/jre/bin/java" ]; then
  JAVA_BIN="$APP_DIR/jre/bin/java"
fi
if [ -z "$JAVA_BIN" ]; then
  echo "Java not found. Install Java 17+, or use the bundled-JRE macOS client package."
  exit 1
fi

mkdir -p "$APP_DIR/logs"
PLIST=/Library/LaunchDaemons/com.trustsign.server.plist

sed \
  -e "s#__INSTALL_DIR__#$APP_DIR#g" \
  -e "s#__JAVA_BIN__#$JAVA_BIN#g" \
  -e "s#__JAR_NAME__#$JAR#g" \
  "$APP_DIR/service/macos/com.trustsign.server.plist" > "$PLIST"

chown root:wheel "$PLIST"
chmod 644 "$PLIST"

launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable system/com.trustsign.server

echo "TrustSign installed as a macOS LaunchDaemon."
echo "It starts at boot (before login) and restarts automatically if it crashes."
echo "Status: sudo launchctl print system/com.trustsign.server"
echo "Stop:   sudo launchctl bootout system \"$PLIST\""
echo "Remove: sudo ./service/macos/uninstall-service.sh"
