#!/usr/bin/env sh
# Installs TrustSign as a systemd service that starts at boot and restarts on crash.
# Run from the extracted client folder: sudo ./service/linux/install-service.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo ./service/linux/install-service.sh"
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
  echo "Java not found. Install Java 17+, or use the bundled-JRE Linux client package."
  exit 1
fi

# Service runs as the user who invoked sudo (falls back to root), so a PKCS#11
# token/HSM driver relying on that user's profile/udev permissions still works.
SERVICE_USER="${SUDO_USER:-root}"

mkdir -p "$APP_DIR/logs"

sed \
  -e "s#__INSTALL_DIR__#$APP_DIR#g" \
  -e "s#__JAVA_BIN__#$JAVA_BIN#g" \
  -e "s#__JAR_NAME__#$JAR#g" \
  -e "s#__SERVICE_USER__#$SERVICE_USER#g" \
  "$APP_DIR/service/linux/trustsign.service" > /etc/systemd/system/trustsign.service

systemctl daemon-reload
systemctl enable --now trustsign.service

echo "TrustSign installed as a systemd service (runs as $SERVICE_USER)."
echo "It starts at boot and restarts automatically if it crashes."
echo "Status: systemctl status trustsign"
echo "Stop:   sudo systemctl stop trustsign"
echo "Remove: sudo ./service/linux/uninstall-service.sh"
