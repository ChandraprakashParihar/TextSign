#!/usr/bin/env sh
# Removes the TrustSign systemd service installed by install-service.sh.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo ./service/linux/uninstall-service.sh"
  exit 1
fi

systemctl stop trustsign.service 2>/dev/null || true
systemctl disable trustsign.service 2>/dev/null || true
rm -f /etc/systemd/system/trustsign.service
systemctl daemon-reload
echo "TrustSign service removed."
