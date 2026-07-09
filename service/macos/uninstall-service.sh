#!/usr/bin/env bash
# Removes the TrustSign LaunchDaemon installed by install-service.sh.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo: sudo ./service/macos/uninstall-service.sh"
  exit 1
fi

PLIST=/Library/LaunchDaemons/com.trustsign.server.plist
launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
echo "TrustSign service removed."
