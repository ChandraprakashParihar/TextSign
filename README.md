# TrustSign

TrustSign is a Java 17 PDF/text signing service with PKCS#11 and HSM support.

## Production Setup

Use these documents before go-live:

- `PRODUCTION-HARDENING.md` — mandatory security and operational checklist.
- `config/config.production.json` — production config template (safe defaults, no plaintext PIN).

## Quick Start

- Local/dev config: `config/config.json`
- Production template: `config/config.production.json`

Run:

```bash
TRUSTSIGN_TOKEN_PIN=your-pin java -jar trustsign-0.1.0-all.jar --config=config/config.production.json
```

## Packaging for Clients

- Cross-platform client package (Windows/macOS/Linux, requires installed Java):
  - `./gradlew clientFolderCrossPlatform`
  - output: `build/client`
  - launchers included: `run-trustsign.bat`, `run-trustsign.sh`, `run-trustsign.command`
- Windows package with bundled JRE:
  - `./gradlew clientFolderWindows`
  - output: `build/client`
- macOS package with bundled JRE (x64):
  - `./gradlew clientFolderMac -PmacJreSha256=<sha256>`
  - or set `TRUSTSIGN_MAC_JRE_SHA256`
  - output: `build/client`
- Linux package with bundled JRE (x64):
  - `./gradlew clientFolderLinux -PlinuxJreSha256=<sha256>`
  - or set `TRUSTSIGN_LINUX_JRE_SHA256`
  - output: `build/client`
- Windows installer (`.exe`):
  - `./gradlew buildInstaller`
  - or `./gradlew packageWindowsExe` (jpackage, Windows host only)
  - and `./gradlew packageWindowsMsi` (jpackage MSI, Windows host only)

To calculate SHA-256 for any downloaded archive:

```bash
./gradlew printSha256 -Pfile=/absolute/path/to/archive.tar.gz
```

## One-command Release

- Build platform client zips in one command:
  - `./gradlew releaseAllClients`
  - outputs to `build/release`

Artifacts produced:
- `trustsign-client-windows-<version>.zip`
- `trustsign-client-mac-<version>.zip`
- `trustsign-client-linux-<version>.zip`

Native packages (host OS only):
- On macOS host: `.app` image and `.dmg`
- On Linux host: `app-image`, `.deb`, `.rpm`
- On Windows host: `.exe` via `buildInstaller` (Inno Setup), `.exe` via `packageWindowsExe`, and `.msi` via `packageWindowsMsi`

Note: OS-native installers must be built on their respective OS hosts.

### macOS signing + notarization (optional, recommended)

Unsigned DMGs may be blocked by Gatekeeper on client machines. For trusted distribution:

1. Build signed DMG:
   - `./gradlew packageMacDmg -PmacJreSha256=<sha256> -PmacSignIdentity="Developer ID Application: <Your Name> (<TEAMID>)"`
2. Notarize + staple:
   - Create keychain profile once (Apple docs), then:
   - `./gradlew notarizeMacDmg -PmacJreSha256=<sha256> -PmacSignIdentity="Developer ID Application: <Your Name> (<TEAMID>)" -PmacNotaryProfile=<profile>`
3. Verify Gatekeeper acceptance:
   - `./gradlew verifyMacDmgGatekeeper -PmacJreSha256=<sha256> -PmacSignIdentity="Developer ID Application: <Your Name> (<TEAMID>)"`

Supported env vars:
- `TRUSTSIGN_MAC_SIGN_IDENTITY`
- `TRUSTSIGN_MAC_SIGNING_KEYCHAIN` (optional custom keychain)
- `TRUSTSIGN_MAC_NOTARY_PROFILE`

What’s now available
In build.gradle:

Native package tasks

macOS:
packageMacAppImage (.app)
packageMacDmg (.dmg)
Linux:
packageLinuxAppImage
packageLinuxDeb
packageLinuxRpm
Windows:
existing buildInstaller (.exe)
Per-platform bundled client zips

releaseWindowsZip
releaseMacZip
releaseLinuxZip
Single orchestrator

releaseAllClients
Builds all client zips + native packages supported on current host OS.
Outputs to build/release.


Implemented ✅ — macOS signing/notarization automation is now in your build.

Added in build.gradle
Optional signing support for:
packageMacAppImage
packageMacDmg
New task:
notarizeMacDmg
submits DMG via xcrun notarytool --wait
staples ticket via xcrun stapler
New properties / env vars supported
Signing identity:
-PmacSignIdentity="Developer ID Application: ..."
or TRUSTSIGN_MAC_SIGN_IDENTITY
Optional keychain:
-PmacSigningKeychain=/path/to/keychain-db
or TRUSTSIGN_MAC_SIGNING_KEYCHAIN
Notary profile:
-PmacNotaryProfile=<profile>
or TRUSTSIGN_MAC_NOTARY_PROFILE
Usage
./gradlew packageMacDmg \
  -PmacJreSha256=<sha256> \
  -PmacSignIdentity="Developer ID Application: Your Name (TEAMID)"
Then:

./gradlew notarizeMacDmg \
  -PmacJreSha256=<sha256> \
  -PmacSignIdentity="Developer ID Application: Your Name (TEAMID)" \
  -PmacNotaryProfile=<profile>

"logging": {
  "directory": "logs",
  "level": "INFO",
  "consoleEnabled": true,
  "failOnError": false
}
"logFilePath": "/Users/jainnibha/output/logs/trustsign/app.log",
  "hsm": {
    "preferredLibrary": null,
    "slotProbeCount": 32,
    "windowsCandidates": [
    ],
    "macCandidates": [],
    "linuxCandidates": []
  },
  "tsa": {
    "url": "http://timestamp.digicert.com",
    "hashAlgorithm": "SHA-256",
    "failOnError": true,
    "connectTimeoutMs": 10000,
    "readTimeoutMs": 15000
  },
  "ltv": {
    "enabled": true,
    "failOnMissingRevocationData": true,
    "ocspConnectTimeoutMs": 10000,
    "ocspReadTimeoutMs": 15000,
    "crlConnectTimeoutMs": 10000,
    "crlReadTimeoutMs": 15000
  }


  output (raw | file | both)
outputFormat (base64 | hex | binary)

scripts/load-test.sh
It gives repeatable performance checks with concurrency and percentile stats.

What it does
Sends concurrent requests using curl
Supports:
--url
--method (GET/POST)
--requests
--concurrency
--headers (file with one header per line)
--body (request body file)
--connect-timeout
--timeout
--insecure
--warmup
Prints:
throughput (req/s)
status counts (2xx/3xx, 4xx, 5xx, 000)
latency (min, p50, p95, p99, max, avg)
Quick examples
Basic performance check:
./scripts/load-test.sh
Stress your new metrics endpoint:
./scripts/load-test.sh --url http://127.0.0.1:80/pki/health/performance --requests 500 --concurrency 50
Test token validation endpoint:
./scripts/load-test.sh --url http://127.0.0.1:80/pki/validate-token --method POST --requests 200 --concurrency 20