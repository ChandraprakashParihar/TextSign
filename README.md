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

To calculate SHA-256 for any downloaded archive:

```bash
./gradlew printSha256 -Pfile=/absolute/path/to/archive.tar.gz
```
