# TrustSign Windows Installer

This folder contains the Inno Setup script to build a Windows installer for TrustSign. The installer packages **the same files as the client folder** (`build/client`): JAR, `run-trustsign.bat`, `config/` (config.json, licence.json, public-key.pem, truststore.jks, SET-PIN.txt), README.txt, and bundled JRE.

- **Bundled JRE**: Eclipse Temurin 17 JRE for Windows x64 — the client does **not** need to install Java.
- **Same as zip client**: `./gradlew buildInstaller` first runs `clientFolder`, then packages `build/client` into the .exe. So the installed app matches what you get from zipping `build/client`.
- **Run at startup**: Optional task "Run TrustSign when Windows starts" creates a shortcut in the Startup folder.
- **Shortcuts**: Start menu and optional desktop shortcut to run TrustSign.

## What’s in this folder

- **TrustSign.iss** – Inno Setup script (packages `build/client`).
- **config.json**, **licence.json** – Optional overrides; the client package prefers `config/config.json` and `config/licence.json` (see build.gradle). Put a signed licence in `config/licence.json` (or here) before running `clientFolder` / `buildInstaller`.

## Prerequisites (for building the installer)

1. **Java 17+** and **Gradle** (to build the app).
2. **Inno Setup 6** ([download](https://jrsoftware.org/isinfo.php)). Install to the default path so Gradle finds `ISCC.exe`, or add it to PATH.

## Build the installer

1. **Sign a licence** and ensure **config/licence.json** (or installer/licence.json) exists (see **GIVE-TO-CLIENT.md**).
2. From the project root:

```bash
./gradlew buildInstaller
```

The installer is created at:

**`build/installer/TrustSign-0.1.0-Setup.exe`**

If you don’t have Inno Setup, you can still give clients the same content as a zip: run `./gradlew clientFolder` and zip `build/client`.

## What to give the client

1. **TrustSign-0.1.0-Setup.exe** – the installer (same content as `build/client`, including bundled JRE).
2. Or zip **build/client** and give that instead; they run `run-trustsign.bat`.

Config is in `{InstallDir}\config\` (config.json, licence.json, public-key.pem, etc.).

## Production Config Recommendation

For production deployments, start from `config/config.production.json` (project root) instead of dev-style configs.

- Copy it to your deployment config location as `config.json`.
- Set strict values for:
  - `allowedOrigins`
  - `allowedClientIps`
  - `server.maxTcpConnections`
  - `server.maxConcurrentSigningOperations`
- Keep `server.enableDebugEndpoints` as `false`.
- Keep `pkcs11.pin` as `null` and provide PIN through `TRUSTSIGN_TOKEN_PIN`.
