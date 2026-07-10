# How to run TrustSign (for clients)

The client package includes a **bundled JRE** (Windows), so **the client does not need to install Java**. They run **run-trustsign.bat** (Windows) or use the JAR with Java 17+ (Mac/Linux).

---

## Build the client folder (recommended)

**Before building**, put the signer's **public key** in **`config/public-key.pem`** (PEM format: either `-----BEGIN PUBLIC KEY-----` or a certificate `-----BEGIN CERTIFICATE-----`). Signing uses only the certificate on the token that matches this public key.

From the project root run:

```bash
./gradlew clientFolder
```

This creates **`build/client/`** with everything the client needs:

```
build/client/
  trustsign-0.1.0-all.jar
  run-trustsign.bat      ← double-click to start (uses bundled JRE on Windows)
  jre/                   ← bundled Java (Windows); client does not install Java
  config/
    config.json
    public-key.pem       ← the public key you provided
  README.txt
```

**Give the client the whole `build/client` folder** (e.g. zip it) plus a separate **`activation-key.txt`** file.

> The client places `activation-key.txt` in the `config/` folder before first launch. On first run the app contacts the licensing server, activates, and saves an encrypted licence locally. All subsequent runs are fully offline.

---

## What's inside the client folder

1. **trustsign-0.1.0-all.jar** – fat JAR (app + dependencies).
2. **run-trustsign.bat** – double-click to start the service.
3. **config/config.json** – default config (port, PKCS#11 paths). Client can edit if needed.
4. **config/public-key.pem** – signer's public key (used to select which certificate on the token is used for signing). **Required for signing.**
5. **config/truststore.jks** – (if present) trust store for certificate chain validation.
6. **README.txt** – copy of these instructions for the client.

**First-run only:** Place **`activation-key.txt`** (provided separately by the vendor) in the `config/` folder. The app activates automatically on launch and writes `config/.licence.dat`.

**Token PIN:** The client must set the token PIN so the service can use the key. Either:
- Edit **config/config.json** and set **`pkcs11.pin`** to the token PIN (e.g. `"pin": "12345678"`), or
- Set the environment variable **`TRUSTSIGN_TOKEN_PIN`** to the token PIN (no need to store in the file).

---

## How the client runs the service

1. **Windows:** No need to install Java — the package includes a bundled JRE. **Mac/Linux:** Install Java 17 or later if not already present.
2. Put the folder contents in one place (e.g. `TrustSign`). Do not remove the `jre` folder (Windows).
3. Place **`activation-key.txt`** in the `config/` folder (first run only).
4. **Double-click `run-trustsign.bat`**
   - Or open Command Prompt in that folder and run:
     `java -jar trustsign-0.1.0-all.jar`
5. When it's running, the service will show something like:
   `TrustSign text server listening on http://127.0.0.1:31927/v1`
6. To stop: close the window or press Ctrl+C in the command window.

---

## Run as a background service (recommended)

By default, double-clicking the launcher runs TrustSign in a console window that
stops when the window is closed or the machine reboots. To keep TrustSign running
in the background — starting automatically at boot and restarting itself if it
ever crashes — install it as a native OS service instead. Each client package
includes a `service/` folder with everything needed:

```
build/client/service/
  windows/  install-service.bat, uninstall-service.bat, trustsign-service.exe, trustsign-service.xml
  linux/    install-service.sh, uninstall-service.sh, trustsign.service
  macos/    install-service.sh, uninstall-service.sh, com.trustsign.server.plist
```


sudo launchctl disable system/com.trustsign.server
sudo launchctl enable system/com.trustsign.server
sudo ./service/macos/install-service.sh

**Important:** set up `config/config.json` (PIN, port, etc.) and, if applicable,
`activation-key.txt` **before** installing the service — a service has no console
to prompt you interactively.

### Windows

The Windows installer (`TrustSign-Setup.exe`) offers an "Install and start TrustSign
as a Windows Service" checkbox that does this automatically. To do it manually
(e.g. from the zip package):

1. Right-click `service\windows\install-service.bat` → **Run as administrator**.
2. This registers "TrustSign Signing Service" (via the bundled WinSW wrapper),
   set to start automatically at boot, and starts it immediately.
3. Manage it from `services.msc`, or `service\windows\uninstall-service.bat` (also as Administrator) to remove it.

By default the service runs as `LocalSystem`. If your USB token/HSM driver
requires a specific Windows user's profile, edit `trustsign-service.xml` (the
`<serviceaccount>` block) before installing.

### Linux (systemd)

```bash
cd TrustSign   # the extracted client folder
sudo ./service/linux/install-service.sh
```

Installs and enables `trustsign.service`, running as the user who invoked `sudo`.
Manage with `systemctl status trustsign` / `sudo systemctl stop trustsign`. Remove
with `sudo ./service/linux/uninstall-service.sh`.

### macOS (launchd)

```bash
cd TrustSign   # the extracted client folder
sudo ./service/macos/install-service.sh
```

Installs a LaunchDaemon that starts at boot, before any user logs in. Manage with
`sudo launchctl print system/com.trustsign.server`. Remove with
`sudo ./service/macos/uninstall-service.sh`.

### Notes for all platforms

- Logs go to `logs/` in the install folder either way (via `logging.directory` in
  `config.json`), plus a `service-stdout.log`/`service-stderr.log` for crash diagnostics.
- If your signing token is a USB PKCS#11 dongle, confirm it's reachable without an
  interactive desktop session — most PKCS#11 shared-library drivers are fine, but
  some vendor drivers assume a logged-in user. Test the service after installing
  by rebooting and checking the logs before relying on it in production.
- A running service and the interactive `run-trustsign.*` launcher both bind the
  same port — don't run both at once.

## Optional: run from command line only

If the client prefers not to use the batch file:

```bat
cd C:\path\to\TrustSign
java -jar trustsign-0.1.0-all.jar
```

The app reads **`config/config.json`** from the current directory. To use another config file:

```bat
java -jar trustsign-0.1.0-all.jar --config=C:\path\to\config.json
```

---

## Build tasks

| Task | What it does |
|------|----------------|
| **`./gradlew clientFolder`** | Creates `build/client/` with JAR, run script, config, **public-key.pem**, and README. Requires `config/public-key.pem` to exist first. |
| `./gradlew shadowJar` | Builds only the fat JAR to `build/libs/trustsign-0.1.0-all.jar` |
