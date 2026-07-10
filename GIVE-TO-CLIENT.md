# Giving TrustSign to a client (vendor checklist)

Use this checklist when you want to deliver the service to a client.

---

## 1. Create an activation key for the client

Add a new entry to `keys.json` on your activation server:

```json
{
  "key":          "ABCDE-FGHIJ-KLMNO-PQRST",
  "customerId":   "acme-corp",
  "durationDays": 365,
  "used":         false,
  "activationId": null,
  "activatedAt":  0
}
```

- Use a strong random key (e.g. `UUID.randomUUID()` or a password manager).
- Set `durationDays` to the licence period (e.g. `365` for 1 year).
- Each key can only be used once — one key per customer machine.
- Keep `licence-private-key.pem` secret on the activation server. Never give it to clients.

---

## 2. Choose how to deliver

### Option A: Windows installer (recommended for Windows clients)

- Client gets a single **Setup.exe**; no Java install needed (JRE is bundled).
- **You must build the installer on Windows** (Inno Setup is Windows-only). On Mac/Linux, use Option B instead.

**Steps:**

1. Build the installer on a Windows machine:
   ```bash
   ./gradlew buildInstaller
   ```
2. Give the client:
   - **`build/installer/TrustSign-0.1.0-Setup.exe`**
   - **`activation-key.txt`** (the one-time activation key — keep this separate from the installer)

They run the installer, place `activation-key.txt` in the `config/` folder, and start TrustSign. On first launch the app activates automatically.

---

### Option B: Client folder (any OS, or when you can't build the installer)

- Client gets a folder with the JAR, **bundled Windows JRE**, run script, and config.

**Steps:**

1. Ensure **`config/public-key.pem`** exists (signer's public key for selecting the cert on the token).
2. Build the client package:
   ```bash
   ./gradlew clientFolder
   ```
3. Zip and give to the client:
   ```bash
   cd build && zip -r TrustSign-0.1.0-client.zip client/
   ```
   Give them **`TrustSign-0.1.0-client.zip`** and **`activation-key.txt`** separately.

The client unzips, places `activation-key.txt` in the `config/` folder, sets their token PIN, and runs `run-trustsign.bat` (Windows) or `java -jar trustsign-0.1.0-all.jar` (Mac/Linux).

---

## 3. What the client must do

- **Place `activation-key.txt`** in the `config/` folder before first launch.
- **Set the token PIN** so TrustSign can use the key:
  - Edit **`config/config.json`** and set **`pkcs11.pin`**, or
  - Set environment variable **`TRUSTSIGN_TOKEN_PIN`**.
- **Run the service** (double-click the batch file, or run the JAR).
- On **first launch**, the app contacts your activation server, validates the key, and saves an encrypted licence locally. Subsequent launches are fully offline.
- Optionally change **port** or **allowedOrigins** in `config/config.json` if needed.

---

## 4. Optional (recommended): install as a background service

So the client doesn't have to keep a console window open / manually restart it after
reboot, install it as a native background service — see `CLIENT-RUN.md` → "Run as a
background service" for the Windows/macOS/Linux steps. The Windows installer also
offers this as a checkbox.

**Order matters:** place `activation-key.txt` in `config/` and confirm the app
activates successfully (run it once in the foreground first) **before** installing
the service. A service has no console to prompt for the activation key — if
`.licence.dat` doesn't exist yet when the service starts, it will crash-loop trying
to read a key from stdin that isn't there.

---

## 5. Optional: truststore / chain validation

If you want the client to use **certificate chain validation** (your XT CA certs):

- Include **`config/truststore.jks`** in the package (the **clientFolder** task copies it automatically if it exists).
- Your **`config/config.json`** already has a **`truststore`** section; the same config is copied into the client folder. Ensure the **path** in that section is **`config/truststore.jks`** (relative) so it works in the client's folder.

If the client does not need chain validation, remove the **`truststore`** block from **`config/config.json`** before building the client package or installer.
