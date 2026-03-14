# Giving TrustSign to a client (vendor checklist)

Use this checklist when you want to deliver the service to a client.

---

## 1. Create a licence for the client

Only you can set how long the client can use the service. The period starts when they **first run** the app.

```bash
# Example: 90 days from first use (use your private key path)
java -cp build/libs/trustsign-0.1.0-all.jar com.trustsign.tools.LicenceGenerator sign 90 build/tools-keys/licence-private-key.pem config/licence.json
```

- Put the signed **`config/licence.json`** where the client package will get it (see step 2).
- Keep **`licence-private-key.pem`** secret; never give it to the client.

---

## 2. Choose how to deliver

### Option A: Windows installer (recommended for Windows clients)

- Client gets a single **Setup.exe**; no Java install needed (JRE is bundled).
- **You must build the installer on Windows** (Inno Setup is Windows-only). On Mac/Linux, use Option B instead.

**Steps:**

1. Copy the signed licence into the installer folder:
   ```bash
   cp config/licence.json installer/licence.json
   ```
2. On a **Windows** machine with **Inno Setup 6** installed, run:
   ```bash
   ./gradlew buildInstaller
   ```
3. Give the client: **`build/installer/TrustSign-0.1.0-Setup.exe`**.

They run the installer, set their token PIN (in config or env), and start TrustSign from the Start menu or desktop shortcut.

---

### Option B: Client folder (any OS, or when you can’t build the installer)

- Client gets a folder with the JAR, **bundled Windows JRE**, run script, and config. **Windows clients do not need to install Java.** Mac/Linux clients need Java 17+ to run the JAR.

**Steps:**

1. Ensure **`config/public-key.pem`** exists (signer’s public key for selecting the cert on the token).
2. Ensure **`config/licence.json`** is the signed licence for this client (from step 1).
3. Build the client package:
   ```bash
   ./gradlew clientFolder
   ```
4. Zip the folder and give it to the client:
   ```bash
   cd build && zip -r TrustSign-0.1.0-client.zip client/
   ```
   Give them **`TrustSign-0.1.0-client.zip`**.

The client unzips, sets their token PIN (see README.txt inside the folder), and runs **`run-trustsign.bat`** (Windows) or `java -jar trustsign-0.1.0-all.jar` (Mac/Linux).

---

## 3. What the client must do

- **Set the token PIN** so TrustSign can use the key:
  - Edit **`config/config.json`** and set **`pkcs11.pin`**, or  
  - Set environment variable **`TRUSTSIGN_TOKEN_PIN`**.
- **Run the service** (double‑click the batch file, or run the JAR).
- Optionally change **port** or **allowedOrigins** in `config/config.json` if needed.

---

## 4. Optional: truststore / chain validation

If you want the client to use **certificate chain validation** (your XT CA certs):

- Include **`config/truststore.jks`** in the package (the **clientFolder** task copies it automatically if it exists).
- Your **`config/config.json`** already has a **`truststore`** section; the same config is copied into the client folder. Ensure the **path** in that section is **`config/truststore.jks`** (relative) so it works in the client’s folder.

If the client does not need chain validation, remove the **`truststore`** block from **`config/config.json`** (or from **`installer/config.json`** for the installer) before building the client package or installer.
