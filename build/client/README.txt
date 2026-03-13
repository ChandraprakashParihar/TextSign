# How to run TrustSign (for clients)

You can give the client **one JAR file** and a small run script. The client needs **Java 17 or later** installed.

---

## Build the client folder (recommended)

**Before building**, put the signer’s **public key** in **`config/public-key.pem`** (PEM format: either `-----BEGIN PUBLIC KEY-----` or a certificate `-----BEGIN CERTIFICATE-----`). Signing uses only the certificate on the token that matches this public key.

From the project root run:

```bash
./gradlew clientFolder
```

This creates **`build/client/`** with everything the client needs:

```
build/client/
  trustsign-0.1.0-all.jar
  run-trustsign.bat
  config/
    config.json
    public-key.pem    ← the public key you provided
  README.txt
```

**Give the client the whole `build/client` folder** (e.g. zip it and send as `TrustSign-0.1.0-client.zip`).

---

## What’s inside the client folder

1. **trustsign-0.1.0-all.jar** – fat JAR (app + dependencies).
2. **run-trustsign.bat** – double‑click to start the service.
3. **config/config.json** – default config (port, PKCS#11 paths). Client can edit if needed.
4. **config/public-key.pem** – signer’s public key (used to select which certificate on the token is used for signing). **Required for signing.**
5. **README.txt** – copy of these instructions for the client.

**Token PIN:** The client must set the token PIN so the service can use the key. Either:
- Edit **config/config.json** and set **`pkcs11.pin`** to the token PIN (e.g. `"pin": "12345678"`), or  
- Set the environment variable **`TRUSTSIGN_TOKEN_PIN`** to the token PIN (no need to store in the file).

---

## How the client runs the service

1. Install **Java 17 or later** if needed (e.g. [Eclipse Temurin 17](https://adoptium.net/temurin/releases/?os=windows&arch=x64&package=jre&version=17)).
2. Put the JAR, `run-trustsign.bat`, and `config` folder in one folder (e.g. `TrustSign`).
3. **Double‑click `run-trustsign.bat`**  
   - Or open Command Prompt in that folder and run:  
     `java -jar trustsign-0.1.0-all.jar`
4. When it’s running, the service will show something like:  
   `TrustSign text server listening on http://127.0.0.1:31927/v1`
5. To stop: close the window or press Ctrl+C in the command window.

---

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
