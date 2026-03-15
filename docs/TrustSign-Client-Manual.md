# TrustSign — Client Installation & Integration Guide

**Version 0.1.0**

This manual describes how to install and run the TrustSign signing service from the provided ZIP package, and how to integrate the **`/auto-sign-text`** endpoint into your backend server so your applications can request text signing from TrustSign.

---

## Table of Contents

1. [Overview](#1-overview)
2. [System Requirements](#2-system-requirements)
3. [Installation from ZIP](#3-installation-from-zip)
4. [Configuration](#4-configuration)
5. [Running the TrustSign Service](#5-running-the-trustsign-service)
6. [Integrating `/auto-sign-text` in Your Backend](#6-integrating-auto-sign-text-in-your-backend)
7. [API Reference: POST /v1/auto-sign-text](#7-api-reference-post-v1auto-sign-text)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Overview

TrustSign is a local signing service that uses a PKCS#11 hardware token (or software token) to sign text documents. You receive TrustSign as a **ZIP package** containing the application, a bundled JRE (Windows), configuration, and run scripts.

**Typical setup:**

- You run the **TrustSign service** on a machine where the signing token is attached (e.g. a Windows PC or server).
- Your **backend server** (your own application) runs on the same machine or another machine on the network.
- Your backend **calls the TrustSign API** (e.g. `POST /v1/auto-sign-text`) to request signing. TrustSign signs the content and returns the result; the signed file is written to a directory you specify.

This guide covers **installation from the ZIP file** and **integration of the `/auto-sign-text` endpoint** into your backend.

---

## 2. System Requirements

| Item | Requirement |
|------|-------------|
| **OS** | Windows (recommended; package includes bundled JRE), or Mac/Linux with Java 17+ installed |
| **Java** | Not required on Windows (JRE is bundled). On Mac/Linux: Java 17 or later |
| **Hardware** | PKCS#11-compatible USB token (e.g. ePass2003, HyperPKI) or supported software token |
| **Network** | If your backend runs on another machine, ensure firewall allows access to the TrustSign port (default: 31927) |

---

## 3. Installation from ZIP

### 3.1 Extract the ZIP

1. Obtain the client package (e.g. **TrustSign-0.1.0-client.zip** or similar name provided by your vendor).
2. Extract the ZIP to a folder of your choice, for example:
   - `C:\TrustSign` (Windows)
   - `/opt/TrustSign` (Linux)
3. Do **not** remove or rename the `jre` folder on Windows (it contains the bundled Java runtime).

After extraction, the folder should look like this:

```
TrustSign/
  trustsign-0.1.0-all.jar
  run-trustsign.bat          (Windows launcher)
  jre/                       (Windows only – bundled Java)
  config/
    config.json
    licence.json
    public-key.pem
    (optional: truststore.jks)
  README.txt
```

### 3.2 Verify Contents

| File/Folder | Purpose |
|-------------|---------|
| **trustsign-0.1.0-all.jar** | TrustSign application (do not delete) |
| **run-trustsign.bat** | Double-click to start the service on Windows |
| **jre/** | Bundled Java (Windows); required if you do not install Java |
| **config/config.json** | Port, PKCS#11 library paths, and other settings |
| **config/licence.json** | Licence file (do not delete or modify) |
| **config/public-key.pem** | Public key used to select the signing certificate on the token (required for signing) |

---

## 4. Configuration

### 4.1 Set the Token PIN

The service needs the PIN of your PKCS#11 token to access the private key. Use **one** of the following:

**Option A – Config file**

1. Open `config\config.json` in a text editor.
2. Find the `pkcs11` section and set `pin` to your token PIN, for example:

   ```json
   "pkcs11": {
     "pin": "your-token-pin",
     ...
   }
   ```

**Option B – Environment variable**

Set the environment variable **`TRUSTSIGN_TOKEN_PIN`** to your token PIN (e.g. in a batch file or system environment). This avoids storing the PIN in the config file.

### 4.2 Optional: Change Port or Other Settings

Edit `config/config.json` if you need to:

- Change the **port** (default is `31927`). Your backend will use this port when calling TrustSign.
- Add or change **allowedOrigins** if your backend is served from a specific origin and you use browser-based calls (CORS).

Example snippet:

```json
{
  "port": 31927,
  "allowedOrigins": ["http://localhost:3000", "https://your-backend.example.com"],
  ...
}
```

### 4.3 Optional: Restrict Output Directory

If you want to limit where signed files can be written, the vendor can set **`outputBaseDir`** in the configuration. In that case, the `outputDir` you send to `/auto-sign-text` must be under that base path.

---

## 5. Running the TrustSign Service

### 5.1 Start the Service

**Windows (recommended):**

1. Connect your PKCS#11 token (e.g. USB).
2. Double-click **`run-trustsign.bat`** in the TrustSign folder.
3. A console window will open. When the service is ready, you will see a message like:

   ```
   TrustSign text server listening on http://127.0.0.1:31927/v1
   ```

4. Leave this window open while you use the service. To stop, close the window or press **Ctrl+C**.

**Command line (all platforms):**

```bat
cd C:\TrustSign
java -jar trustsign-0.1.0-all.jar
```

On Mac/Linux, use the same `java -jar` command from the installation directory.

### 5.2 Using a Custom Config File

To use a config file from another location:

```bat
java -jar trustsign-0.1.0-all.jar --config=C:\path\to\config.json
```

### 5.3 Check That the Service Is Running

Open a browser or use `curl`:

```bash
curl http://127.0.0.1:31927/v1/health
```

Expected response (JSON): `{"status":"ok","ts":"..."}`

---

## 6. Integrating `/auto-sign-text` in Your Backend

You provide a backend server (your own application). That backend runs alongside (or on another machine than) TrustSign. Your backend should call TrustSign when it needs to sign text.

### 6.1 Architecture

```
[Your Backend Server]  ----HTTP POST---->  [TrustSign Service]
       (your code)       /v1/auto-sign-text    (this package)
                                |
                                v
                        [PKCS#11 token]
                        (signs the text)
```

- **TrustSign** runs as a separate process and listens on a port (default **31927**).
- **Your backend** sends a **POST** request to **`http://<host>:<port>/v1/auto-sign-text`** with:
  - A **multipart/form-data** body.
  - Part **`file`**: the text file (or text content) to sign.
  - Part **`outputDir`**: the directory path on the **TrustSign machine** where the signed file should be written.

The response is JSON: success with `outputPath` and certificate info, or an error message.

### 6.2 Base URL

- **Default (same machine):** `http://127.0.0.1:31927/v1`
- **If TrustSign runs on another machine:** `http://<TrustSign-host>:31927/v1` (replace `<TrustSign-host>` with the actual hostname or IP; ensure firewall allows it).

Full endpoint: **`POST http://<host>:31927/v1/auto-sign-text`**

### 6.3 Important Points for Your Backend

1. **Output directory (`outputDir`)** is a path on the **machine where TrustSign is running**, not on your backend server. Ensure that path exists and is writable by the user running TrustSign. If `outputBaseDir` is set in TrustSign config, `outputDir` must be under that base.
2. **Request format:** `multipart/form-data` with:
   - `file`: the text file (or a file-like part with the text content).
   - `outputDir`: string, directory path for the signed file.
3. **Response:** JSON. On success you get `ok: true`, `outputPath`, and certificate details. On error you get `error` and optionally `details`.
4. **Security:** Run TrustSign in a trusted network. If your backend is on another host, restrict access (firewall, VPN, or binding to a specific interface) as needed.

---

## 7. API Reference: POST /v1/auto-sign-text

### 7.1 Endpoint

| Method | URL |
|--------|-----|
| **POST** | `http://<host>:<port>/v1/auto-sign-text` |

Example: `http://127.0.0.1:31927/v1/auto-sign-text`

### 7.2 Request

**Content-Type:** `multipart/form-data`

| Part name   | Type   | Required | Description |
|------------|--------|----------|-------------|
| **file**   | file   | Yes      | The text file to sign (UTF-8). Max size is 2 MB. |
| **outputDir** | string | Yes   | Directory path (on the TrustSign server) where the signed file will be written. Must not contain `..`. If the server has `outputBaseDir` set, this must be under that path. |

The signed file is written with the same name as the uploaded file, with **`-signed`** before the extension (e.g. `document.txt` → `document-signed.txt`).

### 7.3 Success Response (HTTP 200)

**Content-Type:** `application/json`

```json
{
  "ok": true,
  "subjectDn": "CN=..., O=..., ...",
  "serialNumber": "1a2b3c4d",
  "outputPath": "C:\\TrustSign\\output\\document-signed.txt"
}
```

| Field          | Description |
|----------------|-------------|
| **ok**         | `true` on success |
| **subjectDn**  | Subject DN of the signing certificate |
| **serialNumber** | Serial number of the certificate (hex) |
| **outputPath** | Full path of the signed file on the TrustSign machine |

### 7.4 Error Responses

| HTTP | Body (example) | Meaning |
|------|----------------|---------|
| 400 | `{"error": "Missing text file field: file"}` | No `file` part in the request |
| 400 | `{"error": "Missing field: outputDir"}` | No `outputDir` part |
| 400 | `{"error": "Invalid outputDir", "details": "..."}` | `outputDir` invalid or not allowed (e.g. path traversal or outside `outputBaseDir`) |
| 400 | `{"error": "No PKCS#11 libraries configured for this OS"}` | No token library configured for this platform |
| 400 | `{"error": "Token load failed", "details": "..."}` | Token not found, wrong PIN, or driver issue |
| 400 | `{"error": "No certificate on token matches provided public key"}` | Token does not have a certificate matching `config/public-key.pem` |
| 403 | `{"error": "Licence", "message": "..."}` | Licence check failed |
| 500 | `{"error": "...", "details": "..."}` | Server or config error (e.g. config file not found, invalid config) |

### 7.5 Example: cURL

```bash
curl -X POST "http://127.0.0.1:31927/v1/auto-sign-text" \
  -F "file=@/path/to/document.txt" \
  -F "outputDir=C:\TrustSign\output"
```

### 7.6 Example: Python (requests)

```python
import requests

url = "http://127.0.0.1:31927/v1/auto-sign-text"
# outputDir is a path on the machine where TrustSign runs
output_dir = "C:\\TrustSign\\output"

with open("document.txt", "rb") as f:
    files = {"file": ("document.txt", f, "text/plain")}
    data = {"outputDir": output_dir}
    r = requests.post(url, files=files, data=data)

print(r.status_code)
print(r.json())
if r.ok:
    print("Signed file written to:", r.json().get("outputPath"))
```

### 7.7 Example: Node.js (form-data and axios/fetch)

```javascript
const FormData = require('form-data');
const fs = require('fs');
const axios = require('axios');

const url = 'http://127.0.0.1:31927/v1/auto-sign-text';
const form = new FormData();
form.append('file', fs.createReadStream('document.txt'), { filename: 'document.txt' });
form.append('outputDir', 'C:\\TrustSign\\output');

const response = await axios.post(url, form, {
  headers: form.getHeaders(),
  maxBodyLength: Infinity,
});
console.log(response.data);
// response.data.outputPath is the path of the signed file on the TrustSign machine
```

### 7.8 Signed Output Format

The signed file contains:

1. The original text (with normalized line endings).
2. A signature block:

   ```
   <START-SIGNATURE><base64-signature></START-SIGNATURE>
   <START-CERTIFICATE><base64-cert></START-CERTIFICATE>
   <SIGNER-VERSION>TrustSign_0.1.0</SIGNER-VERSION>
   ```

Your backend or downstream systems can verify the signature using the certificate and the content before `<START-SIGNATURE>`.

---

## 8. Troubleshooting

| Issue | What to check |
|-------|----------------|
| **"Missing text file field: file"** | Send the file as a multipart part named exactly `file`. |
| **"Missing field: outputDir"** | Send a form field named exactly `outputDir` with a non-empty path. |
| **"Invalid outputDir"** | Ensure `outputDir` does not contain `..` and, if the server has `outputBaseDir`, that it is under that base. Create the directory on the TrustSign machine if needed. |
| **"No PKCS#11 libraries configured"** | Config has no library path for your OS. Contact your vendor or add the correct path in `config.json` under `pkcs11`. |
| **"Token load failed"** | Check token is connected, PIN is correct (in config or `TRUSTSIGN_TOKEN_PIN`), and the correct PKCS#11 driver is installed. |
| **"No certificate on token matches provided public key"** | The token’s certificate does not match `config/public-key.pem`. Ensure the correct public key is in the package. |
| **"Licence" (403)** | Licence invalid or expired. Contact your vendor. |
| Connection refused | TrustSign is not running, or firewall is blocking the port. Start the service and ensure the port (e.g. 31927) is reachable from your backend. |

---

## Summary

1. **Install:** Extract the TrustSign ZIP, set the token PIN in config or environment, and (on Windows) run **run-trustsign.bat**.
2. **Run:** Keep the TrustSign process running; it listens on `http://127.0.0.1:31927/v1` by default.
3. **Integrate:** From your backend, send **POST** requests to **`http://<host>:31927/v1/auto-sign-text`** with **multipart/form-data** (`file` + `outputDir`), and handle the JSON response to get `outputPath` and certificate info.

For further support, contact your TrustSign vendor.
