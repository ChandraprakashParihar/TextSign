# TrustSign Client Documentation

This folder contains the **Client Installation & Integration Guide** for TrustSign.

## Files

| File | Description |
|------|-------------|
| **TrustSign-Client-Manual.md** | Full manual in Markdown (source). |
| **TrustSign-Client-Manual.html** | Print-ready HTML version of the manual. |
| **TrustSign-Client-Manual.pdf** | PDF version (if generated). |

## How to create the PDF

**Option 1 – From the HTML (recommended, no extra tools)**  
1. Open **TrustSign-Client-Manual.html** in a browser (Chrome, Edge, or Firefox).  
2. Press **Ctrl+P** (Print).  
3. Choose **Save as PDF** or **Microsoft Print to PDF** as the destination.  
4. Save as **TrustSign-Client-Manual.pdf**.

**Option 2 – Using Pandoc (if installed)**  
```bash
pandoc TrustSign-Client-Manual.md -o TrustSign-Client-Manual.pdf
```
You need a LaTeX engine (e.g. MiKTeX) for best results with pandoc.

**Option 3 – Using Node (md-to-pdf)**  
```bash
npx md-to-pdf TrustSign-Client-Manual.md -o TrustSign-Client-Manual.pdf
```

You can give the PDF to your client together with the TrustSign ZIP package.
  "tsa": {
    "url": "http://timestamp.digicert.com",
    "hashAlgorithm": "SHA-256",
    "failOnError": false,
    "connectTimeoutMs": 10000,
    "readTimeoutMs": 15000
  }
  "ltv": {
    "enabled": true,
    "failOnMissingRevocationData": false,
    "ocspConnectTimeoutMs": 10000,
    "ocspReadTimeoutMs": 15000,
    "crlConnectTimeoutMs": 10000,
    "crlReadTimeoutMs": 15000
  }


/// Trust Chain Setup 
Use these exact commands from your repo root (/Users/jainnibha/chandra-workspace/trustsign).

Rebuild truststore with your new chain:
./scripts/create-truststore.sh \
  "/Users/jainnibha/client_crt/tayal/CCA_India_2022.cer" \
  "/Users/jainnibha/client_crt/tayal/Verasys_CA_2022.cer" \
  "/Users/jainnibha/client_crt/tayal/Verasys_Sub_CA_2022.cer"
Verify truststore contents:
keytool -list -v -keystore "config/truststore.jks" -storepass trustsign
(Optional) print each cert to verify issuer/subject chain:
keytool -printcert -file "/Users/jainnibha/client_crt/tayal/CCA_India_2022.cer"
keytool -printcert -file "/Users/jainnibha/client_crt/tayal/Verasys_CA_2022.cer"
keytool -printcert -file "/Users/jainnibha/client_crt/tayal/Verasys_Sub_CA_2022.cer"
Run the smoke test that validates chain loading/path validation:
./gradlew test --tests com.trustsign.core.CertificateChainSmokeTest
Start server:
./gradlew run
In another terminal, hit health endpoint:
curl -i "http://localhost:80/pki/health"
If curl health is 200 and the test command is BUILD SUCCESSFUL, your chain setup is good.
