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
