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
