# TrustSign Production Hardening

This document captures the minimum production settings and operational checks for running TrustSign safely at scale.

## 1) Mandatory Security Settings

- Do not store real token PINs in `config/config.json`.
- Set token PIN via environment variable:
  - `TRUSTSIGN_TOKEN_PIN=<your-pin>`
- Keep debug endpoints disabled in production:
  - `server.enableDebugEndpoints=false`
- Keep error details hidden in production:
  - do **not** set `-Dtrustsign.exposeErrorDetails=true`
- Restrict client IPs in config:
  - `allowedClientIps: ["<trusted-ip-1>", "<trusted-ip-2>"]`

## 2) Required Runtime Properties

- Session cap (prevents memory abuse):
  - `-Dtrustsign.maxSessions=10000`
- Session issue rate limit (per IP, per minute):
  - `-Dtrustsign.sessionRateLimitPerMinute=30`

Recommended startup example:

```bash
TRUSTSIGN_TOKEN_PIN=your-pin \
java \
  -Dtrustsign.maxSessions=10000 \
  -Dtrustsign.sessionRateLimitPerMinute=30 \
  -jar trustsign-0.1.0-all.jar --config=config/config.json
```

## 3) Server Config Recommendations

In `config/config.json` under `server`:

- `maxThreads`: tune by CPU and HSM throughput (`200-500` typical per instance)
- `minSpareThreads`: `16-64`
- `acceptQueueSize`: `4096+` for bursty traffic
- `maxConcurrentSigningOperations`: set to measured HSM safe concurrency (do not set unlimited)
- `signingAcquireTimeoutMs`: keep bounded (e.g. `60000-300000`)
- `sessionIssueRateLimitPerMinute`: start with `30`, tune using logs/metrics
- `multipartPdfMaxFileMb`: keep strict (smallest acceptable for your use-case)
- `maxTcpConnections`: set a real cap in production (avoid `0` unlimited)

## 4) CORS and Network Controls

- `allowedOrigins` is enforced for `/v1/**`; keep it strict (no wildcard in production).
- Put service behind a reverse proxy/load balancer with:
  - TLS termination
  - request size limits
  - connection and request timeout limits
  - optional WAF/rate-limit policies

## 5) Build/Installer Supply Chain

Windows JRE checksum pin is mandatory for installer/client bundle flows:

- `TRUSTSIGN_WINDOWS_JRE_SHA256=<expected-sha256>`
  or
- `-PwindowsJreSha256=<expected-sha256>`

CI should run:

```bash
./gradlew verifyInstallerInputs
```

## 6) Operational Readiness Checklist

Before go-live:

- [ ] `./gradlew test` passes in CI
- [ ] Debug endpoints return `404` in prod config
- [ ] Error responses include `code` and do not expose `details`
- [ ] Session issuance is rate-limited and monitored
- [ ] HSM throughput test done with realistic concurrency and document sizes
- [ ] TSA/OCSP/CRL timeout and fail behavior validated under outage simulation
- [ ] Log path writable and rotated by host/logging platform
- [ ] Alerts configured for 4xx/5xx spikes, signing latency, queue/backlog

## 7) Scale Guidance (10 lakh+ bursts)

Do not attempt extreme concurrency on a single JVM/HSM instance.
Use:

- horizontal scaling (multiple app instances),
- external queue for async sign jobs,
- worker pools pinned to HSM capacity,
- backpressure at ingress.

This service is now hardened for synchronous API operation, but lakh-scale burst handling should use queue-based architecture.
