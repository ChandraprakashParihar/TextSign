# Licence (vendor only)

You control how long each client can use TrustSign and which machine it runs on. The licence is cryptographically bound to the client's machine — it cannot be copied to another machine or modified without detection.

## How it works

- **Activation key** (`activation-key.txt`): A one-time key you give the client. On first launch the client contacts your activation server, which validates the key, signs a machine-bound token, and marks the key as used.
- **Machine binding**: The signed token embeds the client machine's hardware fingerprint (MAC addresses, hostname, OS, CPU count). The encrypted licence file can only be decrypted on the same machine.
- **Local encrypted storage** (`.licence.dat`): After activation the signed token is stored on the client machine in an AES-256-GCM encrypted file. All subsequent runs validate locally — no network call is needed.
- **Tamper protection**: The file is HMAC-protected and AES-GCM authenticated. Editing the file or copying it to another machine causes immediate rejection before decryption is attempted.

## One-time setup: generate your key pair

Run once from the project root (after building the JAR):

```bash
java -cp build/libs/trustsign-0.1.0-all.jar com.trustsign.tools.LicenceGenerator genkey .
```

This creates:

- `licence-private-key.pem` — **Keep this secret on the activation server only.** Never ship it to clients or commit it to version control.
- `licence-public-key.pem` — Put this in `src/main/resources/com/trustsign/licence-public-key.pem` (replace the existing file), then **rebuild** the application. The built JAR only accepts tokens signed with the matching private key.

## Running the activation server

The activation server (`com.trustsign.tools.licenceserver.ActivationServerApp`) is a Spring Boot app you deploy on your own infrastructure.

1. Place `licence-private-key.pem` next to the server JAR (or configure `trustsign.licence.private-key`).
2. Create a `keys.json` file listing your activation keys (see below).
3. Start the server: `java -jar activation-server.jar`

### keys.json format

```json
[
  {
    "key":          "ABCDE-FGHIJ-KLMNO-PQRST",
    "customerId":   "acme-corp",
    "durationDays": 365,
    "used":         false,
    "activationId": null,
    "activatedAt":  0
  }
]
```

Each key can only be used once. After activation, `used` becomes `true` and `activationId` / `activatedAt` are recorded.

## Creating a licence for a client

1. Add a new entry to `keys.json` on your activation server with a unique key, the customer's ID, and the desired duration in days.
2. Give the client **only** the `activation-key.txt` file containing the key string.
3. On their first launch, the app contacts your server automatically, receives the signed token, and saves it locally.

## Inspecting a machine's fingerprints

To see what fingerprints a machine would send during activation:

```bash
java -cp build/libs/trustsign-0.1.0-all.jar com.trustsign.tools.LicenceGenerator print-fp
```
