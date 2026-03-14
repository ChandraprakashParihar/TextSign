# Licence (vendor only)

You control how long each client can use TrustSign. The period starts when the client **first uses** the service and cannot be extended by changing the system date or editing files.

## How it works

- **Licence file** (`licence.json`): Contains a **duration in days** and a **signature**. Only you can create or change it (you sign it with your private key). The client cannot change the duration.
- **First use**: The first time the client runs the service, that date is stored in a protected state file. The client cannot backdate it (it is checked against the build date) or edit it without breaking the signature.
- **Clock rollback**: If the client sets the system date back to get more time, the service rejects requests until the date is restored.

## One-time setup: generate your key pair

Run (from the project root, after building the JAR):

```bash
java -cp build/libs/trustsign-0.1.0-all.jar com.trustsign.tools.LicenceGenerator genkey .
```

This creates:

- `licence-private-key.pem` — **Keep this secret.** Use it only to sign licence files. Do not give it to clients or commit it to version control.
- `licence-public-key.pem` — Put this in `src/main/resources/com/trustsign/licence-public-key.pem` (replace the existing file), then **rebuild** the application. The built app will only accept licences signed with the matching private key.

## Creating a licence for a client

1. Decide the **duration in days** (e.g. 90 for 3 months, 365 for 1 year). The period starts when the client first uses the service.
2. Sign a licence file:

   ```bash
   java -cp build/libs/trustsign-0.1.0-all.jar com.trustsign.tools.LicenceGenerator sign <durationDays> licence-private-key.pem config/licence.json
   ```

   Example for 90 days:

   ```bash
   java -cp build/libs/trustsign-0.1.0-all.jar com.trustsign.tools.LicenceGenerator sign 90 licence-private-key.pem config/licence.json
   ```

3. **For the Windows installer**: Copy the signed `config/licence.json` to `installer/licence.json` before running `./gradlew buildInstaller`. The installer will put it in the client’s config folder.
4. **For a manual client package**: Include the signed `licence.json` in the client’s config directory (e.g. next to `config.json`).

Only you can change the duration, because only you have the private key. The client cannot modify the licence or the internal state to extend use.
