package com.trustsign.core;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Handles first-time activation and encrypted local licence storage.
 *
 * On first launch: reads an activation key from {@value #ACTIVATION_KEY_FILE},
 * POSTs to the licensing server, receives a signed token, and writes
 * {@value #LICENCE_DAT_FILE} (AES-256-GCM encrypted, machine-bound).
 *
 * On subsequent launches: decryption and validation happen inside
 * {@link LicenceEnforcer} — no network call is made.
 *
 * <h3>Encrypted file format (TRUSTSIGN-LICENCE-V2)</h3>
 * <pre>
 *   Line 1: "TRUSTSIGN-LICENCE-V2"         (magic / version marker)
 *   Line 2: base64url(16-byte random salt)  (PBKDF2 salt for enc-key derivation)
 *   Line 3: base64url(12-byte-IV ‖ AES-GCM-ciphertext ‖ 16-byte-auth-tag)
 *   Line 4: hex-HMAC-SHA256(lines 1-3, hmac_key)
 * </pre>
 * Where:
 * <ul>
 *   <li>enc_key  = PBKDF2-HMAC-SHA256(password = stable_fp ‖ APP_ENC_KDF_SUFFIX,
 *                                     salt = file_salt, 65536 iters, 256 bits)</li>
 *   <li>hmac_key = SHA-256(APP_HMAC_CONSTANT ‖ stable_fp)</li>
 *   <li>stable_fp = MachineFingerprint.computeStable() — SHA-256(hostname + OS)</li>
 * </ul>
 * Consequence: copying the file to a machine with a different hostname causes
 * HMAC failure before decryption is even attempted. Even if an attacker knows
 * the constants (they're in the JAR), they would need the exact stable_fp value
 * (i.e. the same hostname and OS) to produce a valid HMAC or decrypt the file.
 */
public final class LicenceActivator {

    /** File in the config directory containing the one-time activation key. */
    public static final String ACTIVATION_KEY_FILE = "activation-key.txt";
    /** Encrypted licence token storage file written after first activation. */
    public static final String LICENCE_DAT_FILE    = ".licence.dat";

    /**
     * Default activation server URL. Override with system property
     * {@code trustsign.licence.server} (e.g. for staging/testing).
     */
    public static final String DEFAULT_SERVER_URL =
        "https://9ef4-2401-4900-88f0-b2e6-316b-7abb-aa2f-3252.ngrok-free.app/api/v1/activate";

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PBKDF2_ALG = "PBKDF2WithHmacSHA256";
    private static final int    PBKDF2_ITERATIONS = 65536;
    /** Appended to the stable fingerprint before PBKDF2 — application domain separator. */
    private static final byte[] APP_ENC_KDF_SUFFIX =
        "TrustSign-Lic-ENC-V2".getBytes(StandardCharsets.UTF_8);
    /** Mixed into HMAC key so the MAC cannot be forged by another application. */
    private static final String APP_HMAC_CONSTANT = "TrustSign-Lic-HMAC-V2-7f3a9b2c";
    private static final String FILE_MAGIC = "TRUSTSIGN-LICENCE-V2";

    private LicenceActivator() {}

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Activates the licence if {@value #LICENCE_DAT_FILE} does not yet exist.
     * Reads the activation key from {@value #ACTIVATION_KEY_FILE}, contacts the
     * licensing server, and writes the encrypted token file.
     *
     * @param configDir directory containing both activation-key.txt and where
     *                  .licence.dat will be written
     * @throws Exception if the licence file is absent, the key is blank, the
     *                   server is unreachable, or the server returns an error
     */
    public static void activateIfNeeded(Path configDir) throws Exception {
        Path licenceDat = configDir.resolve(LICENCE_DAT_FILE);
        if (Files.exists(licenceDat)) {
            return;
        }
        Files.createDirectories(configDir);
        Path activationKeyPath = configDir.resolve(ACTIVATION_KEY_FILE);
        String serverUrl = System.getProperty("trustsign.licence.server", DEFAULT_SERVER_URL);

        printActivationBanner();

        // Pre-filled key (e.g. silent/automated deployment) — try once, no prompt.
        if (Files.exists(activationKeyPath)) {
            String saved = Files.readString(activationKeyPath, StandardCharsets.UTF_8).strip();
            if (!saved.isBlank()) {
                try {
                    String token = requestActivation(saved, serverUrl);
                    writeEncryptedToken(licenceDat, token);
                    System.out.println("[TrustSign] Licence activated successfully.");
                    return;
                } catch (IOException e) {
                    System.err.println("  Saved key rejected: " + e.getMessage());
                    System.err.println("  Please enter a valid activation key below.");
                    System.err.println();
                }
            }
        }

        // Interactive loop — retry until the server accepts the key or user aborts.
        java.io.BufferedReader stdin =
            new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
        java.io.Console console = System.console();

        while (true) {
            System.out.print("Activation key: ");
            System.out.flush();
            String key = console != null ? console.readLine() : stdin.readLine();

            if (key == null) {
                throw new IOException(
                    "Input stream closed. Run from an interactive terminal to enter the activation key.");
            }
            if (key.isBlank()) {
                System.err.println("  No key entered. Please try again.");
                System.err.println();
                continue;
            }
            key = key.strip();

            try {
                String token = requestActivation(key, serverUrl);
                Files.writeString(activationKeyPath, key, StandardCharsets.UTF_8);
                writeEncryptedToken(licenceDat, token);
                System.out.println();
                System.out.println("[TrustSign] Licence activated successfully.");
                return;
            } catch (IOException e) {
                System.err.println("  Invalid key: " + e.getMessage());
                System.err.println("  Please try again.");
                System.err.println();
            }
        }
    }

    private static void printActivationBanner() {
        System.out.println();
        System.out.println("-------------------------------------------------------");
        System.out.println("  TrustSign — Licence Activation");
        System.out.println("  This machine has not been activated yet.");
        System.out.println("  Enter the activation key provided by your vendor.");
        System.out.println("  (Press Ctrl+C to exit)");
        System.out.println("-------------------------------------------------------");
        System.out.println();
    }

    // =========================================================================
    // Encrypted storage (package-private so LicenceEnforcer can call it)
    // =========================================================================

    /**
     * Encrypts {@code tokenString} with a key derived from the current machine's
     * stable fingerprint and writes it to {@code path} in TRUSTSIGN-LICENCE-V2 format.
     */
    static void writeEncryptedToken(Path path, String tokenString) throws Exception {
        SecureRandom rng = new SecureRandom();
        byte[] salt = new byte[16];
        byte[] iv   = new byte[12];
        rng.nextBytes(salt);
        rng.nextBytes(iv);

        String stableFp = MachineFingerprint.computeStable();
        SecretKey encKey = deriveEncKey(stableFp, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, encKey, new GCMParameterSpec(128, iv));
        byte[] ciphertext = cipher.doFinal(tokenString.getBytes(StandardCharsets.UTF_8));

        // prepend IV so line 3 = IV ‖ ciphertext ‖ auth-tag
        byte[] ivAndCt = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCt, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCt, iv.length, ciphertext.length);

        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String line2 = b64.encodeToString(salt);
        String line3 = b64.encodeToString(ivAndCt);
        String line4 = computeFileHmac(FILE_MAGIC + "\n" + line2 + "\n" + line3, stableFp);

        Path parent = path.getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.writeString(path,
            FILE_MAGIC + "\n" + line2 + "\n" + line3 + "\n" + line4 + "\n",
            StandardCharsets.UTF_8);
    }

    /**
     * Reads and decrypts the licence token from {@code path}.
     *
     * @throws IOException if the file is missing, malformed, HMAC fails
     *                     (tamper / wrong machine), or AES-GCM auth fails
     *                     (wrong machine encryption key)
     */
    public static String readAndDecryptToken(Path path) throws Exception {
        if (!Files.exists(path)) {
            throw new IOException("Licence file not found: " + path.toAbsolutePath());
        }
        String content = Files.readString(path, StandardCharsets.UTF_8);
        String[] lines = content.split("\n", -1);
        if (lines.length < 4 || !FILE_MAGIC.equals(lines[0].trim())) {
            throw new IOException("Licence file format invalid or corrupted");
        }
        String line1 = lines[0].trim();
        String line2 = lines[1].trim();
        String line3 = lines[2].trim();
        String line4 = lines[3].trim();

        String stableFp = MachineFingerprint.computeStable();

        // Verify HMAC before attempting decryption.
        // This fails immediately if the file was copied to another machine
        // (different stable_fp → different hmac_key) or if the file was edited.
        String expectedHmac = computeFileHmac(line1 + "\n" + line2 + "\n" + line3, stableFp);
        if (!MessageDigest.isEqual(
                expectedHmac.getBytes(StandardCharsets.UTF_8),
                line4.getBytes(StandardCharsets.UTF_8))) {
            throw new IOException(
                "Licence HMAC verification failed — the file may have been tampered with "
                + "or copied from a different machine");
        }

        Base64.Decoder b64 = Base64.getUrlDecoder();
        byte[] salt  = b64.decode(line2);
        byte[] ivAndCt = b64.decode(line3);

        if (ivAndCt.length < 12 + 16) {
            throw new IOException("Licence encrypted payload is too short");
        }
        byte[] iv = Arrays.copyOf(ivAndCt, 12);
        byte[] ct = Arrays.copyOfRange(ivAndCt, 12, ivAndCt.length);

        SecretKey encKey = deriveEncKey(stableFp, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, encKey, new GCMParameterSpec(128, iv));

        try {
            byte[] plaintext = cipher.doFinal(ct);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (javax.crypto.AEADBadTagException e) {
            throw new IOException(
                "Licence decryption failed — machine hardware fingerprint mismatch "
                + "(hostname or OS changed, or licence file was copied from another machine)");
        }
    }

    // =========================================================================
    // Renewal
    // =========================================================================

    /**
     * Contacts the licensing server to renew an expired token.
     * Uses the {@code activationId} from the expired token — no activation key needed.
     * On success, overwrites {@code licenceDat} with the new encrypted token.
     *
     * @return true if renewal succeeded and the file was updated; false if the
     *         server denied the renewal or is unreachable (caller should show
     *         the "licence expired" message in that case)
     */
    public static boolean renewIfExpired(Path licenceDat, LicenceToken expiredToken) {
        try {
            String baseUrl = System.getProperty("trustsign.licence.server", DEFAULT_SERVER_URL);
            String renewUrl = baseUrl.replace("/activate", "/renew");
            String newToken = requestRenewal(expiredToken.activationId(), renewUrl);
            writeEncryptedToken(licenceDat, newToken);
            System.out.println("[TrustSign] Licence renewed successfully.");
            return true;
        } catch (Exception e) { // requestRenewal / writeEncryptedToken declare throws Exception
            System.err.println("[TrustSign] Licence renewal failed: " + e.getMessage());
            return false;
        }
    }

    private static String requestRenewal(String activationId, String renewUrl) throws Exception {
        String fp3 = MachineFingerprint.computeStrict();
        String fp2 = MachineFingerprint.computeMedium();
        String hostname = resolveHostnameForRequest();
        long ts = System.currentTimeMillis() / 1000L;

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("activationId", activationId);
        body.put("fp3", fp3);
        body.put("fp2", fp2);
        body.put("hostname", hostname);
        body.put("requestedAt", ts);

        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(renewUrl))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
            .timeout(Duration.ofSeconds(30))
            .build();

        HttpResponse<String> response =
            client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            String detail = "";
            try {
                JsonNode err = JSON.readTree(response.body());
                if (err != null && err.has("message")) {
                    detail = ": " + err.get("message").asText();
                }
            } catch (com.fasterxml.jackson.core.JacksonException ignored) {}
            throw new IOException(
                "Renewal failed (HTTP " + response.statusCode() + ")" + detail);
        }

        JsonNode resp = JSON.readTree(response.body());
        if (resp == null || !resp.has("token")) {
            throw new IOException(
                "Renewal server returned an invalid response (missing 'token' field)");
        }
        return resp.get("token").asText().strip();
    }

    // =========================================================================
    // Server communication
    // =========================================================================

    private static String requestActivation(String activationKey, String serverUrl)
        throws Exception {
        String fp3 = MachineFingerprint.computeStrict();
        String fp2 = MachineFingerprint.computeMedium();
        String hostname = resolveHostnameForRequest();
        long ts = System.currentTimeMillis() / 1000L;

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("activationKey", activationKey);
        body.put("fp3", fp3);
        body.put("fp2", fp2);
        body.put("hostname", hostname);
        body.put("requestedAt", ts);

        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
            .timeout(Duration.ofSeconds(30))
            .build();

        HttpResponse<String> response =
            client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            String detail = "";
            try {
                JsonNode err = JSON.readTree(response.body());
                if (err != null && err.has("message")) {
                    detail = ": " + err.get("message").asText();
                }
            } catch (com.fasterxml.jackson.core.JacksonException ignored) {}
            throw new IOException(
                "Activation failed (HTTP " + response.statusCode() + ")" + detail);
        }

        JsonNode resp = JSON.readTree(response.body());
        if (resp == null || !resp.has("token")) {
            throw new IOException(
                "Activation server returned an invalid response (missing 'token' field)");
        }
        return resp.get("token").asText().strip();
    }

    // =========================================================================
    // Cryptographic helpers
    // =========================================================================

    private static SecretKey deriveEncKey(String stableFp, byte[] salt) throws Exception {
        byte[] fpBytes = stableFp.getBytes(StandardCharsets.UTF_8);
        // password = stable_fp_bytes ‖ APP_ENC_KDF_SUFFIX  (domain separation)
        byte[] password = new byte[fpBytes.length + APP_ENC_KDF_SUFFIX.length];
        System.arraycopy(fpBytes, 0, password, 0, fpBytes.length);
        System.arraycopy(APP_ENC_KDF_SUFFIX, 0, password, fpBytes.length, APP_ENC_KDF_SUFFIX.length);
        // PBEKeySpec takes char[]; hex-encode so every byte is representable
        char[] pwChars = HexFormat.of().formatHex(password).toCharArray();
        PBEKeySpec spec = new PBEKeySpec(pwChars, salt, PBKDF2_ITERATIONS, 256);
        try {
            byte[] keyBytes = SecretKeyFactory.getInstance(PBKDF2_ALG)
                .generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    private static String computeFileHmac(String data, String stableFp) throws Exception {
        // hmac_key = SHA-256(APP_HMAC_CONSTANT ‖ stable_fp)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hmacKeyBytes = md.digest(
            (APP_HMAC_CONSTANT + stableFp).getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(hmacKeyBytes, "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static String resolveHostnameForRequest() {
        try {
            return java.net.InetAddress.getLocalHost().getHostName();
        } catch (java.net.UnknownHostException e) {
            return "unknown";
        }
    }
}
