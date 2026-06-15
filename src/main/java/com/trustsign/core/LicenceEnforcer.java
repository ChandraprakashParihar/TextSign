package com.trustsign.core;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * Validates a server-issued, machine-bound licence token on every application start.
 *
 * <h3>Validation steps</h3>
 * <ol>
 *   <li>Anti-debug check — refuse if a JDWP debugger is attached.</li>
 *   <li>Load and decrypt the encrypted token file via {@link LicenceActivator}.</li>
 *   <li>Verify the RSA-SHA256 server signature over the token payload.</li>
 *   <li>Machine fingerprint check — current fp3 or fp2 must match the token.</li>
 *   <li>Build-time check — token issue date must not predate the release.</li>
 *   <li>Expiry check — current wall clock must be before {@code exp}.</li>
 * </ol>
 *
 * No network call is made; validation is entirely offline after first activation.
 */
public final class LicenceEnforcer {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long CLOCK_SKEW_TOLERANCE_MS = 24L * 60 * 60 * 1000; // 1 day

    /**
     * Evaluated once at class-load time so it cannot be bypassed by a
     * reflective assignment after the check.
     */
    private static final boolean DEBUGGER_PRESENT = detectJdwpAgent();

    private final Path licenceDat;
    private final long buildTimestampMs;
    private final PublicKey publicKey;

    public LicenceEnforcer(Path licenceDat, long buildTimestampMs, PublicKey publicKey) {
        this.licenceDat       = licenceDat;
        this.buildTimestampMs = buildTimestampMs;
        this.publicKey        = publicKey;
    }

    // =========================================================================
    // Public result type
    // =========================================================================

    public record Result(boolean allowed, String message) {
        public static Result allow()              { return new Result(true, null); }
        public static Result deny(String message) { return new Result(false, message); }
    }

    // =========================================================================
    // Main check
    // =========================================================================

    public Result check() {
        // Anti-debug: any JDWP agent is treated as a tamper attempt.
        if (DEBUGGER_PRESENT) {
            return Result.deny("Licence check failed");
        }
        try {
            // 1. Decrypt (AES-256-GCM, machine-fingerprint-derived key).
            //    Throws if file missing, HMAC fails, or AES auth-tag fails.
            String tokenString = LicenceActivator.readAndDecryptToken(licenceDat);

            // 2. Parse and verify the server RSA signature.
            LicenceToken token = parseAndVerifySignature(tokenString);
            if (token == null) {
                return Result.deny("Licence signature is invalid");
            }

            // 3. Machine binding: fp3 (strict) or fp2 (medium) must match.
            if (!machineMatches(token)) {
                return Result.deny(
                    "This licence is not valid for this machine. "
                    + "Re-activate or contact your vendor.");
            }

            long nowMs = System.currentTimeMillis();

            // 4. Build-timestamp guard: prevents backdating the activation to
            //    before this build was released.
            if (buildTimestampMs > 0
                    && token.issuedAtMs() < buildTimestampMs - CLOCK_SKEW_TOLERANCE_MS) {
                return Result.deny(
                    "Licence issue date precedes this build's release date");
            }

            // 5. Expiry — attempt automatic server renewal before giving up.
            if (nowMs > token.expiresAtMs()) {
                if (LicenceActivator.renewIfExpired(licenceDat, token)) {
                    String renewed = LicenceActivator.readAndDecryptToken(licenceDat);
                    LicenceToken newToken = parseAndVerifySignature(renewed);
                    if (newToken != null && System.currentTimeMillis() <= newToken.expiresAtMs()) {
                        return Result.allow();
                    }
                }
                return Result.deny(
                    "Licence has expired and could not be renewed. "
                    + "Contact your vendor.");
            }

            return Result.allow();

        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && (msg.contains("tampered")
                    || msg.contains("fingerprint mismatch")
                    || msg.contains("copied from"))) {
                return Result.deny("Licence invalid: " + msg);
            }
            return Result.deny("Licence check failed: "
                + (msg != null ? msg : "unknown error"));
        }
    }

    // =========================================================================
    // Signature verification
    // =========================================================================

    private LicenceToken parseAndVerifySignature(String tokenString) throws Exception {
        // Wire format:  {base64url(json)}.{base64url(sig)}
        int dot = tokenString.lastIndexOf('.');
        if (dot < 1 || dot >= tokenString.length() - 1) {
            throw new IllegalArgumentException("Malformed token: missing '.' separator");
        }
        String payloadB64 = tokenString.substring(0, dot);
        String sigB64     = tokenString.substring(dot + 1);

        byte[] payloadBytes = Base64.getUrlDecoder().decode(payloadB64);
        byte[] sigBytes     = Base64.getUrlDecoder().decode(sigB64);

        // The server signs the raw UTF-8 bytes of the base64url-encoded payload block.
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(payloadB64.getBytes(StandardCharsets.UTF_8));
        if (!verifier.verify(sigBytes)) {
            return null;
        }
        return JSON.readValue(payloadBytes, LicenceToken.class);
    }

    // =========================================================================
    // Machine fingerprint matching
    // =========================================================================

    private static boolean machineMatches(LicenceToken token) {
        try {
            // Try strict match first (all signals including MAC).
            String fp3 = MachineFingerprint.computeStrict();
            if (constantTimeEquals(fp3, token.fingerprintStrict())) return true;
            // Fall back to medium match (hostname + OS + CPU — survives NIC swap).
            String fp2 = MachineFingerprint.computeMedium();
            return constantTimeEquals(fp2, token.fingerprintMedium());
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(
            a.getBytes(StandardCharsets.UTF_8),
            b.getBytes(StandardCharsets.UTF_8));
    }

    // =========================================================================
    // Anti-debug
    // =========================================================================

    /**
     * Returns true if a JDWP debug agent is attached to this JVM.
     * Called once at class-load time; the result is stored in a static final
     * field so it cannot be patched away after the check without rewriting
     * the class.
     */
    private static boolean detectJdwpAgent() {
        try {
            List<String> args =
                java.lang.management.ManagementFactory.getRuntimeMXBean()
                    .getInputArguments();
            for (String arg : args) {
                if (arg.toLowerCase(Locale.ROOT).contains("jdwp")) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    // =========================================================================
    // Public key loading
    // =========================================================================

    /**
     * Loads a PEM-encoded RSA public key (PKCS#8 SubjectPublicKeyInfo format)
     * from an InputStream. The key must be wrapped in
     * {@code -----BEGIN PUBLIC KEY-----} / {@code -----END PUBLIC KEY-----} headers.
     */
    public static PublicKey loadPublicKeyFromPem(InputStream in) throws Exception {
        String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        pem = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(pem);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }
}
