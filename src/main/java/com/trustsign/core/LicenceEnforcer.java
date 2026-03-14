package com.trustsign.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Enforces a time-limited licence: duration is set by the vendor (signed licence file),
 * and "first use" starts when the client first runs the service. Protects against
 * client changing system date (clock rollback) and tampering with state.
 */
public final class LicenceEnforcer {

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String STATE_HMAC_ALG = "HmacSHA256";
  /** Key derived from constant so state file cannot be edited without breaking HMAC. */
  private static final byte[] STATE_HMAC_KEY = deriveStateKey();
  /** Allow 1 day tolerance for clock skew before treating as rollback. */
  private static final long CLOCK_ROLLBACK_TOLERANCE_MS = 24 * 60 * 60 * 1000L;
  /** One day in ms for expiry check. */
  private static final long ONE_DAY_MS = 24 * 60 * 60 * 1000L;

  private final Path licencePath;
  private final Path statePath;
  private final long buildTimestampMs;
  private final PublicKey licencePublicKey;

  private int durationDays = -1;

  public LicenceEnforcer(Path licencePath, Path statePath, long buildTimestampMs, PublicKey licencePublicKey) {
    this.licencePath = licencePath;
    this.statePath = statePath;
    this.buildTimestampMs = buildTimestampMs;
    this.licencePublicKey = licencePublicKey;
  }

  /**
   * Result of a licence check.
   */
  public record Result(boolean allowed, String message) {
    public static Result allow() {
      return new Result(true, null);
    }
    public static Result deny(String message) {
      return new Result(false, message);
    }
  }

  /**
   * Performs licence check: loads signed licence (duration), loads or creates state (first use / last seen),
   * rejects if expired, tampered, or clock rolled back. Updates last-seen time on success.
   */
  public Result check() {
    try {
      if (durationDays < 0) {
        int d = loadAndVerifyLicence();
        if (d < 0) return Result.deny("Invalid or missing licence file");
        this.durationDays = d;
      }
      long now = System.currentTimeMillis();
      return loadOrCreateStateAndCheck(now);
    } catch (Exception e) {
      return Result.deny("Licence check failed: " + (e.getMessage() != null ? e.getMessage() : "unknown error"));
    }
  }

  private int loadAndVerifyLicence() throws Exception {
    if (!Files.isRegularFile(licencePath)) {
      return -1;
    }
    String json = Files.readString(licencePath);
    JsonNode root = JSON.readTree(json);
    if (root == null) return -1;
    JsonNode dur = root.get("durationDays");
    JsonNode sig = root.get("signature");
    if (dur == null || !dur.isInt() || sig == null || !sig.isTextual()) {
      return -1;
    }
    int days = dur.asInt();
    if (days <= 0) return -1;
    // Signature is over canonical payload: "durationDays=<value>"
    String payload = "durationDays=" + days;
    byte[] payloadBytes = payload.getBytes(StandardCharsets.UTF_8);
    byte[] sigBytes = Base64.getDecoder().decode(sig.asText().trim());
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(licencePublicKey);
    verifier.update(payloadBytes);
    if (!verifier.verify(sigBytes)) {
      return -1;
    }
    return days;
  }

  private Result loadOrCreateStateAndCheck(long now) throws Exception {
    if (!Files.exists(statePath)) {
      return createFirstUseState(now);
    }
    String content = Files.readString(statePath);
    String[] lines = content.split("\n");
    if (lines.length < 3) {
      return Result.deny("Licence state invalid or tampered");
    }
    long firstUse;
    long lastSeen;
    try {
      firstUse = Long.parseLong(lines[0].trim());
      lastSeen = Long.parseLong(lines[1].trim());
    } catch (NumberFormatException e) {
      return Result.deny("Licence state invalid or tampered");
    }
    String expectedHmac = computeStateHmac(lines[0].trim(), lines[1].trim());
    if (!constantTimeEquals(expectedHmac, lines[2].trim())) {
      return Result.deny("Licence expired or invalid");
    }
    // firstUse must not be before build time (client cannot backdate first use beyond release)
    if (buildTimestampMs > 0 && firstUse < buildTimestampMs) {
      return Result.deny("Licence state invalid");
    }
    // Clock rollback: current time must not be before last seen (minus tolerance)
    if (now < lastSeen - CLOCK_ROLLBACK_TOLERANCE_MS) {
      return Result.deny("System date appears to have been set back. Restore the correct date to use the service.");
    }
    // Expired: firstUse + durationDays
    long expiryMs = firstUse + (long) durationDays * ONE_DAY_MS;
    if (now > expiryMs) {
      return Result.deny("Licence has expired. Contact the vendor for a new licence.");
    }
    // Update lastSeen to detect future rollbacks
    long newLastSeen = Math.max(lastSeen, now);
    writeStateFile(firstUse, newLastSeen);
    return Result.allow();
  }

  private Result createFirstUseState(long now) throws IOException {
    if (buildTimestampMs > 0 && now < buildTimestampMs) {
      return Result.deny("System date is before release date. Set the correct date.");
    }
    writeStateFile(now, now);
    return Result.allow();
  }

  private void writeStateFile(long firstUse, long lastSeen) throws IOException {
    String line1 = String.valueOf(firstUse);
    String line2 = String.valueOf(lastSeen);
    String hmac = computeStateHmac(line1, line2);
    Path parent = statePath.getParent();
    if (parent != null) Files.createDirectories(parent);
    // Ensure writable so we can update lastSeen on next run
    if (Files.exists(statePath)) {
      try { statePath.toFile().setWritable(true); } catch (Exception ignored) {}
    }
    Files.writeString(statePath, line1 + "\n" + line2 + "\n" + hmac + "\n");
  }

  private static String computeStateHmac(String firstUse, String lastSeen) {
    try {
      String payload = firstUse + "\n" + lastSeen;
      Mac mac = Mac.getInstance(STATE_HMAC_ALG);
      mac.init(new SecretKeySpec(STATE_HMAC_KEY, STATE_HMAC_ALG));
      byte[] hmac = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hmac);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] deriveStateKey() {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] seed = "TrustSign-Licence-State-Key-v1".getBytes(StandardCharsets.UTF_8);
      return md.digest(seed);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private static boolean constantTimeEquals(String a, String b) {
    if (a == null || b == null) return a == b;
    byte[] aa = a.getBytes(StandardCharsets.UTF_8);
    byte[] bb = b.getBytes(StandardCharsets.UTF_8);
    return aa.length == bb.length && MessageDigest.isEqual(aa, bb);
  }

  /**
   * Loads a PEM-encoded RSA public key from the given stream.
   */
  public static PublicKey loadPublicKeyFromPem(InputStream in) throws Exception {
    String pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    pem = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s", "");
    byte[] der = Base64.getDecoder().decode(pem);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
    return KeyFactory.getInstance("RSA").generatePublic(spec);
  }
}
