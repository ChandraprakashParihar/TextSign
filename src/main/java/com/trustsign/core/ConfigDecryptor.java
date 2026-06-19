package com.trustsign.core;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Decrypts config values that are wrapped with {@code ENC(base64...)}.
 * Encryption is done on the vendor's server using the same AES-256-GCM key.
 *
 * If the value does NOT start with {@code ENC(}, it is returned as-is (plaintext fallback).
 *
 * Performance: the PBKDF2 key is derived once and cached. Decrypted values are also
 * cached so repeated calls for the same encrypted input are a simple HashMap lookup.
 */
public final class ConfigDecryptor {

  private static final byte[] APP_KEY_SALT =
      "TrustSign-TS-PWD-V1-9c4e".getBytes(StandardCharsets.UTF_8);
  private static final String APP_KEY_PASSPHRASE = "Xr7!qLm@2wTsKd#5pNv&8yBjF0uHc$4e";
  private static final int PBKDF2_ITERATIONS = 65536;
  private static final String PBKDF2_ALG = "PBKDF2WithHmacSHA256";

  private static volatile SecretKey cachedKey;
  private static final ConcurrentHashMap<String, String> decryptCache = new ConcurrentHashMap<>();

  public static String decryptIfEncrypted(String value) {
    if (value == null) return null;
    String trimmed = value.trim();
    if (!trimmed.startsWith("ENC(") || !trimmed.endsWith(")")) {
      return value;
    }
    String cached = decryptCache.get(trimmed);
    if (cached != null) return cached;

    String base64 = trimmed.substring(4, trimmed.length() - 1);
    String result = decrypt(base64);
    decryptCache.put(trimmed, result);
    return result;
  }

  private static String decrypt(String base64Encrypted) {
    try {
      byte[] combined = Base64.getUrlDecoder().decode(base64Encrypted);
      if (combined.length < 28) {
        throw new IllegalArgumentException("Encrypted value is too short");
      }

      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, getKey(),
          new GCMParameterSpec(128, combined, 0, 12));
      byte[] plaintext = cipher.doFinal(combined, 12, combined.length - 12);

      return new String(plaintext, StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new RuntimeException(
          "Failed to decrypt config value. The ENC(...) value may be corrupted or encrypted with a different key.", e);
    }
  }

  private static SecretKey getKey() throws Exception {
    SecretKey k = cachedKey;
    if (k != null) return k;
    synchronized (ConfigDecryptor.class) {
      if (cachedKey != null) return cachedKey;
      PBEKeySpec spec = new PBEKeySpec(
          APP_KEY_PASSPHRASE.toCharArray(), APP_KEY_SALT, PBKDF2_ITERATIONS, 256);
      try {
        byte[] keyBytes = SecretKeyFactory.getInstance(PBKDF2_ALG)
            .generateSecret(spec).getEncoded();
        cachedKey = new SecretKeySpec(keyBytes, "AES");
        return cachedKey;
      } finally {
        spec.clearPassword();
      }
    }
  }

  private ConfigDecryptor() {}
}
