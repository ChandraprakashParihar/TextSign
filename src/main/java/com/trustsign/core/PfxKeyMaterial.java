package com.trustsign.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

/**
 * Loads a PKCS#12 (.pfx/.p12) file as a software-key signing credential — the
 * file-based equivalent of {@link Pkcs11Token} for deployments without a
 * hardware token. Unlike a PKCS#11 key, a PKCS#12 private key is fully
 * extractable, so signing with it needs none of the elaborate
 * provider-binding workarounds PKCS#11 keys require elsewhere in this
 * codebase (see the "SunRsaSign" shimming in {@code OoxmlSignerService}):
 * the standard JDK "SunRsaSign" provider signs it directly.
 *
 * <p>Deliberately returns the same shape as {@link Pkcs11Token.Loaded}
 * ({@code KeyStore} + {@code Provider}) so every downstream consumer —
 * certificate selection, {@code KeyStore.getKey}, the various
 * {@code *SignerService.sign(...)} calls — works completely unchanged
 * regardless of which credential source produced them.
 */
public final class PfxKeyMaterial {

  public record Loaded(KeyStore keyStore, Provider provider) {}

  public static Loaded load(String path, char[] password) throws Exception {
    if (path == null || path.isBlank()) {
      throw new IllegalArgumentException("PFX path is not configured");
    }
    Path pfxPath = Paths.get(path);
    if (!Files.isRegularFile(pfxPath)) {
      throw new IllegalArgumentException("Configured PFX file not found: " + path);
    }

    KeyStore ks = KeyStore.getInstance("PKCS12");
    byte[] pfxBytes = Files.readAllBytes(pfxPath);
    try (ByteArrayInputStream in = new ByteArrayInputStream(pfxBytes)) {
      ks.load(in, password);
    } catch (IOException e) {
      // KeyStore.load throws a generic IOException for both "wrong password"
      // and "corrupt/not-a-PKCS12-file" — neither is separable from the JDK
      // API without fragile message-string matching, so both are reported
      // together with a single, actionable hint.
      throw new IllegalArgumentException(
          "Unable to open PFX file (wrong password, or not a valid PKCS#12 file): " + path, e);
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalArgumentException("Unable to load PFX file: " + path + " (" + safeMsg(e) + ")", e);
    }

    Provider rsaProvider = Security.getProvider("SunRsaSign");
    if (rsaProvider == null) {
      // Every reference JVM ships SunRsaSign; this is a defensive check, not
      // an expected runtime path.
      throw new IllegalStateException("SunRsaSign provider not available on this JVM.");
    }
    return new Loaded(ks, rsaProvider);
  }

  private static String safeMsg(Throwable t) {
    String m = t.getMessage();
    return (m != null && !m.isBlank()) ? m : t.getClass().getSimpleName();
  }

  private PfxKeyMaterial() {}
}
