package com.trustsign.hsm;

import com.trustsign.core.TokenCertificateSelector;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HSM-only PKCS#11 setup: enumerates {@code slotListIndex} values for each configured library until
 * the keystore contains a signer certificate matching the uploaded .cer. Does not use {@link com.trustsign.core.Pkcs11Token}.
 */
public final class HsmPkcs11ConfigurationService {

  private static final Logger LOG = LoggerFactory.getLogger(HsmPkcs11ConfigurationService.class);

  public static final int DEFAULT_SLOT_PROBE_COUNT = 32;
  public static final int MAX_SLOT_PROBE_COUNT = 256;
  private static volatile String lastSuccessfulLib;
  private static volatile int lastSuccessfulSlot = -1;

  /**
   * A token slot whose keystore contains a key entry matching one of the signer certificates.
   */
  public record MatchedSlotLoad(
      KeyStore keyStore,
      Provider provider,
      String libraryPath,
      int slotListIndex,
      TokenCertificateSelector.Selection selection) {}

  /**
   * @param slotProbeCount number of slot indices to try per library: {@code 0 .. slotProbeCount-1}
   */
  public static MatchedSlotLoad loadMatchingSlot(
      char[] pin,
      List<String> libraryCandidates,
      List<X509Certificate> signerCertificates,
      int slotProbeCount) {
    if (pin == null || pin.length == 0) {
      throw new IllegalArgumentException("pin is required");
    }
    if (libraryCandidates == null || libraryCandidates.isEmpty()) {
      throw new IllegalStateException("No PKCS#11 library paths configured for HSM.");
    }
    if (signerCertificates == null || signerCertificates.isEmpty()) {
      throw new IllegalArgumentException("signerCertificates is empty");
    }
    int slots = normalizeSlotProbeCount(slotProbeCount);

    // Fast path: try last-known-good library+slot first
    String cachedLib = lastSuccessfulLib;
    int cachedSlot = lastSuccessfulSlot;
    if (cachedLib != null && cachedSlot >= 0) {
      MatchedSlotLoad fast = trySlot(cachedLib, cachedSlot, pin, signerCertificates);
      if (fast != null) {
        LOG.debug("HSM fast-path hit: lib={} slot={}", cachedLib, cachedSlot);
        return fast;
      }
    }

    Exception last = null;
    int tried = 0;

    for (String lib : libraryCandidates) {
      if (lib == null || lib.isBlank()) {
        continue;
      }
      Path libPath = Paths.get(lib);
      if (!Files.isRegularFile(libPath)) {
        last = new IOException("PKCS#11 library not found: " + lib);
        tried++;
        continue;
      }

      for (int slotIdx = 0; slotIdx < slots; slotIdx++) {
        Provider p11 = null;
        try {
          p11 = createProviderForSlot(libPath, slotIdx);
          if (Security.getProvider(p11.getName()) == null) {
            Security.addProvider(p11);
          }
          KeyStore ks = KeyStore.getInstance("PKCS11", p11);
          ks.load(null, pin);

          TokenCertificateSelector.Selection sel = TokenCertificateSelector.selectBySignerCertificates(ks, signerCertificates);
          if (sel != null) {
            lastSuccessfulLib = lib;
            lastSuccessfulSlot = slotIdx;
            LOG.info("HSM cert matched on lib={} slot={} alias={}", lib, slotIdx, sel.alias());
            return new MatchedSlotLoad(ks, p11, lib, slotIdx, sel);
          }

          LOG.warn("HSM slot loaded but no cert match via KeyStore. lib={} slot={}", lib, slotIdx);
          logSlotContents(ks, lib, slotIdx, signerCertificates);
          tried++;
        } catch (Exception e) {
          last = e;
          tried++;
        } finally {
          if (p11 != null) {
            try {
              Security.removeProvider(p11.getName());
            } catch (Exception ignore) {
            }
          }
        }
      }
    }

    // Always log uploaded cert details at WARN so the mismatch is diagnosable
    // without needing DEBUG level.
    for (X509Certificate uploaded : signerCertificates) {
      LOG.warn("HSM match failed. uploaded .cer thumbprint={} subject='{}' serial={} issuer='{}'",
          TokenCertificateSelector.thumbprint(uploaded),
          uploaded.getSubjectX500Principal().getName(),
          uploaded.getSerialNumber().toString(16),
          uploaded.getIssuerX500Principal().getName());
    }

    String hint = last != null ? last.getMessage() : "No slot contained a matching certificate.";
    throw new RuntimeException(
        "Unable to load HSM PKCS#11 slot with a certificate matching the provided .cer (tried " + tried + " slot attempts). " + hint,
        last);
  }

  private static MatchedSlotLoad trySlot(String lib, int slotIdx, char[] pin,
      List<X509Certificate> signerCertificates) {
    try {
      Path libPath = Paths.get(lib);
      if (!Files.isRegularFile(libPath)) return null;
      Provider p11 = createProviderForSlot(libPath, slotIdx);
      if (Security.getProvider(p11.getName()) == null) {
        Security.addProvider(p11);
      }
      KeyStore ks = KeyStore.getInstance("PKCS11", p11);
      ks.load(null, pin);
      TokenCertificateSelector.Selection sel =
          TokenCertificateSelector.selectBySignerCertificates(ks, signerCertificates);
      if (sel != null) {
        return new MatchedSlotLoad(ks, p11, lib, slotIdx, sel);
      }
      Security.removeProvider(p11.getName());
    } catch (Exception ignored) {}
    return null;
  }

  public static int normalizeSlotProbeCount(int requested) {
    if (requested <= 0) {
      return DEFAULT_SLOT_PROBE_COUNT;
    }
    return Math.min(requested, MAX_SLOT_PROBE_COUNT);
  }

  private static final java.util.concurrent.ConcurrentHashMap<String, Path> SLOT_CFG_CACHE =
      new java.util.concurrent.ConcurrentHashMap<>();

  public static Provider createProviderForSlot(Path libraryPath, int slotListIndex) throws IOException {
    Provider base = Security.getProvider("SunPKCS11");
    if (base == null) {
      throw new IllegalStateException("SunPKCS11 provider not available on this JVM.");
    }
    String safe = Integer.toHexString(libraryPath.hashCode());
    String cacheKey = safe + "_" + slotListIndex;
    String cfg = "name=TrustSignHsm_" + cacheKey + "\n"
        + "library=" + libraryPath + "\n"
        + "slotListIndex=" + slotListIndex + "\n";

    Path tmp = SLOT_CFG_CACHE.computeIfAbsent(cacheKey, k -> {
      try {
        Path p = Files.createTempFile("pkcs11-hsm-", ".cfg");
        p.toFile().deleteOnExit();
        return p;
      } catch (IOException e) {
        throw new java.io.UncheckedIOException(e);
      }
    });
    Files.writeString(tmp, cfg, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);

    return base.configure(tmp.toAbsolutePath().toString());
  }

  private static void logSlotContents(KeyStore ks, String lib, int slotIdx,
      List<X509Certificate> uploadedCerts) {
    try {
      LOG.warn("--- HSM slot diagnostic: lib={} slot={} ---", lib, slotIdx);
      int aliasCount = 0;
      for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
        String alias = e.nextElement();
        aliasCount++;
        Certificate cert = ks.getCertificate(alias);
        if (cert instanceof X509Certificate x509) {
          LOG.warn("  token alias='{}' thumbprint={} subject='{}' serial={} issuer='{}'",
              alias,
              TokenCertificateSelector.thumbprint(x509),
              x509.getSubjectX500Principal().getName(),
              x509.getSerialNumber().toString(16),
              x509.getIssuerX500Principal().getName());
        } else {
          LOG.warn("  token alias='{}' certType={}", alias, cert != null ? cert.getType() : "null");
        }
      }
      if (aliasCount == 0) {
        LOG.warn("  (keystore is empty — no aliases found on this slot)");
      }
      for (X509Certificate uploaded : uploadedCerts) {
        LOG.warn("  uploaded .cer thumbprint={} subject='{}' serial={} issuer='{}'",
            TokenCertificateSelector.thumbprint(uploaded),
            uploaded.getSubjectX500Principal().getName(),
            uploaded.getSerialNumber().toString(16),
            uploaded.getIssuerX500Principal().getName());
      }
    } catch (Exception e) {
      LOG.warn("  failed to enumerate slot contents: {}", e.getMessage());
    }
  }

  private HsmPkcs11ConfigurationService() {}
}
