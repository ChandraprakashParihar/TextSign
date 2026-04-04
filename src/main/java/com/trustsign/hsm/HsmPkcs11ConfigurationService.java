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
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * HSM-only PKCS#11 setup: enumerates {@code slotListIndex} values for each configured library until
 * the keystore contains a signer certificate matching the uploaded .cer. Does not use {@link com.trustsign.core.Pkcs11Token}.
 */
public final class HsmPkcs11ConfigurationService {

  public static final int DEFAULT_SLOT_PROBE_COUNT = 32;
  public static final int MAX_SLOT_PROBE_COUNT = 256;

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
            return new MatchedSlotLoad(ks, p11, lib, slotIdx, sel);
          }
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

    String hint = last != null ? last.getMessage() : "No slot contained a matching certificate.";
    throw new RuntimeException(
        "Unable to load HSM PKCS#11 slot with a certificate matching the provided .cer (tried " + tried + " slot attempts). " + hint,
        last);
  }

  public static int normalizeSlotProbeCount(int requested) {
    if (requested <= 0) {
      return DEFAULT_SLOT_PROBE_COUNT;
    }
    return Math.min(requested, MAX_SLOT_PROBE_COUNT);
  }

  private static Provider createProviderForSlot(Path libraryPath, int slotListIndex) throws IOException {
    Provider base = Security.getProvider("SunPKCS11");
    if (base == null) {
      throw new IllegalStateException("SunPKCS11 provider not available on this JVM.");
    }
    String safe = Integer.toHexString(libraryPath.hashCode());
    String cfg = "name=TrustSignHsm_" + safe + "_" + slotListIndex + "\n"
        + "library=" + libraryPath + "\n"
        + "slotListIndex=" + slotListIndex + "\n";

    Path tmp = Files.createTempFile("pkcs11-hsm-", ".cfg");
    Files.writeString(tmp, cfg, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
    tmp.toFile().deleteOnExit();

    return base.configure(tmp.toAbsolutePath().toString());
  }

  private HsmPkcs11ConfigurationService() {}
}
