package com.trustsign.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

public final class Pkcs11Token {

  public record Loaded(KeyStore keyStore, Provider provider, String libraryPath) {}

  public static Loaded load(char[] pin, List<String> libraryCandidates) {
    Exception last = null;
    int tried = 0;

    for (String lib : libraryCandidates) {
      if (lib == null || lib.isBlank()) continue;

      Path libPath = Paths.get(lib);
      if (!Files.isRegularFile(libPath)) {
        last = new IOException("PKCS#11 library not found: " + lib);
        tried++;
        continue;
      }

      Provider p11 = null;
      try {
        p11 = createProviderWithTempConfig(libPath);

        if (Security.getProvider(p11.getName()) == null) {
          Security.addProvider(p11);
        }

        KeyStore ks = KeyStore.getInstance("PKCS11", p11);

        ks.load(null, pin);

        return new Loaded(ks, p11, lib);
      } catch (Exception e) {
        last = e;
        tried++;

        if (p11 != null) {
          try { Security.removeProvider(p11.getName()); } catch (Exception ignore) {}
        }
      }
    }

    String hint = last != null ? last.getMessage() : "No library path succeeded.";
    if (tried == 0) hint = "No PKCS#11 library paths configured or all paths are blank.";
    throw new RuntimeException("Unable to load token using configured PKCS#11 libraries. " + hint, last);
  }

  private static Provider createProviderWithTempConfig(Path libraryPath) throws IOException {
    Provider base = Security.getProvider("SunPKCS11");
    if (base == null) {
      throw new IllegalStateException("SunPKCS11 provider not available on this JVM.");
    }

    String safe = Integer.toHexString(libraryPath.hashCode());
    String cfg = "name=TrustSignToken_" + safe + "\n" +
                "library=" + libraryPath + "\n";

    Path tmp = Files.createTempFile("pkcs11-", ".cfg");
    Files.writeString(tmp, cfg, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
    tmp.toFile().deleteOnExit();

    return base.configure(tmp.toAbsolutePath().toString());
  }

  public static List<CertItem> listCertificates(KeyStore ks) {
    try {
      List<CertItem> out = new ArrayList<>();
      Enumeration<String> aliases = ks.aliases();

      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (!ks.isKeyEntry(alias)) continue;

        Certificate cert = ks.getCertificate(alias);
        if (!(cert instanceof X509Certificate x509)) continue;

        out.add(new CertItem(
            alias,
            x509.getSubjectX500Principal().getName(),
            x509.getIssuerX500Principal().getName(),
            x509.getSerialNumber().toString(16),
            x509.getNotBefore(),
            x509.getNotAfter(),
            x509.getPublicKey().getAlgorithm()
        ));
      }
      return out;
    } catch (Exception e) {
      throw new RuntimeException("Failed to list certificates from token.", e);
    }
  }

  public record CertItem(
      String alias,
      String subject,
      String issuer,
      String serialHex,
      Date notBefore,
      Date notAfter,
      String pubKeyAlg
  ) {}
}

