package com.trustsign.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

public final class Pkcs11Token {
  private static final ConcurrentHashMap<String, Provider> PROVIDER_CACHE = new ConcurrentHashMap<>();
  private static final AtomicReference<String> LAST_SUCCESSFUL_LIBRARY = new AtomicReference<>();
  private static final LongAdder LOAD_REQUESTS = new LongAdder();
  private static final LongAdder LOAD_SUCCESSES = new LongAdder();
  private static final LongAdder LOAD_FAILURES = new LongAdder();
  private static final LongAdder LOAD_TOTAL_TIME_NS = new LongAdder();

  public record Loaded(KeyStore keyStore, Provider provider, String libraryPath) {}

  public static Loaded load(char[] pin, List<String> libraryCandidates) {
    long startedAt = System.nanoTime();
    LOAD_REQUESTS.increment();
    Exception last = null;
    int tried = 0;
    List<String> orderedCandidates = prioritizeCandidates(libraryCandidates);

    for (String lib : orderedCandidates) {
      if (lib == null || lib.isBlank()) continue;

      Path libPath = Paths.get(lib);
      if (!Files.isRegularFile(libPath)) {
        last = new IOException("PKCS#11 library not found: " + lib);
        tried++;
        continue;
      }

      Provider p11 = null;
      boolean fromCache = false;
      try {
        p11 = PROVIDER_CACHE.get(libPath.toAbsolutePath().toString());
        if (p11 == null) {
          p11 = createProviderWithTempConfig(libPath);
          PROVIDER_CACHE.put(libPath.toAbsolutePath().toString(), p11);
        } else {
          fromCache = true;
        }

        if (Security.getProvider(p11.getName()) == null) {
          Security.addProvider(p11);
        }

        KeyStore ks = KeyStore.getInstance("PKCS11", p11);

        ks.load(null, pin);

        LAST_SUCCESSFUL_LIBRARY.set(libPath.toAbsolutePath().toString());
        LOAD_SUCCESSES.increment();
        LOAD_TOTAL_TIME_NS.add(System.nanoTime() - startedAt);
        return new Loaded(ks, p11, lib);
      } catch (Exception e) {
        last = e;
        tried++;

        if (p11 != null && !fromCache) {
          PROVIDER_CACHE.remove(libPath.toAbsolutePath().toString());
          try { Security.removeProvider(p11.getName()); } catch (Exception ignore) {}
        }
      }
    }

    String hint = last != null ? last.getMessage() : "No library path succeeded.";
    if (tried == 0) hint = "No PKCS#11 library paths configured or all paths are blank.";
    LOAD_FAILURES.increment();
    LOAD_TOTAL_TIME_NS.add(System.nanoTime() - startedAt);
    throw new RuntimeException("Unable to load token using configured PKCS#11 libraries. " + hint, last);
  }

  public static Map<String, Object> metricsSnapshot() {
    long requests = LOAD_REQUESTS.sum();
    long totalNs = LOAD_TOTAL_TIME_NS.sum();
    double avgMs = requests == 0 ? 0.0 : (totalNs / 1_000_000.0) / requests;
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("loadRequests", requests);
    out.put("loadSuccesses", LOAD_SUCCESSES.sum());
    out.put("loadFailures", LOAD_FAILURES.sum());
    out.put("avgLoadLatencyMs", avgMs);
    out.put("providerCacheSize", PROVIDER_CACHE.size());
    out.put("lastSuccessfulLibrary", LAST_SUCCESSFUL_LIBRARY.get());
    return out;
  }

  private static List<String> prioritizeCandidates(List<String> libraryCandidates) {
    if (libraryCandidates == null || libraryCandidates.isEmpty()) {
      return List.of();
    }
    String lastSuccessful = LAST_SUCCESSFUL_LIBRARY.get();
    if (lastSuccessful == null || lastSuccessful.isBlank()) {
      return libraryCandidates;
    }
    ArrayList<String> ordered = new ArrayList<>(libraryCandidates.size());
    for (String candidate : libraryCandidates) {
      if (candidate == null || candidate.isBlank()) continue;
      String normalized = Paths.get(candidate).toAbsolutePath().toString();
      if (normalized.equals(lastSuccessful)) {
        ordered.add(candidate);
        break;
      }
    }
    for (String candidate : libraryCandidates) {
      if (candidate == null || candidate.isBlank()) continue;
      if (!ordered.contains(candidate)) {
        ordered.add(candidate);
      }
    }
    return ordered;
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

