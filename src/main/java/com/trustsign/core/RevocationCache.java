package com.trustsign.core;

import java.security.cert.X509Certificate;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Caches OCSP/CRL fetch outcomes (success or failure) per issuer+serial for a
 * short TTL. LTV embedding fetches revocation data for the same handful of
 * chain certificates (leaf/SubCA/CA) on every single sign call; without this
 * cache, a slow or unreachable responder costs its full connect+read timeout
 * on every request instead of once per TTL window.
 */
final class RevocationCache {
  private static final long SUCCESS_TTL_NANOS = TimeUnit.MINUTES.toNanos(10);
  private static final long FAILURE_TTL_NANOS = TimeUnit.SECONDS.toNanos(60);

  private record Entry(byte[] data, Exception failure, long expiresAtNanos) {}

  private static final ConcurrentHashMap<String, Entry> CACHE = new ConcurrentHashMap<>();

  static byte[] ocsp(X509Certificate cert, X509Certificate issuer, int connectTimeoutMs, int readTimeoutMs)
      throws Exception {
    return getOrFetch(
        key("ocsp", cert, issuer),
        () -> OcspClient.fetchOcspResponse(cert, issuer, connectTimeoutMs, readTimeoutMs));
  }

  static byte[] crl(X509Certificate cert, X509Certificate issuer, int connectTimeoutMs, int readTimeoutMs)
      throws Exception {
    return getOrFetch(
        key("crl", cert, issuer),
        () -> CrlFetcher.fetchCrl(cert, issuer, connectTimeoutMs, readTimeoutMs));
  }

  private static String key(String kind, X509Certificate cert, X509Certificate issuer) {
    return kind + ':' + issuer.getSubjectX500Principal().getName() + ':' + cert.getSerialNumber().toString(16);
  }

  private static byte[] getOrFetch(String key, Callable<byte[]> fetcher) throws Exception {
    long now = System.nanoTime();
    Entry cached = CACHE.get(key);
    if (cached != null && now < cached.expiresAtNanos()) {
      if (cached.failure() != null) {
        throw cached.failure();
      }
      return cached.data();
    }
    try {
      byte[] data = fetcher.call();
      CACHE.put(key, new Entry(data, null, now + SUCCESS_TTL_NANOS));
      return data;
    } catch (Exception e) {
      CACHE.put(key, new Entry(null, e, now + FAILURE_TTL_NANOS));
      throw e;
    }
  }

  private RevocationCache() {}
}
