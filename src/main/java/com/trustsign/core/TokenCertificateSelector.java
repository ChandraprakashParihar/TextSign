package com.trustsign.core;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

/**
 * Picks a token key entry whose certificate public key matches one of the requested keys.
 */
public final class TokenCertificateSelector {

  public record Selection(String alias, X509Certificate certificate, Certificate[] chain) {}

  public static Selection select(KeyStore ks, List<PublicKey> requestedPublicKeys) throws Exception {
    if (requestedPublicKeys == null || requestedPublicKeys.isEmpty()) {
      throw new IllegalArgumentException("No public keys provided for certificate selection");
    }
    for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
      String alias = e.nextElement();
      Certificate cert = ks.getCertificate(alias);
      if (cert instanceof X509Certificate x509) {
        PublicKey certKey = x509.getPublicKey();
        for (PublicKey requested : requestedPublicKeys) {
          if (certKey.equals(requested)) {
            Certificate[] chain = ks.getCertificateChain(alias);
            return new Selection(alias, x509, chain);
          }
        }
      }
    }
    return null;
  }

  private TokenCertificateSelector() {}
}
