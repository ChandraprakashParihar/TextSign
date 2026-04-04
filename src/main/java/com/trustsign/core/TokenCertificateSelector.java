package com.trustsign.core;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

/**
 * Picks a token key entry by public key or by signer certificate (.cer).
 */
public final class TokenCertificateSelector {

  public record Selection(String alias, X509Certificate certificate, Certificate[] chain) {}

  /**
   * Match order: same serial number and issuer DN, else same public key.
   */
  public static Selection selectBySignerCertificates(KeyStore ks, List<X509Certificate> providedCertificates)
      throws Exception {
    if (providedCertificates == null || providedCertificates.isEmpty()) {
      throw new IllegalArgumentException("No certificates provided for certificate selection");
    }
    for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
      String alias = e.nextElement();
      Certificate cert = ks.getCertificate(alias);
      if (cert instanceof X509Certificate x509) {
        for (X509Certificate provided : providedCertificates) {
          if (signerCertificatesMatch(x509, provided)) {
            Certificate[] chain = ks.getCertificateChain(alias);
            return new Selection(alias, x509, chain);
          }
        }
      }
    }
    return null;
  }

  public static boolean signerCertificatesMatch(X509Certificate tokenCert, X509Certificate provided) {
    if (tokenCert.getSerialNumber().equals(provided.getSerialNumber())
        && tokenCert.getIssuerX500Principal().equals(provided.getIssuerX500Principal())) {
      return true;
    }
    return tokenCert.getPublicKey().equals(provided.getPublicKey());
  }

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
