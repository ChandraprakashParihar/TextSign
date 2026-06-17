package com.trustsign.core;

import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.List;

/**
 * Picks a token key entry by certificate thumbprint (SHA-1 of DER),
 * falling back to serial+issuer and then public key comparison.
 */
public final class TokenCertificateSelector {

  public record Selection(String alias, X509Certificate certificate, Certificate[] chain) {}

  /**
   * Match order: thumbprint (SHA-1 of DER) → serial+issuer → public key.
   * Thumbprint is the primary match because it uniquely identifies a certificate
   * even when CN or other fields are identical across multiple certs.
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
    // 1. Thumbprint match (SHA-1 of DER encoding) — byte-for-byte identical certificate
    String tokenThumb = thumbprint(tokenCert);
    String providedThumb = thumbprint(provided);
    if (tokenThumb != null && tokenThumb.equals(providedThumb)) {
      return true;
    }
    // 2. Serial + issuer — unique per CA
    if (tokenCert.getSerialNumber().equals(provided.getSerialNumber())
        && tokenCert.getIssuerX500Principal().equals(provided.getIssuerX500Principal())) {
      return true;
    }
    // 3. Public key — same key pair even if certificate was re-issued
    return tokenCert.getPublicKey().equals(provided.getPublicKey());
  }

  /**
   * Computes the SHA-1 thumbprint (fingerprint) of a certificate's DER encoding.
   * This is the same value shown as "Thumbprint" in Windows Certificate Manager.
   */
  public static String thumbprint(X509Certificate cert) {
    try {
      byte[] der = cert.getEncoded();
      byte[] sha1 = MessageDigest.getInstance("SHA-1").digest(der);
      return HexFormat.of().formatHex(sha1);
    } catch (Exception e) {
      return null;
    }
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
