package com.trustsign.core;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * Parses PEM or base64-encoded public keys (and PEM certificates) for token certificate selection.
 */
public final class SigningPublicKeyParser {

  public static List<PublicKey> parsePublicKeys(String pemOrBase64) throws Exception {
    String trimmed = pemOrBase64 == null ? "" : pemOrBase64.trim();
    List<PublicKey> keys = new ArrayList<>();
    if (trimmed.isEmpty()) {
      return keys;
    }

    String upper = trimmed.toUpperCase(Locale.ROOT);
    boolean hasPemMarkers = upper.contains("-----BEGIN CERTIFICATE-----")
        || upper.contains("-----BEGIN PUBLIC KEY-----");

    if (!hasPemMarkers) {
      keys.add(parseSingle(trimmed));
      return keys;
    }

    int pos = 0;
    while (pos < trimmed.length()) {
      int nextCert = upper.indexOf("-----BEGIN CERTIFICATE-----", pos);
      int nextPub = upper.indexOf("-----BEGIN PUBLIC KEY-----", pos);
      if (nextCert == -1 && nextPub == -1) {
        break;
      }

      boolean isCert;
      int begin;
      if (nextCert == -1) {
        begin = nextPub;
        isCert = false;
      } else if (nextPub == -1 || nextCert < nextPub) {
        begin = nextCert;
        isCert = true;
      } else {
        begin = nextPub;
        isCert = false;
      }

      String endMarker = isCert ? "-----END CERTIFICATE-----" : "-----END PUBLIC KEY-----";
      int end = upper.indexOf(endMarker, begin);
      if (end == -1) {
        break;
      }
      end += endMarker.length();

      String block = trimmed.substring(begin, end);
      try {
        PublicKey pk = parseSingle(block);
        if (pk != null) {
          keys.add(pk);
        }
      } catch (Exception ignore) {
        // skip malformed block
      }
      pos = end;
    }
    return keys;
  }

  private static PublicKey parseSingle(String pemOrBase64) throws Exception {
    String trimmed = pemOrBase64.trim();
    if (trimmed.contains("BEGIN CERTIFICATE")) {
      String certPem = trimmed
          .replace("-----BEGIN CERTIFICATE-----", "")
          .replace("-----END CERTIFICATE-----", "")
          .replaceAll("\\s", "");
      byte[] certDer = Base64.getDecoder().decode(certPem);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certDer));
      return cert.getPublicKey();
    }

    String normalized = trimmed
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s", "");
    byte[] der = Base64.getDecoder().decode(normalized);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }

  private SigningPublicKeyParser() {}
}
