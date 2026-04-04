package com.trustsign.core;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Parses PEM or base64-DER X.509 certificates (.cer) for HSM signer selection.
 */
public final class SigningCertificateParser {

  public static List<X509Certificate> parseCertificates(String pemOrDerBase64) throws Exception {
    String trimmed = pemOrDerBase64 == null ? "" : pemOrDerBase64.trim();
    List<X509Certificate> out = new ArrayList<>();
    if (trimmed.isEmpty()) {
      return out;
    }

    String upper = trimmed.toUpperCase(Locale.ROOT);
    if (!upper.contains("-----BEGIN CERTIFICATE-----")) {
      out.add(parseSingleDer(Base64.getDecoder().decode(trimmed.replaceAll("\\s", ""))));
      return out;
    }

    int pos = 0;
    while (pos < trimmed.length()) {
      int begin = upper.indexOf("-----BEGIN CERTIFICATE-----", pos);
      if (begin == -1) {
        break;
      }
      int end = upper.indexOf("-----END CERTIFICATE-----", begin);
      if (end == -1) {
        break;
      }
      end += "-----END CERTIFICATE-----".length();
      String block = trimmed.substring(begin, end);
      try {
        out.add(parsePemCertificateBlock(block));
      } catch (Exception ignore) {
        // skip malformed block
      }
      pos = end;
    }
    return out;
  }

  private static X509Certificate parsePemCertificateBlock(String pemBlock) throws Exception {
    String b64 = pemBlock
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replaceAll("\\s", "");
    return parseSingleDer(Base64.getDecoder().decode(b64));
  }

  /**
   * Parses a .cer upload: PEM text (one or more certificates) or raw DER.
   */
  public static List<X509Certificate> parseFromUpload(byte[] cerBytes) throws Exception {
    if (cerBytes == null || cerBytes.length == 0) {
      return Collections.emptyList();
    }
    String asUtf8 = new String(cerBytes, StandardCharsets.UTF_8);
    if (asUtf8.contains("BEGIN CERTIFICATE")) {
      return parseCertificates(asUtf8);
    }
    return List.of(parseSingleDer(cerBytes));
  }

  private static X509Certificate parseSingleDer(byte[] der) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
  }

  private SigningCertificateParser() {}
}
