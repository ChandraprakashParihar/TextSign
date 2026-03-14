package com.trustsign.core;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

/**
 * Helper for validating signing certificates from the token.
 *
 * Currently performs:
 * - validity period checks
 * - optional key usage checks
 * - optional CRL-based revocation checks (via CRL distribution points)
 */
public final class CertificateValidator {

  /**
   * Validates that the given certificate is suitable for signing according to
   * simple local checks:
   * - not expired / not before
   * - (optional) digital signature / non-repudiation key usage
   * - (optional) CRL revocation status using CRL distribution points
   * - (optional) trust-chain validation against a trust store / system trust
   *
   * Behaviour is controlled by system properties:
   * - trustsign.requireDigitalSignature (default: true)
   * - trustsign.enableCrlCheck (default: false)
   * - trustsign.enablePathValidation (default: true)
   * - trustsign.truststore.path (optional, file path)
   * - trustsign.truststore.password (optional, for custom trust store)
   * - trustsign.truststore.type (default: JKS)
   *
   * Throws {@link SecurityException} when the certificate is not acceptable.
   */
  public static void validateForSigning(X509Certificate cert) {
    validateForSigning(cert, null);
  }

  /**
   * Variant that also accepts the full certificate chain as presented by the token.
   */
  public static void validateForSigning(X509Certificate cert, X509Certificate[] chain) {
    if (cert == null) {
      throw new SecurityException("Signing certificate is missing");
    }

    try {
      cert.checkValidity();
    } catch (Exception e) {
      throw new SecurityException("Certificate is not valid: " + e.getMessage(), e);
    }

    boolean requireKeyUsage = Boolean.parseBoolean(
        System.getProperty("trustsign.requireDigitalSignature", "true")
    );
    if (requireKeyUsage) {
      boolean[] ku = cert.getKeyUsage();
      // digitalSignature (0) or nonRepudiation/contentCommitment (1)
      if (ku == null || (!safeIndex(ku, 0) && !safeIndex(ku, 1))) {
        throw new SecurityException("Certificate is not allowed for digital signatures");
      }
    }

    boolean enableCrl = Boolean.parseBoolean(
        System.getProperty("trustsign.enableCrlCheck", "true")
    );
    if (enableCrl) {
      checkRevocationWithCrl(cert);
    }

    boolean enablePathValidation = Boolean.parseBoolean(
        System.getProperty("trustsign.enablePathValidation", "true")
    );
    if (enablePathValidation) {
      validateTrustChain(cert, chain);
    }
  }

  private static boolean safeIndex(boolean[] arr, int idx) {
    return idx >= 0 && idx < arr.length && arr[idx];
  }

  /**
   * Best-effort CRL check using the CRL distribution points extension (if present).
   * Only HTTP/HTTPS URLs are supported.
   */
  private static void checkRevocationWithCrl(X509Certificate cert) {
    try {
      byte[] extVal = cert.getExtensionValue("2.5.29.31"); // CRLDistributionPoints OID
      if (extVal == null) {
        return; // no CRL info, nothing we can reasonably do here
      }

      ASN1Primitive derObj = ASN1Primitive.fromByteArray(
          ASN1OctetString.getInstance(extVal).getOctets()
      );
      CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj);
      if (distPoint == null) return;

      for (DistributionPoint dp : distPoint.getDistributionPoints()) {
        DistributionPointName dpName = dp.getDistributionPoint();
        if (dpName == null || dpName.getType() != DistributionPointName.FULL_NAME) continue;

        GeneralNames gns = GeneralNames.getInstance(dpName.getName());
        for (GeneralName gn : gns.getNames()) {
          if (gn.getTagNo() != GeneralName.uniformResourceIdentifier) continue;

          String uri = gn.getName().toString();
          if (!uri.startsWith("http://") && !uri.startsWith("https://")) continue;

          if (isRevokedByCrl(cert, uri)) {
            throw new SecurityException("Certificate has been revoked (CRL: " + uri + ")");
          }
        }
      }
    } catch (SecurityException se) {
      throw se;
    } catch (Exception e) {
      // Treat CRL failures as soft by default to avoid blocking signing
      // when CRL endpoints are temporarily unavailable.
      boolean failHard = Boolean.parseBoolean(
          System.getProperty("trustsign.crlFailHard", "false")
      );
      if (failHard) {
        throw new SecurityException("CRL check failed: " + e.getMessage(), e);
      }
    }
  }

  private static boolean isRevokedByCrl(X509Certificate cert, String crlUrl) throws Exception {
    URL url = new URL(crlUrl);
    try (InputStream in = url.openStream()) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509CRL crl = (X509CRL) cf.generateCRL(in);
      return crl.isRevoked(cert);
    }
  }

  /**
   * Validates the certificate (and optional chain) against a trust store / system trust
   * using the default X509TrustManager implementation.
   */
  private static void validateTrustChain(X509Certificate leaf, X509Certificate[] chain) {
    try {
      X509Certificate[] toValidate;
      if (chain != null && chain.length > 0) {
        toValidate = chain;
      } else {
        toValidate = new X509Certificate[]{leaf};
      }

      KeyStore trustStore = loadTrustStoreIfConfigured();

      TrustManagerFactory tmf = TrustManagerFactory.getInstance(
          TrustManagerFactory.getDefaultAlgorithm()
      );
      if (trustStore != null) {
        tmf.init(trustStore);
      } else {
        tmf.init((KeyStore) null); // system default
      }

      X509TrustManager x509Tm = null;
      for (TrustManager tm : tmf.getTrustManagers()) {
        if (tm instanceof X509TrustManager xtm) {
          x509Tm = xtm;
          break;
        }
      }
      if (x509Tm == null) {
        throw new SecurityException("No X509TrustManager available for path validation");
      }

      // Use "RSA" as the authType for typical RSA/ECDSA signing certs; implementation
      // usually ignores the exact string but requires it to be non-empty.
      x509Tm.checkServerTrusted(toValidate, "RSA");
    } catch (SecurityException se) {
      throw se;
    } catch (Exception e) {
      throw new SecurityException("Certificate path validation failed: " + e.getMessage(), e);
    }
  }

  /**
   * Loads a custom trust store when configured, otherwise returns null.
   */
  private static KeyStore loadTrustStoreIfConfigured() throws Exception {
    String path = System.getProperty("trustsign.truststore.path");
    if (path == null || path.isBlank()) {
      return null;
    }
    String type = System.getProperty("trustsign.truststore.type", KeyStore.getDefaultType());
    String password = System.getProperty("trustsign.truststore.password", "");

    KeyStore ks = KeyStore.getInstance(type);
    try (FileInputStream fis = new FileInputStream(path)) {
      char[] pwd = password.isEmpty() ? null : password.toCharArray();
      ks.load(fis, pwd);
    }
    return ks;
  }

  private CertificateValidator() {}
}

