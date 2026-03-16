package com.trustsign.core;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;

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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * Helper for validating signing certificates from the token.
 *
 * Currently performs:
 * - validity period checks
 * - optional key usage checks (is signing allowed)
 * - optional CRL-based revocation checks (via CRL distribution points)
 * - optional trust-chain validation
 * - optional CCA ROOT SKI validation (root CA Subject Key Identifier must be in allowed list)
 * - optional class validation (certificate policy OID must be in allowed list)
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
   * - trustsign.enableCcaRootSkiCheck (default: false); when true, root CA SKI must be in trustsign.allowedRootSkis
   * - trustsign.allowedRootSkis (comma-separated hex Subject Key Identifiers of allowed root CAs, e.g. CCA India)
   * - trustsign.enableClassValidation (default: false); when true, cert must contain a policy OID in trustsign.allowedCertificatePolicyOids
   * - trustsign.allowedCertificatePolicyOids (comma-separated OIDs, e.g. India PKI Class 2/3 policy OIDs)
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

    boolean enableCcaRootSkiCheck = Boolean.parseBoolean(
        System.getProperty("trustsign.enableCcaRootSkiCheck", "false")
    );
    if (enableCcaRootSkiCheck) {
      validateCcaRootSki(cert, chain);
    }

    boolean enableClassValidation = Boolean.parseBoolean(
        System.getProperty("trustsign.enableClassValidation", "false")
    );
    if (enableClassValidation) {
      validateClass(cert);
    }
  }

  private static final String OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
  private static final String OID_CERTIFICATE_POLICIES = "2.5.29.32";

  /**
   * Validates that the root CA of the certificate chain has a Subject Key Identifier
   * that is in the allowed list (e.g. CCA India root SKI). Requires chain to be present.
   */
  private static void validateCcaRootSki(X509Certificate leaf, X509Certificate[] chain) {
    X509Certificate root = getRootCertificate(leaf, chain);
    if (root == null) {
      throw new SecurityException("CCA ROOT SKI validation requires a certificate chain");
    }
    String rootSkiHex = getSubjectKeyIdentifierHex(root);
    if (rootSkiHex == null || rootSkiHex.isEmpty()) {
      throw new SecurityException("Root certificate has no Subject Key Identifier (SKI)");
    }
    String allowed = System.getProperty("trustsign.allowedRootSkis", "").trim();
    if (allowed.isEmpty()) {
      throw new SecurityException("CCA ROOT SKI check is enabled but trustsign.allowedRootSkis is not set");
    }
    List<String> allowedSkis = parseCommaSeparatedHex(allowed);
    String normalizedRootSki = rootSkiHex.toUpperCase(Locale.ROOT);
    for (String a : allowedSkis) {
      if (a.toUpperCase(Locale.ROOT).equals(normalizedRootSki)) {
        return;
      }
    }
    throw new SecurityException("Root CA Subject Key Identifier is not in the allowed list (CCA ROOT SKI validation failed)");
  }

  /**
   * Validates that the signing certificate contains at least one certificate policy OID
   * from the allowed list (e.g. India PKI Class 2 or Class 3).
   */
  private static void validateClass(X509Certificate cert) {
    List<String> policyOids = getCertificatePolicyOids(cert);
    String allowed = System.getProperty("trustsign.allowedCertificatePolicyOids", "").trim();
    if (allowed.isEmpty()) {
      throw new SecurityException("Class validation is enabled but trustsign.allowedCertificatePolicyOids is not set");
    }
    List<String> allowedOids = Arrays.asList(allowed.split("\\s*,\\s*"));
    for (String oid : policyOids) {
      if (allowedOids.contains(oid)) {
        return;
      }
    }
    throw new SecurityException(
        "Certificate does not contain an allowed certificate policy OID (class validation failed). " +
            "Present policies: " + policyOids + "; allowed: " + allowedOids);
  }

  private static X509Certificate getRootCertificate(X509Certificate leaf, X509Certificate[] chain) {
    if (chain != null && chain.length > 0) {
      return chain[chain.length - 1];
    }
    return null;
  }

  private static String getSubjectKeyIdentifierHex(X509Certificate cert) {
    byte[] extVal = cert.getExtensionValue(OID_SUBJECT_KEY_IDENTIFIER);
    if (extVal == null) return null;
    try {
      byte[] octets = ASN1OctetString.getInstance(extVal).getOctets();
      if (octets == null || octets.length == 0) return null;
      return HexFormat.of().formatHex(octets);
    } catch (Exception e) {
      return null;
    }
  }

  private static List<String> parseCommaSeparatedHex(String allowed) {
    List<String> out = new ArrayList<>();
    for (String s : allowed.split("\\s*,\\s*")) {
      String t = s.trim();
      if (t.isEmpty()) continue;
      out.add(t);
    }
    return out;
  }

  private static List<String> getCertificatePolicyOids(X509Certificate cert) {
    List<String> oids = new ArrayList<>();
    byte[] extVal = cert.getExtensionValue(OID_CERTIFICATE_POLICIES);
    if (extVal == null) return oids;
    try {
      ASN1Primitive derObj = ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(extVal).getOctets());
      CertificatePolicies policies = CertificatePolicies.getInstance(derObj);
      if (policies == null) return oids;
      for (PolicyInformation info : policies.getPolicyInformation()) {
        if (info != null && info.getPolicyIdentifier() != null) {
          oids.add(info.getPolicyIdentifier().getId());
        }
      }
    } catch (Exception ignored) {
      // return empty list on parse error
    }
    return oids;
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

      // Use client-style validation for signing certificates.
      // Many trust managers applying TLS rules enforce Extended Key Usage
      // for client/server auth; for pure signing certificates we ignore
      // those specific EKU errors while still enforcing chain validity.
      try {
        x509Tm.checkClientTrusted(toValidate, "RSA");
      } catch (Exception e) {
        String msg = e.getMessage();
        if (msg != null &&
            (msg.contains("Extended key usage does not permit use for TLS client authentication")
                || msg.contains("Extended key usage does not permit use for TLS server authentication"))) {
          // Treat EKU-for-TLS-only complaints as non-fatal for signing use cases.
          return;
        }
        throw e;
      }
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

