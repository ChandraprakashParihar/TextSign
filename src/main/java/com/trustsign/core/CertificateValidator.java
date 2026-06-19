package com.trustsign.core;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
  private static final Logger LOG = LoggerFactory.getLogger(CertificateValidator.class);
  private static final long TRUSTSTORE_STAT_TTL_MS = 60_000L;
  private static volatile KeyStore cachedTrustStore;
  private static volatile String cachedTrustStoreCacheKey;
  private static volatile long cachedTrustStoreMtime = -1L;
  private static volatile long cachedTrustStoreCheckedAtMs = 0L;

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
  private static final String OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
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
    try {
      X509Certificate[] normalized = normalizeProvidedChain(leaf, chain);
      if (normalized.length > 0) {
        X509Certificate terminal = normalized[normalized.length - 1];
        if (isSelfSigned(terminal)) {
          return terminal;
        }
      }
    } catch (Exception ignored) {
    }
    try {
      KeyStore trustStore = loadTrustStoreIfConfigured();
      if (trustStore == null) {
        return null;
      }
      List<X509Certificate> expectedIssuers = buildExpectedIssuerPathFromTrustStore(leaf, trustStore);
      if (!expectedIssuers.isEmpty()) {
        return expectedIssuers.get(expectedIssuers.size() - 1);
      }
    } catch (Exception ignored) {
    }
    return null;
  }

  private static String getSubjectKeyIdentifierHex(X509Certificate cert) {
    byte[] extVal = cert.getExtensionValue(OID_SUBJECT_KEY_IDENTIFIER);
    if (extVal == null) {
      return null;
    }
    try {
      byte[] octets = ASN1OctetString.getInstance(
          ASN1Primitive.fromByteArray(extractExtensionOctets(extVal))).getOctets();
      if (octets == null || octets.length == 0) return null;
      return HexFormat.of().formatHex(octets);
    } catch (Exception e) {
      return null;
    }
  }

  private static String getAuthorityKeyIdentifierHex(X509Certificate cert) {
    byte[] extVal = cert.getExtensionValue(OID_AUTHORITY_KEY_IDENTIFIER);
    if (extVal == null) {
      return null;
    }
    try {
      AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(
          ASN1Primitive.fromByteArray(extractExtensionOctets(extVal)));
      byte[] keyId = aki == null ? null : aki.getKeyIdentifier();
      if (keyId == null || keyId.length == 0) {
        return null;
      }
      return HexFormat.of().formatHex(keyId);
    } catch (Exception e) {
      return null;
    }
  }

  private static byte[] extractExtensionOctets(byte[] extVal) throws Exception {
    return ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extVal)).getOctets();
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
      ASN1Primitive derObj = ASN1Primitive.fromByteArray(extractExtensionOctets(extVal));
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
          extractExtensionOctets(extVal)
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
    URLConnection conn = new URL(crlUrl).openConnection();
    conn.setConnectTimeout(10_000);
    conn.setReadTimeout(15_000);
    try (InputStream in = conn.getInputStream()) {
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
      validateStrictChainAgainstTrustStore(leaf, chain);
    } catch (SecurityException se) {
      throw se;
    } catch (Exception e) {
      throw new SecurityException("Certificate path validation failed: " + e.getMessage(), e);
    }
  }

  /**
   * Strictly validates the provided chain against the configured trust store.
   *
   * Rules enforced:
   * - configured truststore must exist
   * - provided chain must include leaf certificate as first element
   * - every certificate in chain must be valid in time window
   * - every adjacent certificate must verify issuer signature
   * - chain must exactly match the issuer path present in truststore
   * - no missing or extra certificates are allowed
   */
  public static void validateStrictChainAgainstTrustStore(X509Certificate leaf, X509Certificate[] chain) {
    if (leaf == null) {
      throw new SecurityException("Signing certificate is missing");
    }
    try {
      KeyStore trustStore = loadTrustStoreIfConfigured();
      if (trustStore == null) {
        throw new SecurityException("Strict chain validation requires configured truststore");
      }
      X509Certificate[] provided = normalizeProvidedChain(leaf, chain);
      validateProvidedChainOrderSignaturesAndValidity(provided);
      List<X509Certificate> expectedIssuers = buildExpectedIssuerPathFromTrustStore(leaf, trustStore);
      X509Certificate[] resolved = mergeWithExpectedIssuers(provided, expectedIssuers);
      validateProvidedChainOrderSignaturesAndValidity(resolved);
      boolean strictExact = Boolean.parseBoolean(System.getProperty("trustsign.strictExactChainMatch", "false"));
      if (strictExact) {
        enforceExactChainMatch(provided, expectedIssuers);
      }

      X509Certificate root = resolved[resolved.length - 1];
      if (!isSelfSigned(root)) {
        throw new SecurityException("Resolved chain root is not self-signed");
      }
      LOG.info("Strict certificate chain validation successful: subject='{}', chainLength={}, root='{}'",
          leaf.getSubjectX500Principal().getName(),
          resolved.length,
          root.getSubjectX500Principal().getName());
    } catch (SecurityException se) {
      LOG.warn("Strict certificate chain validation failed: subject='{}', reason={}",
          leaf.getSubjectX500Principal().getName(), se.getMessage());
      throw se;
    } catch (Exception e) {
      throw new SecurityException("Certificate path validation failed: " + e.getMessage(), e);
    }
  }

  private static X509Certificate[] normalizeProvidedChain(X509Certificate leaf, X509Certificate[] chain) {
    List<X509Certificate> candidates = new ArrayList<>();
    candidates.add(leaf);
    if (chain != null) {
      for (X509Certificate cert : chain) {
        if (cert != null && !containsEquivalent(candidates, cert)) {
          candidates.add(cert);
        }
      }
    }
    List<X509Certificate> ordered = new ArrayList<>();
    Set<String> seen = new HashSet<>();
    X509Certificate current = leaf;
    ordered.add(current);
    seen.add(certificateFingerprint(current));
    while (true) {
      X509Certificate issuer = findIssuerInCollection(current, candidates);
      if (issuer == null) {
        break;
      }
      String fp = certificateFingerprint(issuer);
      if (!seen.add(fp)) {
        break;
      }
      ordered.add(issuer);
      current = issuer;
      if (isSelfSigned(current)) {
        break;
      }
      if (ordered.size() > 32) {
        throw new SecurityException("Unexpected certificate chain depth; possible loop");
      }
    }
    return ordered.toArray(new X509Certificate[0]);
  }

  private static void validateProvidedChainOrderSignaturesAndValidity(X509Certificate[] chain) {
    for (int i = 0; i < chain.length; i++) {
      X509Certificate cert = chain[i];
      try {
        cert.checkValidity();
      } catch (Exception e) {
        throw new SecurityException("Certificate in chain is not currently valid at position " + i + ": " + e.getMessage(), e);
      }
      if (i < chain.length - 1) {
        X509Certificate issuer = chain[i + 1];
        if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
          throw new SecurityException("Issuer mismatch between chain certificates at positions " + i + " and " + (i + 1));
        }
        try {
          cert.verify(issuer.getPublicKey());
        } catch (Exception e) {
          throw new SecurityException("Signature verification failed between chain certificates at positions " + i + " and " + (i + 1) + ": " + e.getMessage(), e);
        }
      }
    }
  }

  private static List<X509Certificate> buildExpectedIssuerPathFromTrustStore(X509Certificate leaf, KeyStore trustStore) throws Exception {
    List<X509Certificate> path = new ArrayList<>();
    X509Certificate current = leaf;
    while (true) {
      X509Certificate issuer = findIssuerInTrustStore(current, trustStore);
      if (issuer == null) {
        throw new SecurityException("Issuer certificate not present in truststore for subject: " + current.getSubjectX500Principal().getName());
      }
      path.add(issuer);
      if (isSelfSigned(issuer)) {
        break;
      }
      current = issuer;
      if (path.size() > 16) {
        throw new SecurityException("Unexpected truststore issuer path depth; possible loop");
      }
    }
    return path;
  }

  private static X509Certificate[] mergeWithExpectedIssuers(X509Certificate[] provided, List<X509Certificate> expectedIssuers) {
    List<X509Certificate> merged = new ArrayList<>();
    merged.add(provided[0]); // leaf
    for (int i = 0; i < expectedIssuers.size(); i++) {
      X509Certificate expected = expectedIssuers.get(i);
      int providedIndex = i + 1;
      if (providedIndex < provided.length) {
        X509Certificate actual = provided[providedIndex];
        if (!expected.equals(actual)) {
          throw new SecurityException("Provided chain certificate mismatch at position " + providedIndex +
              ": expected subject='" + expected.getSubjectX500Principal().getName() +
              "', actual subject='" + actual.getSubjectX500Principal().getName() + "'");
        }
        merged.add(actual);
      } else {
        merged.add(expected);
      }
    }
    return merged.toArray(new X509Certificate[0]);
  }

  private static void enforceExactChainMatch(X509Certificate[] provided, List<X509Certificate> expectedIssuers) {
    int expectedLength = expectedIssuers.size() + 1; // plus leaf cert
    if (provided.length != expectedLength) {
      throw new SecurityException("Chain length mismatch: provided=" + provided.length + ", expected=" + expectedLength);
    }
    for (int i = 0; i < expectedIssuers.size(); i++) {
      X509Certificate expected = expectedIssuers.get(i);
      X509Certificate actual = provided[i + 1];
      if (!expected.equals(actual)) {
        throw new SecurityException("Chain certificate mismatch at position " + (i + 1) +
            ": expected subject='" + expected.getSubjectX500Principal().getName() +
            "', actual subject='" + actual.getSubjectX500Principal().getName() + "'");
      }
    }
  }

  private static X509Certificate findIssuerInTrustStore(X509Certificate cert, KeyStore trustStore) throws Exception {
    var issuerDn = cert.getIssuerX500Principal();
    List<X509Certificate> candidates = new ArrayList<>();
    Enumeration<String> aliases = trustStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement();
      Certificate c = trustStore.getCertificate(alias);
      if (c instanceof X509Certificate x509 && x509.getSubjectX500Principal().equals(issuerDn)) {
        candidates.add(x509);
      }
    }
    return selectBestIssuerCandidate(cert, candidates);
  }

  private static X509Certificate findIssuerInCollection(X509Certificate cert, List<X509Certificate> collection) {
    if (cert == null || collection == null || collection.isEmpty()) {
      return null;
    }
    var issuerDn = cert.getIssuerX500Principal();
    List<X509Certificate> candidates = new ArrayList<>();
    for (X509Certificate candidate : collection) {
      if (candidate == null || cert.equals(candidate)) {
        continue;
      }
      if (candidate.getSubjectX500Principal().equals(issuerDn)) {
        candidates.add(candidate);
      }
    }
    return selectBestIssuerCandidate(cert, candidates);
  }

  private static X509Certificate selectBestIssuerCandidate(X509Certificate cert, List<X509Certificate> candidates) {
    if (candidates == null || candidates.isEmpty()) {
      return null;
    }
    String authorityKeyId = getAuthorityKeyIdentifierHex(cert);
    X509Certificate best = null;
    int bestScore = Integer.MIN_VALUE;
    for (X509Certificate candidate : candidates) {
      try {
        cert.verify(candidate.getPublicKey());
      } catch (Exception e) {
        continue;
      }
      int score = 0;
      String subjectKeyId = getSubjectKeyIdentifierHex(candidate);
      if (authorityKeyId != null && subjectKeyId != null
          && authorityKeyId.equalsIgnoreCase(subjectKeyId)) {
        score += 4;
      }
      boolean[] ku = candidate.getKeyUsage();
      if (ku == null || safeIndex(ku, 5)) { // keyCertSign
        score += 1;
      }
      if (isSelfSigned(candidate)) {
        score += 1;
      }
      if (best == null || score > bestScore
          || (score == bestScore && candidate.getNotAfter().after(best.getNotAfter()))) {
        best = candidate;
        bestScore = score;
      }
    }
    return best;
  }

  private static boolean isSelfSigned(X509Certificate cert) {
    if (cert == null || !cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
      return false;
    }
    try {
      cert.verify(cert.getPublicKey());
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static boolean containsEquivalent(List<X509Certificate> list, X509Certificate cert) {
    String target = certificateFingerprint(cert);
    for (X509Certificate x : list) {
      if (target.equals(certificateFingerprint(x))) {
        return true;
      }
    }
    return false;
  }

  private static String certificateFingerprint(X509Certificate cert) {
    try {
      byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
      return HexFormat.of().formatHex(digest);
    } catch (Exception e) {
      return Integer.toHexString(System.identityHashCode(cert));
    }
  }

  /**
   * Looks up the issuer of {@code signer} in the configured trust store (same properties as path validation).
   * Returns null when no trust store is configured, or no entry matches the signer's issuer DN.
   */
  public static X509Certificate findIssuerInConfiguredTruststore(X509Certificate signer) throws Exception {
    if (signer == null) {
      return null;
    }
    KeyStore ks = loadTrustStoreIfConfigured();
    if (ks == null) {
      return null;
    }
    return findIssuerInTrustStore(signer, ks);
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
    String cacheKey = path.trim() + "|" + type.trim() + "|" + password;
    File truststoreFile = new File(path.trim());
    long now = System.currentTimeMillis();
    KeyStore current = cachedTrustStore;
    if (current != null
        && cacheKey.equals(cachedTrustStoreCacheKey)
        && (now - cachedTrustStoreCheckedAtMs) < TRUSTSTORE_STAT_TTL_MS) {
      return current;
    }

    synchronized (CertificateValidator.class) {
      KeyStore inside = cachedTrustStore;
      long nowInside = System.currentTimeMillis();
      if (inside != null
          && cacheKey.equals(cachedTrustStoreCacheKey)
          && (nowInside - cachedTrustStoreCheckedAtMs) < TRUSTSTORE_STAT_TTL_MS) {
        return inside;
      }

      if (!truststoreFile.exists()) {
        throw new SecurityException("Configured truststore file not found: " + truststoreFile.getAbsolutePath());
      }

      verifyTruststoreIntegrity(truststoreFile);

      long mtime = truststoreFile.lastModified();
      if (inside != null
          && cacheKey.equals(cachedTrustStoreCacheKey)
          && mtime == cachedTrustStoreMtime) {
        cachedTrustStoreCheckedAtMs = nowInside;
        return inside;
      }

      KeyStore ks = KeyStore.getInstance(type);
      try (FileInputStream fis = new FileInputStream(truststoreFile)) {
        char[] pwd = password.isEmpty() ? null : password.toCharArray();
        ks.load(fis, pwd);
      }
      cachedTrustStore = ks;
      cachedTrustStoreCacheKey = cacheKey;
      cachedTrustStoreMtime = mtime;
      cachedTrustStoreCheckedAtMs = nowInside;
      LOG.info("Reloaded truststore from disk: {}", truststoreFile.getAbsolutePath());
      return ks;
    }
  }

  private static final String TRUSTSTORE_HMAC_KEY = "TrustSign-TS-Integrity-V1-b7d4e2";
  private static final String TRUSTSTORE_HMAC_FILE = ".truststore-integrity";
  private static volatile long hmacVerifiedMtime = -1L;
  private static volatile String hmacVerifiedPath = null;

  /**
   * Verifies the truststore file against an HMAC stored alongside it.
   * The HMAC uses an application secret (embedded in the obfuscated JAR),
   * so the client cannot forge a valid HMAC for a tampered truststore.
   * The /map-certificate endpoint recomputes the HMAC after modifying the truststore.
   */
  private static void verifyTruststoreIntegrity(File truststoreFile) {
    String path = truststoreFile.getAbsolutePath();
    long mtime = truststoreFile.lastModified();
    if (path.equals(hmacVerifiedPath) && mtime == hmacVerifiedMtime) {
      return;
    }

    File hmacFile = new File(truststoreFile.getParentFile(), TRUSTSTORE_HMAC_FILE);
    if (!hmacFile.exists()) {
      LOG.debug("No truststore HMAC file found — skipping integrity check");
      hmacVerifiedPath = path;
      hmacVerifiedMtime = mtime;
      return;
    }
    try {
      String expected = java.nio.file.Files.readString(hmacFile.toPath(),
          java.nio.charset.StandardCharsets.UTF_8).trim();
      if (expected.isEmpty()) {
        hmacVerifiedPath = path;
        hmacVerifiedMtime = mtime;
        return;
      }

      String actual = computeTruststoreHmac(truststoreFile);
      if (!java.security.MessageDigest.isEqual(
          expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
          actual.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
        LOG.error("TRUSTSTORE INTEGRITY FAILURE: file={}", truststoreFile.getAbsolutePath());
        throw new SecurityException("Truststore file has been tampered with or replaced.");
      }
      hmacVerifiedPath = path;
      hmacVerifiedMtime = mtime;
      LOG.debug("Truststore integrity verified");
    } catch (SecurityException e) {
      throw e;
    } catch (Exception e) {
      throw new SecurityException("Failed to verify truststore integrity: " + e.getMessage(), e);
    }
  }

  /**
   * Computes HMAC-SHA256 of the truststore file using the application secret.
   */
  public static String computeTruststoreHmac(File truststoreFile) throws Exception {
    byte[] keyBytes = java.security.MessageDigest.getInstance("SHA-256")
        .digest(TRUSTSTORE_HMAC_KEY.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256"));
    try (FileInputStream fis = new FileInputStream(truststoreFile)) {
      byte[] buf = new byte[8192];
      int read;
      while ((read = fis.read(buf)) != -1) { mac.update(buf, 0, read); }
    }
    return java.util.HexFormat.of().formatHex(mac.doFinal());
  }

  /**
   * Writes (or updates) the HMAC file for a truststore. Called by /map-certificate
   * after modifying the truststore, and by the build process during initial packaging.
   */
  public static void writeTruststoreHmac(File truststoreFile) throws Exception {
    String hmac = computeTruststoreHmac(truststoreFile);
    File hmacFile = new File(truststoreFile.getParentFile(), TRUSTSTORE_HMAC_FILE);
    java.nio.file.Files.writeString(hmacFile.toPath(), hmac + "\n",
        java.nio.charset.StandardCharsets.UTF_8);
    LOG.info("Truststore HMAC updated: {}", hmacFile.getAbsolutePath());
  }

  public static Map<String, Object> cacheStats() {
    Map<String, Object> out = new java.util.LinkedHashMap<>();
    out.put("truststoreCached", cachedTrustStore != null);
    out.put("truststoreCacheKey", cachedTrustStoreCacheKey);
    out.put("truststoreLastModifiedMs", cachedTrustStoreMtime);
    out.put("truststoreLastCheckedAtMs", cachedTrustStoreCheckedAtMs);
    out.put("truststoreStatTtlMs", TRUSTSTORE_STAT_TTL_MS);
    return out;
  }

  private CertificateValidator() {}
}

