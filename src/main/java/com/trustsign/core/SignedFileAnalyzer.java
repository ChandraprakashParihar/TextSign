package com.trustsign.core;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Analyzes a signed file (e.g. Icegate format) by trying multiple verification
 * strategies (algorithm × content interpretation) and reports which ones succeed.
 * Use this to discover exactly what the signer hashed and signed.
 */
public final class SignedFileAnalyzer {

  public record VerifiedMatch(String algorithm, String contentVariant, int contentLengthBytes) {}
  public record Attempt(String algorithm, String contentVariant, int contentLengthBytes, boolean verified) {}

  public record Result(
      String formatDetected,
      Boolean cmsVerifyOk,
      String cmsVerifyReason,
      boolean standardVerifyOk,
      String standardVerifyReason,
      int contentBeforeSignatureChars,
      int contentBeforeSignatureBytes,
      List<VerifiedMatch> verifiedMatches,
      List<Attempt> attempts,
      String signerSubjectDN,
      String signerSerialNumberHex
  ) {}

  private static final String[] CONTENT_VARIANTS = {
      "exact (as in file)",
      "strip trailing \\n",
      "strip trailing \\r\\n",
      "normalize \\r\\n to \\n",
      "normalize then strip trailing \\n",
      "raw bytes from file (before sig)",
  };

  private static final String[] ALGORITHMS = { "SHA256withRSA" };

  /**
   * Analyzes the given signed file content. Detects CMS format (START-CMS-SIGNATURE)
   * or raw format (START-SIGNATURE / START-CERTIFICATE) and runs the appropriate verification.
   */
  public static Result analyze(String signedText, byte[] rawContentBeforeSig) throws Exception {
    int cmsStart = signedText.indexOf("<START-CMS-SIGNATURE>");
    if (cmsStart >= 0) {
      return analyzeCmsFormat(signedText, rawContentBeforeSig, cmsStart);
    }
    return analyzeRawFormat(signedText, rawContentBeforeSig);
  }

  private static Result analyzeCmsFormat(String signedText, byte[] rawContentBeforeSig, int cmsTagStart) throws Exception {
    String cmsB64 = between(signedText, "<START-CMS-SIGNATURE>", "</START-CMS-SIGNATURE>");
    if (cmsB64 == null || cmsB64.isBlank()) {
      throw new IllegalArgumentException("Empty <START-CMS-SIGNATURE> block");
    }
    byte[] cmsBytes = Base64.getDecoder().decode(cmsB64.trim());
    byte[] contentBytes = rawContentBeforeSig != null && rawContentBeforeSig.length > 0
        ? rawContentBeforeSig
        : signedText.substring(0, cmsTagStart).getBytes(StandardCharsets.UTF_8);
    CmsVerifyService.Result cmsResult = CmsVerifyService.verify(contentBytes, cmsBytes);
    String signerDN = cmsResult.signerCert() != null ? cmsResult.signerCert().getSubjectX500Principal().getName() : null;
    String signerSerial = cmsResult.signerCert() != null ? cmsResult.signerCert().getSerialNumber().toString(16) : null;
    return new Result(
        "cms",
        cmsResult.ok(),
        cmsResult.reason(),
        cmsResult.ok(),
        cmsResult.reason(),
        signedText.substring(0, cmsTagStart).length(),
        contentBytes.length,
        List.of(),
        List.of(),
        signerDN,
        signerSerial
    );
  }

  private static Result analyzeRawFormat(String signedText, byte[] rawContentBeforeSig) throws Exception {
    int sigStart = signedText.indexOf("<START-SIGNATURE>");
    int certStart = signedText.indexOf("<START-CERTIFICATE>");
    if (sigStart < 0 || certStart < 0) {
      throw new IllegalArgumentException("Missing <START-SIGNATURE> or <START-CERTIFICATE> markers (and no <START-CMS-SIGNATURE> found)");
    }

    String textBeforeSig = signedText.substring(0, sigStart);
    String sigB64 = between(signedText, "<START-SIGNATURE>", "</START-SIGNATURE>");
    String certB64 = between(signedText, "<START-CERTIFICATE>", "</START-CERTIFICATE>");
    if (sigB64 == null || certB64 == null) {
      throw new IllegalArgumentException("Empty signature or certificate block");
    }

    byte[] sigBytes = Base64.getDecoder().decode(sigB64.trim());
    byte[] certBytes = Base64.getDecoder().decode(certB64.trim());
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    PublicKey publicKey = cert.getPublicKey();

    byte[][] variantBytes = buildContentVariants(textBeforeSig, rawContentBeforeSig != null ? rawContentBeforeSig : textBeforeSig.getBytes(StandardCharsets.UTF_8));

    List<VerifiedMatch> verifiedMatches = new ArrayList<>();
    List<Attempt> attempts = new ArrayList<>();

    for (String algo : ALGORITHMS) {
      for (int i = 0; i < CONTENT_VARIANTS.length; i++) {
        if (variantBytes[i] == null) continue;
        try {
          Signature sig = Signature.getInstance(algo);
          sig.initVerify(publicKey);
          sig.update(variantBytes[i]);
          boolean ok = sig.verify(sigBytes);
          attempts.add(new Attempt(algo, CONTENT_VARIANTS[i], variantBytes[i].length, ok));
          if (ok) {
            verifiedMatches.add(new VerifiedMatch(algo, CONTENT_VARIANTS[i], variantBytes[i].length));
          }
        } catch (Exception ignored) {
          // skip unsupported algorithm
        }
      }
    }

    TextVerifyService.Result standardResult = TextVerifyService.verify(signedText.getBytes(StandardCharsets.UTF_8));

    return new Result(
        "raw",
        null,
        null,
        standardResult.ok(),
        standardResult.reason(),
        textBeforeSig.length(),
        textBeforeSig.getBytes(StandardCharsets.UTF_8).length,
        verifiedMatches,
        attempts,
        cert.getSubjectX500Principal().getName(),
        cert.getSerialNumber().toString(16)
    );
  }

  /**
   * Analyzes using only the UTF-8 decoded content before signature (no separate raw bytes).
   */
  public static Result analyze(String signedText) throws Exception {
    int sigStart = signedText.indexOf("<START-SIGNATURE>");
    byte[] rawBeforeSig = sigStart > 0
        ? signedText.substring(0, sigStart).getBytes(StandardCharsets.UTF_8)
        : new byte[0];
    return analyze(signedText, rawBeforeSig);
  }

  private static byte[][] buildContentVariants(String textBeforeSig, byte[] rawContentBeforeSig) {
    return new byte[][] {
        textBeforeSig.getBytes(StandardCharsets.UTF_8),
        textBeforeSig.endsWith("\n") ? textBeforeSig.substring(0, textBeforeSig.length() - 1).getBytes(StandardCharsets.UTF_8) : null,
        textBeforeSig.endsWith("\r\n") ? textBeforeSig.substring(0, textBeforeSig.length() - 2).getBytes(StandardCharsets.UTF_8) : null,
        textBeforeSig.replace("\r\n", "\n").replace("\r", "\n").getBytes(StandardCharsets.UTF_8),
        textBeforeSig.replace("\r\n", "\n").replace("\r", "\n").replaceAll("\n$", "").getBytes(StandardCharsets.UTF_8),
        rawContentBeforeSig,
    };
  }

  private static String between(String text, String start, String end) {
    int s = text.indexOf(start);
    int e = text.indexOf(end);
    if (s < 0 || e < 0 || e <= s) return null;
    return text.substring(s + start.length(), e);
  }

  private SignedFileAnalyzer() {}
}
