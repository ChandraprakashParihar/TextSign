package com.trustsign.core;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;

/**
 * Verifies text signatures in the custom format:
 *
 * <original text>
 * <START-SIGNATURE>base64(PKCS#7)</START-SIGNATURE>
 * <START-CERTIFICATE>base64(cert)</START-CERTIFICATE>
 * <SIGNER-VERSION>...</SIGNER-VERSION>
 */
public final class TextVerifyService {
  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public record Result(boolean ok, String reason) {}

  public static Result verify(String signedText) {
    if (signedText == null || signedText.isEmpty()) {
      return new Result(false, "Signed text is empty");
    }
    try {
      int sigStart = signedText.indexOf("<START-SIGNATURE>");
      int sigEnd = signedText.indexOf("</START-SIGNATURE>");
      int certStart = signedText.indexOf("<START-CERTIFICATE>");
      int certEnd = signedText.indexOf("</START-CERTIFICATE>");

      if (sigStart < 0 || sigEnd < 0 || certStart < 0 || certEnd < 0) {
        return new Result(false, "Signature markers not found");
      }

      String textBeforeSig = signedText.substring(0, sigStart);

      String sigB64 = between(signedText, "<START-SIGNATURE>", "</START-SIGNATURE>");
      String certB64 = between(signedText, "<START-CERTIFICATE>", "</START-CERTIFICATE>");
      if (sigB64 == null || sigB64.isBlank()) return new Result(false, "Empty signature block");
      if (certB64 == null || certB64.isBlank()) return new Result(false, "Empty certificate block");

      byte[] sigBytes = Base64.getDecoder().decode(sigB64);
      byte[] certBytes = Base64.getDecoder().decode(certB64);

      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));

      // Try verifying with and without a trailing newline to tolerate editor differences.
      String[] candidates;
      if (textBeforeSig.endsWith("\n")) {
        String stripped = textBeforeSig.substring(0, textBeforeSig.length() - 1);
        candidates = new String[]{textBeforeSig, stripped};
      } else {
        candidates = new String[]{textBeforeSig};
      }

      for (int i = 0; i < candidates.length; i++) {
        String originalText = candidates[i];
        try {
          CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(
              originalText.getBytes(java.nio.charset.StandardCharsets.UTF_8)), sigBytes);

          SignerInformationStore signers = signedData.getSignerInfos();
          Collection<SignerInformation> c = signers.getSigners();
          if (c.isEmpty()) return new Result(false, "No signer information in signature");

          SignerInformation signer = c.iterator().next();
          boolean ok = signer.verify(new org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder()
              .setProvider("BC")
              .build(cert));
          if (ok) return new Result(true, "Signature valid");
        } catch (CMSSignerDigestMismatchException e) {
          if (i == candidates.length - 1) {
            return new Result(false, "Digest mismatch: content has been modified");
          }
        }
      }

      return new Result(false, "Signature invalid");
    } catch (Exception e) {
      String msg = e.getMessage();
      if (msg == null || msg.isBlank()) msg = e.getClass().getSimpleName();
      return new Result(false, msg);
    }
  }

  private static String between(String text, String startTag, String endTag) {
    int s = text.indexOf(startTag);
    int e = text.indexOf(endTag);
    if (s < 0 || e < 0 || e <= s) return null;
    return text.substring(s + startTag.length(), e).trim();
  }

  private TextVerifyService() {}
}

