package com.trustsign.tools;

import com.trustsign.core.TextVerifyService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * One-off tool to discover which exact content bytes Icegate (or any signed file) signed.
 * Run: ./gradlew test --tests "com.trustsign.tools.DiscoverSignedContentFormat" -Ddiscover.signed.file=g:/pki/testncodeSigned.txt
 * Or run main with file path as first arg.
 */
public final class DiscoverSignedContentFormat {

  public static void main(String[] args) throws Exception {
    String path = args.length > 0 ? args[0] : System.getProperty("discover.signed.file");
    if (path == null || path.isBlank()) {
      System.err.println("Usage: DiscoverSignedContentFormat <path-to-signed-file>");
      System.err.println("   or: -Ddiscover.signed.file=<path>");
      return;
    }
    String content = Files.readString(Paths.get(path), StandardCharsets.UTF_8);
    discover(content);
  }

  public static void discover(String signedText) throws Exception {
    discover(signedText, signedText.substring(0, signedText.indexOf("<START-SIGNATURE>")).getBytes(StandardCharsets.UTF_8));
  }

  /** Call with raw bytes that appear before <START-SIGNATURE> in the file (to try CRLF etc). */
  public static void discover(String signedText, byte[] rawContentBeforeSig) throws Exception {
    int sigStart = signedText.indexOf("<START-SIGNATURE>");
    int certStart = signedText.indexOf("<START-CERTIFICATE>");
    if (sigStart < 0 || certStart < 0) {
      System.out.println("No signature/certificate markers found");
      return;
    }
    String textBeforeSig = signedText.substring(0, sigStart);
    String sigB64 = between(signedText, "<START-SIGNATURE>", "</START-SIGNATURE>");
    String certB64 = between(signedText, "<START-CERTIFICATE>", "</START-CERTIFICATE>");
    if (sigB64 == null || certB64 == null) {
      System.out.println("Missing signature or certificate block");
      return;
    }
    byte[] sigBytes = Base64.getDecoder().decode(sigB64.trim());
    byte[] certBytes = Base64.getDecoder().decode(certB64.trim());
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    PublicKey publicKey = cert.getPublicKey();

    StringBuilder out = new StringBuilder();
    out.append("Content before <START-SIGNATURE> length: ").append(textBeforeSig.length()).append(" chars, ").append(textBeforeSig.getBytes(StandardCharsets.UTF_8).length).append(" bytes\n");
    out.append("Signature algorithm: SHA256withRSA only\n\n");

    String[] variants = {
        "exact (as in file)",
        "strip trailing \\n",
        "strip trailing \\r\\n",
        "normalize \\r\\n to \\n then use",
        "normalize then strip trailing \\n",
        "raw bytes from file (before sig)",
    };
    byte[][] variantBytes = {
        textBeforeSig.getBytes(StandardCharsets.UTF_8),
        textBeforeSig.endsWith("\n") ? textBeforeSig.substring(0, textBeforeSig.length() - 1).getBytes(StandardCharsets.UTF_8) : null,
        textBeforeSig.endsWith("\r\n") ? textBeforeSig.substring(0, textBeforeSig.length() - 2).getBytes(StandardCharsets.UTF_8) : null,
        textBeforeSig.replace("\r\n", "\n").replace("\r", "\n").getBytes(StandardCharsets.UTF_8),
        textBeforeSig.replace("\r\n", "\n").replace("\r", "\n").replaceAll("\n$", "").getBytes(StandardCharsets.UTF_8),
        rawContentBeforeSig,
    };

    String algo = "SHA256withRSA";
    for (int i = 0; i < variants.length; i++) {
      if (variantBytes[i] == null) continue;
      try {
        Signature sig = Signature.getInstance(algo);
        sig.initVerify(publicKey);
        sig.update(variantBytes[i]);
        boolean ok = sig.verify(sigBytes);
        out.append(ok ? "  VERIFIES: " : "  no:       ").append(algo).append(" + ").append(variants[i]).append(" (").append(variantBytes[i].length).append(" bytes)\n");
      } catch (Exception ignored) {}
    }

    TextVerifyService.Result r = TextVerifyService.verify(signedText);
    out.append("\nTextVerifyService.verify() result: ").append(r.ok()).append(" - ").append(r.reason()).append("\n");
    String result = out.toString();
    System.out.print(result);
    // Also write to file for CI/scripting
    String reportPath = System.getProperty("discover.report.path");
    if (reportPath != null && !reportPath.isBlank()) {
      java.nio.file.Files.writeString(java.nio.file.Paths.get(reportPath), result, StandardCharsets.UTF_8);
    }
  }

  private static String between(String text, String start, String end) {
    int s = text.indexOf(start);
    int e = text.indexOf(end);
    if (s < 0 || e < 0 || e <= s) return null;
    return text.substring(s + start.length(), e);
  }
}
