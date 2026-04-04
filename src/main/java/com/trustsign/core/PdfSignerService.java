package com.trustsign.core;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * PAdES-style PDF signing (visible stamp + PKCS#7 detached) using a caller-supplied key and provider (e.g. SunPKCS11).
 */
public final class PdfSignerService {

  /**
   * Key material and provider required to produce the embedded PKCS#7 signature.
   */
  public record PdfSigningMaterial(
      PrivateKey privateKey,
      Certificate[] certificateChain,
      Provider cryptoProvider,
      X509Certificate signingCertificate) {

    public PdfSigningMaterial {
      if (privateKey == null) {
        throw new IllegalArgumentException("privateKey is null");
      }
      if (certificateChain == null || certificateChain.length == 0) {
        throw new IllegalArgumentException("certificateChain is empty");
      }
      if (cryptoProvider == null) {
        throw new IllegalArgumentException("cryptoProvider is null");
      }
      if (signingCertificate == null) {
        throw new IllegalArgumentException("signingCertificate is null");
      }
    }

    /** Chain as {@link X509Certificate} entries only, or null if the chain does not start with an X.509 certificate. */
    public X509Certificate[] x509ChainOrNull() {
      if (!(certificateChain[0] instanceof X509Certificate)) {
        return null;
      }
      return Stream.of(certificateChain)
          .filter(X509Certificate.class::isInstance)
          .map(X509Certificate.class::cast)
          .toArray(X509Certificate[]::new);
    }
  }

  private static final Logger LOG = Logger.getLogger(PdfSignerService.class.getName());
  private static final DateTimeFormatter TS_FMT = DateTimeFormatter
      .ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")
      .withZone(ZoneOffset.UTC);

  public static byte[] signPdf(
      byte[] pdfBytes,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider,
      X509Certificate signingCert,
      String reason,
      String location,
      List<Integer> stampPageIndices) throws Exception {
    return signPdf(
        pdfBytes,
        new PdfSigningMaterial(privateKey, chain, p11Provider, signingCert),
        reason,
        location,
        stampPageIndices);
  }

  public static byte[] signPdf(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      List<Integer> stampPageIndices) throws Exception {
    requireNonEmptyPdf(pdfBytes);

    try (PDDocument doc = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
      if (doc.getNumberOfPages() == 0) {
        throw new IllegalArgumentException("PDF has no pages");
      }

      Instant now = Instant.now();
      addVisualSignatureStamp(doc, material.signingCertificate(), now, reason, location, stampPageIndices);

      PDSignature signature = new PDSignature();
      applySignatureMetadata(signature, material.signingCertificate(), reason, location);

      SignatureInterface sigImpl = content -> {
        try {
          return TextSignerService.signDetached(
              content.readAllBytes(),
              material.privateKey(),
              material.certificateChain(),
              material.cryptoProvider());
        } catch (Exception e) {
          throw new java.io.IOException("PDF signature generation failed", e);
        }
      };

      SignatureOptions options = new SignatureOptions();
      options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
      doc.addSignature(signature, sigImpl, options);

      try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
        doc.save(out);
        return out.toByteArray();
      } finally {
        options.close();
      }
    }
  }

  private static void requireNonEmptyPdf(byte[] pdfBytes) {
    if (pdfBytes == null || pdfBytes.length == 0) {
      throw new IllegalArgumentException("pdfBytes is empty");
    }
  }

  private static void applySignatureMetadata(
      PDSignature signature,
      X509Certificate signingCert,
      String reason,
      String location) {
    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
    signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
    signature.setName(signingCert.getSubjectX500Principal().getName());
    if (reason != null && !reason.isBlank()) {
      signature.setReason(reason.trim());
    } else {
      signature.setReason("TrustSign digital signature");
    }
    if (location != null && !location.isBlank()) {
      signature.setLocation(location.trim());
    }
    signature.setSignDate(java.util.Calendar.getInstance());
  }

  private static void addVisualSignatureStamp(
      PDDocument doc,
      X509Certificate cert,
      Instant signedAt,
      String reason,
      String location,
      List<Integer> stampPageIndices) throws Exception {
    String subject = extractDisplaySubject(cert);
    String when = TS_FMT.format(signedAt);

    List<Integer> resolvedPages = resolveStampPages(doc, stampPageIndices);
    if (Boolean.getBoolean("trustsign.debugPdfStamp")) {
      LOG.info("PDF stamp pages resolved: " + resolvedPages);
    }
    for (Integer pageIndex : resolvedPages) {
      PDPage page = doc.getPage(pageIndex);
      PDRectangle mediaBox = page.getMediaBox();

      float boxWidth = (float) (mediaBox.getWidth() * 0.3);
      float boxHeight = (float) (mediaBox.getHeight() * 0.08);
      float margin = 24f;
      float contentPad = 4f;
      float x = mediaBox.getUpperRightX() - boxWidth - margin;
      float y = margin;
      float contentLeftX = x + contentPad;
      float contentTopY = y + boxHeight - contentPad;

      float markerCenterX = x + (boxWidth / 2f);
      float markerCenterY = y + (boxHeight * 0.58f);

      try (PDPageContentStream cs = new PDPageContentStream(
          doc,
          page,
          PDPageContentStream.AppendMode.APPEND,
          true,
          true)) {
        cs.setStrokingColor(0.1f, 0.55f, 0.2f);
        cs.setLineWidth(1.5f);
        cs.addRect(x, y, boxWidth, boxHeight);
        cs.stroke();

        cs.setNonStrokingColor(0.1f, 0.65f, 0.22f);
        cs.setLineWidth(3.2f);
        cs.moveTo(markerCenterX - 12f, markerCenterY + 2f);
        cs.lineTo(markerCenterX - 3f, markerCenterY - 9f);
        cs.lineTo(markerCenterX + 13f, markerCenterY + 10f);
        cs.stroke();

        writeLineBold(cs, "Signature Verified", contentLeftX, contentTopY - 9f);

        float textY = contentTopY - 20f;
        for (String line : wrapSubjectLines(subject, 40)) {
          writeLine(cs, line, x + contentPad, textY);
          textY -= 6.5f;
        }
        float detailsTopY = Math.max(y + contentPad + 8f, textY - 0.5f);
        writeLine(cs, when, x + contentPad, detailsTopY);
        float footerY = detailsTopY - 6.5f;
        if (reason != null && !reason.isBlank()) {
          writeLine(cs, "Reason: " + reason.trim(), x + contentPad, footerY);
          footerY -= 6.5f;
        }
        if (location != null && !location.isBlank()) {
          writeLine(cs, "Location: " + location.trim(), x + contentPad, footerY);
          footerY -= 6.5f;
        }
        writeLine(cs, "Verified by TrustSign", x + contentPad, footerY);
      }
    }
  }

  private static List<Integer> resolveStampPages(PDDocument doc, List<Integer> stampPageIndices) {
    int pageCount = doc.getNumberOfPages();
    if (stampPageIndices == null || stampPageIndices.isEmpty()) {
      return List.of(0);
    }
    if (stampPageIndices.contains(-1)) {
      List<Integer> all = new ArrayList<>();
      for (int i = 0; i < pageCount; i++) {
        all.add(i);
      }
      return all;
    }
    Set<Integer> unique = new LinkedHashSet<>();
    for (Integer idx : stampPageIndices) {
      if (idx == null) {
        continue;
      }
      if (idx >= 0 && idx < pageCount) {
        unique.add(idx);
      }
    }
    if (unique.isEmpty()) {
      return List.of(0);
    }
    return new ArrayList<>(unique);
  }

  private static void writeLine(PDPageContentStream cs, String value, float x, float y) throws Exception {
    cs.beginText();
    cs.setFont(PDType1Font.HELVETICA, 7f);
    cs.setNonStrokingColor(0f, 0f, 0f);
    cs.newLineAtOffset(x, y);
    cs.showText(value);
    cs.endText();
  }

  private static void writeLineBold(PDPageContentStream cs, String value, float x, float y) throws Exception {
    cs.beginText();
    cs.setFont(PDType1Font.HELVETICA_BOLD, 8f);
    cs.setNonStrokingColor(0f, 0f, 0f);
    cs.newLineAtOffset(x, y);
    cs.showText(value);
    cs.endText();
  }

  private static List<String> wrapSubjectLines(String value, int maxCharsPerLine) {
    List<String> lines = new ArrayList<>();
    if (value == null || value.isBlank()) {
      lines.add("Subject:");
      return lines;
    }
    String[] words = value.trim().split("\\s+");
    StringBuilder current = new StringBuilder();
    for (String word : words) {
      if (current.isEmpty()) {
        current.append(word);
        continue;
      }
      if (current.length() + 1 + word.length() <= maxCharsPerLine) {
        current.append(" ").append(word);
      } else {
        lines.add(current.toString());
        current = new StringBuilder(word);
      }
    }
    if (!current.isEmpty()) {
      lines.add(current.toString());
    }
    return lines;
  }

  private static String extractDisplaySubject(X509Certificate cert) {
    String dn = cert.getSubjectX500Principal().getName();
    for (String part : dn.split(",")) {
      String p = part.trim();
      if (p.regionMatches(true, 0, "CN=", 0, 3)) {
        String cn = p.substring(3).trim();
        return cn.isBlank() ? dn : cn;
      }
    }
    return dn;
  }

  private PdfSignerService() {}
}
