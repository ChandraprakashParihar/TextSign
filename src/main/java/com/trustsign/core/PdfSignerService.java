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
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

public final class PdfSignerService {
  private static final DateTimeFormatter TS_FMT = DateTimeFormatter
      .ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")
      .withZone(ZoneOffset.UTC);

  public static byte[] signPdf(
      byte[] pdfBytes,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider,
      X509Certificate signingCert) throws Exception {
    if (pdfBytes == null || pdfBytes.length == 0) {
      throw new IllegalArgumentException("pdfBytes is empty");
    }
    if (privateKey == null) {
      throw new IllegalArgumentException("privateKey is null");
    }
    if (chain == null || chain.length == 0) {
      throw new IllegalArgumentException("certificate chain is empty");
    }
    if (p11Provider == null) {
      throw new IllegalArgumentException("p11Provider is null");
    }
    if (signingCert == null) {
      throw new IllegalArgumentException("signingCert is null");
    }

    try (PDDocument doc = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
      if (doc.getNumberOfPages() == 0) {
        throw new IllegalArgumentException("PDF has no pages");
      }

      Instant now = Instant.now();
      addVisualSignatureStamp(doc, signingCert, now);

      PDSignature signature = new PDSignature();
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
      signature.setName(signingCert.getSubjectX500Principal().getName());
      signature.setReason("TrustSign digital signature");
      signature.setSignDate(java.util.Calendar.getInstance());

      SignatureInterface sigImpl = new SignatureInterface() {
        @Override
        public byte[] sign(InputStream content) throws java.io.IOException {
          try {
            byte[] signedContent = content.readAllBytes();
            return TextSignerService.signDetached(signedContent, privateKey, chain, p11Provider);
          } catch (Exception e) {
            throw new java.io.IOException("PDF signature generation failed", e);
          }
        }
      };

      SignatureOptions options = new SignatureOptions();
      options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
      doc.addSignature(signature, sigImpl, options);

      try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
        doc.saveIncremental(out);
        return out.toByteArray();
      } finally {
        options.close();
      }
    }
  }

  private static void addVisualSignatureStamp(PDDocument doc, X509Certificate cert, Instant signedAt) throws Exception {
    PDPage firstPage = doc.getPage(0);
    PDRectangle mediaBox = firstPage.getMediaBox();

    float boxWidth = 250f;
    float boxHeight = 95f;
    float margin = 24f;
    float x = mediaBox.getUpperRightX() - boxWidth - margin;
    float y = margin;

    String subject = cert.getSubjectX500Principal().getName();
    String serial = cert.getSerialNumber().toString(16);
    String when = TS_FMT.format(signedAt);

    try (PDPageContentStream cs = new PDPageContentStream(
        doc,
        firstPage,
        PDPageContentStream.AppendMode.APPEND,
        true,
        true)) {
      cs.setStrokingColor(0.1f, 0.55f, 0.2f);
      cs.setLineWidth(1.5f);
      cs.addRect(x, y, boxWidth, boxHeight);
      cs.stroke();

      cs.setNonStrokingColor(0.1f, 0.65f, 0.22f);
      cs.setLineWidth(3f);
      cs.moveTo(x + 14f, y + 56f);
      cs.lineTo(x + 24f, y + 44f);
      cs.lineTo(x + 40f, y + 66f);
      cs.stroke();

      cs.beginText();
      cs.setNonStrokingColor(0f, 0f, 0f);
      cs.setFont(PDType1Font.HELVETICA_BOLD, 10f);
      cs.newLineAtOffset(x + 50f, y + 72f);
      cs.showText("Digitally Signed");
      cs.endText();

      writeLine(cs, "Subject: " + trim(subject, 38), x + 12f, y + 56f);
      writeLine(cs, "Serial: " + trim(serial, 38), x + 12f, y + 44f);
      writeLine(cs, "Date: " + when, x + 12f, y + 32f);
      writeLine(cs, "Verified by TrustSign", x + 12f, y + 20f);
    }
  }

  private static void writeLine(PDPageContentStream cs, String value, float x, float y) throws Exception {
    cs.beginText();
    cs.setFont(PDType1Font.HELVETICA, 8f);
    cs.setNonStrokingColor(0f, 0f, 0f);
    cs.newLineAtOffset(x, y);
    cs.showText(value);
    cs.endText();
  }

  private static String trim(String v, int max) {
    if (v == null) {
      return "";
    }
    if (v.length() <= max) {
      return v;
    }
    return v.substring(0, Math.max(0, max - 3)) + "...";
  }

  private PdfSignerService() {}
}
