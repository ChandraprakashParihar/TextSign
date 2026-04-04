package com.trustsign.core;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSInteger;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * PAdES-style PDF signing (visible stamp + PKCS#7 detached) using a
 * caller-supplied key and provider (e.g. SunPKCS11).
 * When {@code pdfBytes} already contains a completed signature, the new
 * signature is appended with an incremental save
 * (earlier signatures remain); the visible stamp is applied only on the first
 * signature pass.
 * Optional {@linkplain PdfSigningOptions#finalVersion() final version} adds
 * metadata, a visible FINAL banner, and
 * (when this is the first signature on the document) a DocMDP transform with
 * P=1 so compliant viewers treat further
 * edits as invalidating the signature.
 */
public final class PdfSignerService {

  public static final String FINAL_VERSION_KEYWORD = "TrustSign:FinalVersion=true";
  public static final String FINAL_VERSION_REASON_SUFFIX = " | FINAL VERSION (no modifications permitted)";
  private static final COSName TRANSFORM_PARAMS_TYPE = COSName.getPDFName("TransformParams");
  private static final COSName MDP_P = COSName.getPDFName("P");
  private static final COSName MDP_V = COSName.getPDFName("V");

  /**
   * @param finalVersion When true, document is marked finalized (metadata +
   *                     stamp; DocMDP P=1 when allowed by PDF rules).
   */
  public record PdfSigningOptions(boolean finalVersion) {
    public static final PdfSigningOptions DEFAULT = new PdfSigningOptions(false);
  }

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

    /**
     * Chain as {@link X509Certificate} entries only, or null if the chain does not
     * start with an X.509 certificate.
     */
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
        stampPageIndices,
        PdfSigningOptions.DEFAULT);
  }

  public static byte[] signPdf(
      byte[] pdfBytes,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider,
      X509Certificate signingCert,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      PdfSigningOptions options) throws Exception {
    return signPdf(
        pdfBytes,
        new PdfSigningMaterial(privateKey, chain, p11Provider, signingCert),
        reason,
        location,
        stampPageIndices,
        options);
  }

  public static byte[] signPdf(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      List<Integer> stampPageIndices) throws Exception {
    return signPdf(pdfBytes, material, reason, location, stampPageIndices, PdfSigningOptions.DEFAULT);
  }

  public static byte[] signPdf(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      PdfSigningOptions options) throws Exception {
    requireNonEmptyPdf(pdfBytes);
    PdfSigningOptions opts = options == null ? PdfSigningOptions.DEFAULT : options;

    try (PDDocument doc = PDDocument.load(pdfBytes)) {
      if (doc.getNumberOfPages() == 0) {
        throw new IllegalArgumentException("PDF has no pages");
      }

      boolean priorSigs = documentHasCompletedPriorSignatures(doc);

      if (opts.finalVersion()) {
        applyFinalVersionDocumentMetadata(doc);
      }

      Instant now = Instant.now();
      // Second+ signatures on the same file: add crypto only; avoid stacking
      // duplicate visible stamps.
      if (!priorSigs) {
        addVisualSignatureStamp(
            doc,
            material.signingCertificate(),
            now,
            reason,
            location,
            stampPageIndices,
            opts.finalVersion());
      }

      PDSignature signature = new PDSignature();
      applySignatureMetadata(signature, material.signingCertificate(), reason, location, opts.finalVersion());

      if (opts.finalVersion()) {
        if (!priorSigs) {
          attachDocMdpNoChangesPermitted(signature);
        } else if (Boolean.getBoolean("trustsign.logFinalVersion")) {
          LOG.info(
              "Final version requested but PDF already had signatures; DocMDP P=1 omitted (incremental signature only).");
        }
      }

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

      SignatureOptions signatureOptions = new SignatureOptions();
      signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
      doc.addSignature(signature, sigImpl, signatureOptions);

      try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
        doc.saveIncremental(out);
        return out.toByteArray();
      } finally {
        signatureOptions.close();
      }
    }
  }

  private static void requireNonEmptyPdf(byte[] pdfBytes) {
    if (pdfBytes == null || pdfBytes.length == 0) {
      throw new IllegalArgumentException("pdfBytes is empty");
    }
  }

  /**
   * DocMDP P=1: no document changes permitted without invalidating the signature
   * (ISO 32000, compliant viewers).
   */
  private static void attachDocMdpNoChangesPermitted(PDSignature signature) {
    COSDictionary refEntry = new COSDictionary();
    refEntry.setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP);
    COSDictionary params = new COSDictionary();
    params.setItem(COSName.TYPE, TRANSFORM_PARAMS_TYPE);
    params.setItem(MDP_P, COSInteger.get(1));
    params.setItem(MDP_V, COSName.getPDFName("1.2"));
    refEntry.setItem(COSName.TRANSFORM_PARAMS, params);
    COSArray refs = new COSArray();
    refs.add(refEntry);
    signature.getCOSObject().setItem(COSName.REFERENCE, refs);
  }

  private static boolean documentHasCompletedPriorSignatures(PDDocument doc) throws IOException {
    PDAcroForm form = doc.getDocumentCatalog().getAcroForm(null);
    if (form == null) {
      return false;
    }
    for (Iterator<PDField> it = form.getFieldIterator(); it.hasNext();) {
      PDField f = it.next();
      if (f instanceof PDSignatureField sf) {
        PDSignature existing = sf.getSignature();
        if (existing != null) {
          byte[] contents = existing.getContents();
          // PKCS#7 blobs are large; empty/placeholder fields are usually padding only.
          if (contents != null && contents.length > 256) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private static void applyFinalVersionDocumentMetadata(PDDocument doc) throws IOException {
    PDDocumentInformation di = doc.getDocumentInformation();
    if (di == null) {
      di = new PDDocumentInformation();
    }
    String kw = di.getKeywords();
    if (kw == null || kw.isBlank()) {
      di.setKeywords(FINAL_VERSION_KEYWORD);
    } else if (!kw.contains("TrustSign:FinalVersion")) {
      di.setKeywords(kw.trim() + "; " + FINAL_VERSION_KEYWORD);
    }
    String subj = di.getSubject();
    String tag = "FINAL VERSION";
    if (subj == null || subj.isBlank()) {
      di.setSubject(tag);
    } else if (!subj.contains(tag)) {
      di.setSubject(subj.trim() + " - " + tag);
    }
    doc.setDocumentInformation(di);
    di.getCOSObject().setNeedToBeUpdated(true);
    doc.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
  }

  private static void applySignatureMetadata(
      PDSignature signature,
      X509Certificate signingCert,
      String reason,
      String location,
      boolean finalVersion) {
    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
    signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
    signature.setName(signingCert.getSubjectX500Principal().getName());
    if (reason != null && !reason.isBlank()) {
      signature.setReason(
          finalVersion ? reason.trim() + FINAL_VERSION_REASON_SUFFIX : reason.trim());
    } else {
      signature.setReason(
          finalVersion ? "TrustSign digital signature" + FINAL_VERSION_REASON_SUFFIX : "TrustSign digital signature");
    }
    if (location != null && !location.isBlank()) {
      signature.setLocation(location.trim());
    }
    if (finalVersion) {
      signature.setContactInfo("TrustSign: This document is a FINAL VERSION. Alterations invalidate the signature.");
    }
    signature.setSignDate(java.util.Calendar.getInstance());
  }

  private static void addVisualSignatureStamp(
      PDDocument doc,
      X509Certificate cert,
      Instant signedAt,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      boolean finalVersion) throws Exception {
    String subject = extractDisplaySubject(cert);
    String when = TS_FMT.format(signedAt);

    List<Integer> resolvedPages = resolveStampPages(doc, stampPageIndices);
    if (Boolean.getBoolean("trustsign.debugPdfStamp")) {
      LOG.info("PDF stamp pages resolved: " + resolvedPages);
    }
    for (Integer pageIndex : resolvedPages) {
      PDPage page = doc.getPage(pageIndex);
      // Use crop box (visible area); media box can be larger so a bottom-right stamp
      // would be off-page on some PDFs.
      PDRectangle visible = page.getCropBox();
      float vx = visible.getLowerLeftX();
      float vy = visible.getLowerLeftY();
      float vW = visible.getWidth();
      float vH = visible.getHeight();

      float boxWidth = (float) (vW * 0.34);
      float boxHeight = (float) (vH * (finalVersion ? 0.14 : 0.08));
      float margin = 24f;
      float contentPad = 4f;
      float x = vx + vW - boxWidth - margin;
      float y = vy + margin;
      float contentLeftX = x + contentPad;
      float contentTopY = y + boxHeight - contentPad;
      /**
       * Keep body text left of this x so the checkmark does not overlap (timestamp,
       * etc.).
       */
      float textRightMargin = x + boxWidth - 26f;

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

        float cursorY = contentTopY - 6f;
        if (finalVersion) {
          // addRect(x, y, w, h) uses lower-left (x,y); y increases upward.
          float bannerH = 22f;
          float bannerBottomY = cursorY - bannerH;
          cs.setStrokingColor(0.55f, 0.08f, 0.08f);
          cs.setLineWidth(1.25f);
          cs.addRect(x + 2f, bannerBottomY, boxWidth - 4f, bannerH);
          cs.stroke();
          writeLineBoldRed(cs, "FINAL VERSION", contentLeftX, bannerBottomY + 14f);
          writeLineSmall(cs, "No further edits permitted; changes invalidate signature.", contentLeftX,
              bannerBottomY + 4f);
          cursorY = bannerBottomY - 6f;
        } else {
          cursorY = contentTopY - 9f;
        }

        writeLineBold(cs, "Signature Verified", contentLeftX, cursorY);

        float textY = cursorY - 11f;
        for (String line : wrapSubjectLines(subject, 36)) {
          writeLineClamped(cs, line, contentLeftX, textY, textRightMargin);
          textY -= 6.5f;
        }
        // textY is the next line slot; last drawn baseline was textY + 6.5
        float detailsTopY = Math.max(y + contentPad + 8f, textY - 3f);
        writeLineClamped(cs, when, contentLeftX, detailsTopY, textRightMargin);
        float footerY = detailsTopY - 6.5f;
        if (reason != null && !reason.isBlank()) {
          writeLineClamped(cs, "Reason: " + reason.trim(), contentLeftX, footerY, textRightMargin);
          footerY -= 6.5f;
        }
        if (location != null && !location.isBlank()) {
          writeLineClamped(cs, "Location: " + location.trim(), contentLeftX, footerY, textRightMargin);
          footerY -= 6.5f;
        }
        writeLineClamped(cs, "Verified by TrustSign", contentLeftX, footerY, textRightMargin);

        // Small checkmark in upper-right; drawn last so it does not sit under body
        // text.
        float cx = x + boxWidth - 18f;
        float cy = finalVersion ? contentTopY - 10f : contentTopY - 8f;
        cs.setStrokingColor(0.1f, 0.65f, 0.22f);
        cs.setLineWidth(2.2f);
        cs.moveTo(cx - 8f, cy);
        cs.lineTo(cx - 2f, cy - 6f);
        cs.lineTo(cx + 9f, cy + 7f);
        cs.stroke();
      }
      // Incremental save only follows objects marked for update from the catalog;
      // without this,
      // appended page content (the visible stamp) can be dropped while the signature
      // is still embedded.
      markPageRootPathForIncrementalSave(page);
    }
  }

  /**
   * Marks this page and its ancestors in the page tree so
   * {@link PDDocument#saveIncremental} writes
   * content stream changes (see PDFBox javadoc: closed update path from catalog
   * to page).
   */
  private static void markPageRootPathForIncrementalSave(PDPage page) {
    page.getCOSObject().setNeedToBeUpdated(true);
    COSDictionary parent = page.getCOSObject().getCOSDictionary(COSName.PARENT);
    while (parent != null) {
      parent.setNeedToBeUpdated(true);
      parent = parent.getCOSDictionary(COSName.PARENT);
    }
  }

  private static void writeLineSmall(PDPageContentStream cs, String value, float fx, float fy) throws IOException {
    cs.beginText();
    cs.setFont(PDType1Font.HELVETICA, 6f);
    cs.setNonStrokingColor(0.2f, 0.2f, 0.2f);
    cs.newLineAtOffset(fx, fy);
    cs.showText(truncateForPdfShowText(value, 90));
    cs.endText();
  }

  private static void writeLineBoldRed(PDPageContentStream cs, String value, float fx, float fy) throws IOException {
    cs.beginText();
    cs.setFont(PDType1Font.HELVETICA_BOLD, 8f);
    cs.setNonStrokingColor(0.55f, 0f, 0f);
    cs.newLineAtOffset(fx, fy);
    cs.showText(truncateForPdfShowText(value, 48));
    cs.endText();
  }

  /** PDFWinAnsiEncoding: keep to basic Latin for Type1 fonts. */
  private static String truncateForPdfShowText(String value, int maxChars) {
    if (value == null) {
      return "";
    }
    String v = value.length() > maxChars ? value.substring(0, maxChars) + "..." : value;
    StringBuilder sb = new StringBuilder(v.length());
    for (int i = 0; i < v.length(); i++) {
      char c = v.charAt(i);
      if (c >= 32 && c <= 126) {
        sb.append(c);
      } else {
        sb.append('?');
      }
    }
    return sb.toString();
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

  private static void writeLineClamped(PDPageContentStream cs, String value, float fx, float fy, float maxX)
      throws IOException {
    int maxChars = Math.max(10, (int) ((maxX - fx) / 3.6f));
    cs.beginText();
    cs.setFont(PDType1Font.HELVETICA, 7f);
    cs.setNonStrokingColor(0f, 0f, 0f);
    cs.newLineAtOffset(fx, fy);
    cs.showText(truncateForPdfShowText(value, maxChars));
    cs.endText();
  }

  private static void writeLineBold(PDPageContentStream cs, String value, float fx, float fy) throws IOException {
    cs.beginText();
    cs.setFont(PDType1Font.HELVETICA_BOLD, 8f);
    cs.setNonStrokingColor(0f, 0f, 0f);
    cs.newLineAtOffset(fx, fy);
    cs.showText(truncateForPdfShowText(value, 48));
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

  private PdfSignerService() {
  }
}
