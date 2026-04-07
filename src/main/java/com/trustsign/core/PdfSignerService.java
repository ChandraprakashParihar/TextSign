package com.trustsign.core;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSInteger;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

import java.awt.Color;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * ISO 32000 digital signatures with {@code adbe.pkcs7.detached} (PKCS#7/CMS)
 * and a
 * <strong>visible signature field</strong> using PDFBox’s standard template
 * flow
 * ({@link SignatureOptions#setVisualSignature(InputStream)}), matching common
 * tools
 * (Apache PDFBox examples / typical Acrobat-style widgets).
 * <p>
 * Each signing pass adds one new signature via incremental update. Re-signing
 * draws
 * another widget at the same default position (bottom-right of the chosen
 * page).
 * Optional {@linkplain PdfSigningOptions#finalVersion() final version} adds
 * metadata,
 * a FINAL banner in the appearance, and (when allowed) DocMDP {@code P=1} on
 * the
 * first signature only.
 */
public final class PdfSignerService {

  public static final String FINAL_VERSION_KEYWORD = "TrustSign:FinalVersion=true";
  public static final String FINAL_VERSION_REASON_SUFFIX = " | FINAL VERSION (no modifications permitted)";
  private static final COSName TRANSFORM_PARAMS_TYPE = COSName.getPDFName("TransformParams");
  private static final COSName MDP_P = COSName.getPDFName("P");
  private static final COSName MDP_V = COSName.getPDFName("V");

  /**
   * @param finalVersion            When true, document is marked finalized
   *                                (metadata +
   *                                stamp; DocMDP P=1 when allowed by PDF rules).
   * @param allowResignFinalVersion When true, allows signing a PDF that already
   *                                has a completed signature
   *                                with ISO 32000 DocMDP {@code P=1} (no document
   *                                changes permitted) from any
   *                                product; default blocks re-sign unless this
   *                                override is set.
   */
  public record PdfSigningOptions(boolean finalVersion, boolean allowResignFinalVersion) {
    public static final PdfSigningOptions DEFAULT = new PdfSigningOptions(false, false);

    public PdfSigningOptions(boolean finalVersion) {
      this(finalVersion, false);
    }
  }

  /**
   * Thrown when the PDF already contains a completed signature whose dictionary
   * declares DocMDP
   * {@code P=1} (ISO 32000: no document changes without invalidating that
   * signature), and the request
   * did not set {@link PdfSigningOptions#allowResignFinalVersion()}.
   */
  public static final class DocMdpNoChangesLockException extends IllegalArgumentException {
    public DocMdpNoChangesLockException() {
      super(
          "This PDF is certified or locked with DocMDP P=1 (ISO 32000: no document changes permitted). ");
    }
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

      if (documentHasDocMdpP1LockFromCompletedSignature(doc) && !opts.allowResignFinalVersion()) {
        throw new DocMdpNoChangesLockException();
      }

      boolean priorSigs = documentHasCompletedPriorSignatures(doc);

      if (opts.finalVersion()) {
        applyFinalVersionDocumentMetadata(doc);
      }

      maybeClearNeedAppearancesIfSafe(doc);

      List<Integer> resolvedPages = resolveStampPages(doc, stampPageIndices);
      int signaturePageIndex = resolvedPages.get(0);
      PDRectangle widgetRect = computeSignatureWidgetRect(doc, signaturePageIndex, opts.finalVersion());

      PDSignature signature = new PDSignature();
      applySignatureMetadata(signature, material.signingCertificate(), reason, location, opts.finalVersion());

      if (opts.finalVersion()) {
        if (!priorSigs) {
          attachDocMdpNoChangesPermitted(doc, signature);
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
      try (InputStream visTemplate = createStandardVisibleSignatureTemplate(
          doc,
          signaturePageIndex,
          widgetRect,
          signature,
          material.signingCertificate(),
          opts.finalVersion())) {
        signatureOptions.setVisualSignature(visTemplate);
        signatureOptions.setPage(signaturePageIndex);
        doc.addSignature(signature, sigImpl, signatureOptions);
      }

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
  private static void attachDocMdpNoChangesPermitted(PDDocument doc, PDSignature signature) {
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

    // ISO 32000 certification link: Catalog /Perms /DocMDP must point to this
    // signature dictionary so viewers enforce no-change certification.
    COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
    COSDictionary perms = catalog.getCOSDictionary(COSName.PERMS);
    if (perms == null) {
      perms = new COSDictionary();
      catalog.setItem(COSName.PERMS, perms);
    }
    perms.setItem(COSName.DOCMDP, signature);
    perms.setNeedToBeUpdated(true);
    catalog.setNeedToBeUpdated(true);
  }

  /**
   * True when {@code /Contents} looks like a real PKCS#7/CMS signature (DER), not
   * an empty signature field
   * whose {@code /Contents} is a long buffer of zero bytes (common in “sign
   * later” templates).
   */
  private static boolean signatureContentsLookSigned(byte[] contents) {
    if (contents == null || contents.length < 128) {
      return false;
    }
    // /Contents can be DER bytes padded with trailing zeros, and sometimes has leading
    // zeros depending on writer/reservation behavior. Detect the first non-zero byte.
    int firstNonZero = -1;
    for (int i = 0; i < contents.length; i++) {
      if (contents[i] != 0) {
        firstNonZero = i;
        break;
      }
    }
    if (firstNonZero < 0) {
      return false;
    }
    // CMS SignedData / PKCS#7 is a DER SEQUENCE (tag 0x30).
    return contents[firstNonZero] == (byte) 0x30;
  }

  /**
   * ISO 32000 DocMDP: any <em>completed</em> prior signature whose
   * {@code Reference} array contains
   * {@code /TransformMethod /DocMDP} with transform params {@code P=1} (no
   * document changes permitted).
   * Applies regardless of signing product (Adobe, TrustSign, etc.).
   */
  private static boolean documentHasDocMdpP1LockFromCompletedSignature(PDDocument doc) throws IOException {
    for (PDSignature existing : doc.getSignatureDictionaries()) {
      if (existing == null) {
        continue;
      }
      byte[] contents = existing.getContents();
      if (!signatureContentsLookSigned(contents)) {
        continue;
      }
      if (signatureHasDocMdpP1(existing)) {
        return true;
      }
    }
    return false;
  }

  private static boolean signatureHasDocMdpP1(PDSignature sig) {
    COSArray refs = sig.getCOSObject().getCOSArray(COSName.REFERENCE);
    if (refs == null) {
      return false;
    }
    for (int i = 0; i < refs.size(); i++) {
      COSDictionary refDict = asCosDictionary(refs.get(i));
      if (refDict == null) {
        continue;
      }
      if (!COSName.DOCMDP.equals(refDict.getCOSName(COSName.TRANSFORM_METHOD))) {
        continue;
      }
      COSDictionary params = refDict.getCOSDictionary(COSName.TRANSFORM_PARAMS);
      if (params == null) {
        continue;
      }
      int p = params.getInt(MDP_P, -1);
      if (p == 1) {
        return true;
      }
    }
    return false;
  }

  private static COSDictionary asCosDictionary(COSBase base) {
    if (base instanceof COSDictionary d) {
      return d;
    }
    if (base instanceof COSObject obj) {
      COSBase resolved = obj.getObject();
      return resolved instanceof COSDictionary d ? d : null;
    }
    return null;
  }

  private static boolean documentHasCompletedPriorSignatures(PDDocument doc) throws IOException {
    for (PDSignature existing : doc.getSignatureDictionaries()) {
      if (existing == null) {
        continue;
      }
      byte[] contents = existing.getContents();
      if (signatureContentsLookSigned(contents)) {
        return true;
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

  /**
   * PDFBox / Adobe Reader: {@code /NeedAppearances true} can hide or distort
   * visible signatures
   * (PDFBOX-3738). Remove only when the form has no fields yet.
   */
  private static void maybeClearNeedAppearancesIfSafe(PDDocument doc) {
    PDAcroForm acroForm = doc.getDocumentCatalog().getAcroForm(null);
    if (acroForm != null && acroForm.getNeedAppearances()) {
      if (acroForm.getFields().isEmpty()) {
        acroForm.getCOSObject().removeItem(COSName.NEED_APPEARANCES);
      } else {
        LOG.warning(
            "AcroForm /NeedAppearances is true; visible signature may not display correctly in some viewers");
      }
    }
  }

  /**
   * Widget rectangle in page space (lower-left origin), bottom-right of crop box
   * — same footprint as before.
   */
  private static PDRectangle computeSignatureWidgetRect(PDDocument doc, int pageIndex, boolean finalVersion) {
    PDPage page = doc.getPage(pageIndex);
    PDRectangle visible = page.getCropBox();
    float vx = visible.getLowerLeftX();
    float vy = visible.getLowerLeftY();
    float vW = visible.getWidth();
    float vH = visible.getHeight();
    // Keep default size close to common utility signatures, but leave enough
    // vertical room so all appearance lines remain visible (especially FINAL mode).
    float boxWidth = Math.max(190f, Math.min((float) (vW * 0.26), 250f));
    float boxHeight = finalVersion
        ? Math.max(78f, Math.min((float) (vH * 0.12), 108f))
        : Math.max(56f, Math.min((float) (vH * 0.075), 78f));
    float margin = 24f;
    float x = vx + vW - boxWidth - margin;
    float y = vy + margin;
    PDRectangle rect = new PDRectangle();
    rect.setLowerLeftX(x);
    rect.setLowerLeftY(y);
    rect.setUpperRightX(x + boxWidth);
    rect.setUpperRightY(y + boxHeight);
    return rect;
  }

  /**
   * One-page template PDF consumed by
   * {@link SignatureOptions#setVisualSignature(InputStream)} — same
   * structure as Apache PDFBox {@code CreateVisibleSignature2} (form XObject +
   * /AP).
   */
  private static InputStream createStandardVisibleSignatureTemplate(
      PDDocument srcDoc,
      int pageNum,
      PDRectangle rect,
      PDSignature signature,
      X509Certificate signingCert,
      boolean finalVersion) throws IOException {
    String subject = extractDisplaySubject(signingCert);
    java.util.Date signTime = signature.getSignDate() != null ? signature.getSignDate().getTime()
        : new java.util.Date();
    String when = TS_FMT.format(signTime.toInstant());

    try (PDDocument doc = new PDDocument()) {
      PDPage page = new PDPage(srcDoc.getPage(pageNum).getCropBox());
      doc.addPage(page);

      PDAcroForm acroForm = new PDAcroForm(doc);
      doc.getDocumentCatalog().setAcroForm(acroForm);
      acroForm.setSignaturesExist(true);
      acroForm.setAppendOnly(true);
      acroForm.getCOSObject().setDirect(true);

      PDSignatureField signatureField = new PDSignatureField(acroForm);
      signatureField.setPartialName("TrustSignSig" + System.nanoTime());
      acroForm.getFields().add(signatureField);

      PDAnnotationWidget widget = signatureField.getWidgets().get(0);
      widget.setRectangle(rect);
      widget.setPage(page);
      page.getAnnotations().add(widget);

      PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
      PDAppearanceDictionary appearance = new PDAppearanceDictionary();
      appearance.getCOSObject().setDirect(true);
      PDAppearanceStream appearanceStream = new PDAppearanceStream(doc);
      appearanceStream.setResources(new PDResources());
      appearanceStream.setBBox(bbox);
      appearance.setNormalAppearance(appearanceStream);
      widget.setAppearance(appearance);

      try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
        cs.setStrokingColor(0.75f, 0.75f, 0.75f);
        cs.setLineWidth(0.5f);
        cs.addRect(0, 0, bbox.getWidth(), bbox.getHeight());
        cs.stroke();
        cs.setNonStrokingColor(0.97f, 0.97f, 0.97f);
        cs.addRect(0.5f, 0.5f, bbox.getWidth() - 1f, bbox.getHeight() - 1f);
        cs.fill();

        float fontSize = 7f;
        float leading = fontSize * 1.35f;
        float tx = 4f;
        float ty = bbox.getHeight() - leading;

        cs.beginText();
        cs.setLeading(leading);
        cs.newLineAtOffset(tx, ty);
        if (finalVersion) {
          cs.setFont(PDType1Font.HELVETICA_BOLD, 8f);
          cs.setNonStrokingColor(Color.RED);
          cs.showText(truncateForPdfShowText("FINAL VERSION", 48));
          cs.newLine();
          cs.setFont(PDType1Font.HELVETICA, 6f);
          cs.setNonStrokingColor(0.35f, 0.35f, 0.35f);
          cs.showText(truncateForPdfShowText("No further edits permitted.", 72));
          cs.newLine();
        }
        cs.setFont(PDType1Font.HELVETICA_BOLD, 8f);
        cs.setNonStrokingColor(Color.BLACK);
        cs.showText(truncateForPdfShowText("Digitally signed by", 40));
        cs.newLine();
        cs.setFont(PDType1Font.HELVETICA, fontSize);
        for (String line : wrapSubjectLines(subject, 42)) {
          cs.showText(truncateForPdfShowText(line, 64));
          cs.newLine();
        }
        cs.showText(truncateForPdfShowText(when, 64));
        cs.newLine();
        String r = signature.getReason();
        if (r != null && !r.isBlank()) {
          cs.showText(truncateForPdfShowText("Reason: " + r.trim(), 64));
          cs.newLine();
        }
        String loc = signature.getLocation();
        if (loc != null && !loc.isBlank()) {
          cs.showText(truncateForPdfShowText("Location: " + loc.trim(), 64));
        }
        cs.endText();
      }

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      doc.save(baos);
      return new ByteArrayInputStream(baos.toByteArray());
    }
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
