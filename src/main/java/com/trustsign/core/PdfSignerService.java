package com.trustsign.core;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDate;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.TSAClientBouncyCastle;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSInteger;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

/** iText-backed PDF signing with visible signature appearance (Acrobat-compatible). */
public final class PdfSignerService {

  public static final String FINAL_VERSION_KEYWORD = "TrustSign:FinalVersion=true";
  public static final String FINAL_VERSION_REASON_SUFFIX = " | FINAL VERSION (no modifications permitted)";
  private static final COSName MDP_P = COSName.getPDFName("P");

  public record PdfSigningOptions(
      boolean finalVersion,
      boolean allowResignFinalVersion,
      TsaClient.Config tsaConfig,
      LtvEnabler.Config ltvConfig) {
    public static final PdfSigningOptions DEFAULT = new PdfSigningOptions(
        false,
        false,
        TsaClient.Config.DISABLED,
        LtvEnabler.Config.DISABLED);

    public PdfSigningOptions(boolean finalVersion) {
      this(finalVersion, false, TsaClient.Config.DISABLED, LtvEnabler.Config.DISABLED);
    }

    public PdfSigningOptions(boolean finalVersion, boolean allowResignFinalVersion) {
      this(finalVersion, allowResignFinalVersion, TsaClient.Config.DISABLED, LtvEnabler.Config.DISABLED);
    }
  }

  public static final class DocMdpNoChangesLockException extends IllegalArgumentException {
    public DocMdpNoChangesLockException() {
      super(
          "This PDF is certified or locked with DocMDP P=1 (ISO 32000: no document changes permitted). ");
    }
  }

  public record PdfSigningMaterial(
      PrivateKey privateKey,
      Certificate[] certificateChain,
      Provider cryptoProvider,
      X509Certificate signingCertificate) {

    public PdfSigningMaterial {
      if (privateKey == null) throw new IllegalArgumentException("privateKey is null");
      if (certificateChain == null || certificateChain.length == 0) {
        throw new IllegalArgumentException("certificateChain is empty");
      }
      if (cryptoProvider == null) throw new IllegalArgumentException("cryptoProvider is null");
      if (signingCertificate == null) throw new IllegalArgumentException("signingCertificate is null");
    }

    public X509Certificate[] x509ChainOrNull() {
      if (!(certificateChain[0] instanceof X509Certificate)) return null;
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

    int signaturePageIndex;
    PDRectangle widgetRect;
    boolean priorSigs;
    try (PDDocument doc = PDDocument.load(pdfBytes)) {
      if (doc.getNumberOfPages() == 0) throw new IllegalArgumentException("PDF has no pages");
      if (documentHasDocMdpP1LockFromCompletedSignature(doc) && !opts.allowResignFinalVersion()) {
        throw new DocMdpNoChangesLockException();
      }
      priorSigs = documentHasCompletedPriorSignatures(doc);
      List<Integer> resolvedPages = resolveStampPages(doc.getNumberOfPages(), stampPageIndices);
      signaturePageIndex = resolvedPages.get(0);
      widgetRect = computeSignatureWidgetRect(doc, signaturePageIndex, opts.finalVersion());
    }

    byte[] sourceBytes = opts.finalVersion() ? applyFinalVersionDocumentMetadata(pdfBytes) : pdfBytes;
    byte[] signed = signWithIText(sourceBytes, material, reason, location, signaturePageIndex, widgetRect, opts, priorSigs);

    if (opts.ltvConfig() != null && opts.ltvConfig().enabled()) {
      return appendLtvRevision(signed, opts.ltvConfig());
    }
    return signed;
  }

  private static byte[] signWithIText(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      int signaturePageIndex,
      PDRectangle widgetRect,
      PdfSigningOptions opts,
      boolean hadPriorSignatures) throws Exception {
    try (ByteArrayOutputStream out = new ByteArrayOutputStream();
         PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes))) {
      StampingProperties sp = new StampingProperties().useAppendMode();
      PdfSigner signer = new PdfSigner(reader, out, sp);
      if (opts.finalVersion() && !hadPriorSignatures) {
        signer.setCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);
      } else if (opts.finalVersion() && Boolean.getBoolean("trustsign.logFinalVersion")) {
        LOG.info("Final version requested but PDF already had signatures; DocMDP P=1 omitted.");
      }

      signer.setFieldName("TrustSignSig" + System.nanoTime());
      PdfSignatureAppearance appearance = signer.getSignatureAppearance();
      appearance.setPageNumber(signaturePageIndex + 1);
      appearance.setPageRect(new Rectangle(
          widgetRect.getLowerLeftX(),
          widgetRect.getLowerLeftY(),
          widgetRect.getWidth(),
          widgetRect.getHeight()));
      appearance.setReason(resolveReason(reason, opts.finalVersion()));
      if (location != null && !location.isBlank()) appearance.setLocation(location.trim());
      appearance.setCertificate(material.signingCertificate());
      appearance.setLayer2Text(buildAppearanceText(material.signingCertificate(), appearance.getReason(), location, opts.finalVersion()));
      appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
      appearance.setReuseAppearance(false);
      signer.setSignDate(java.util.Calendar.getInstance());

      IExternalSignature externalSignature = new PrivateKeySignature(
          material.privateKey(),
          "SHA-256",
          material.cryptoProvider().getName());
      IExternalDigest externalDigest = new BouncyCastleDigest();

      TSAClientBouncyCastle tsaClient = null;
      if (opts.tsaConfig() != null && opts.tsaConfig().enabled()) {
        tsaClient = new TSAClientBouncyCastle(
            opts.tsaConfig().url(),
            null,
            null,
            4096,
            opts.tsaConfig().normalizedHashAlgorithm());
      }
      try {
        signer.signDetached(
            externalDigest,
            externalSignature,
            material.certificateChain(),
            null,
            null,
            tsaClient,
            131072,
            PdfSigner.CryptoStandard.CMS);
      } catch (Exception e) {
        if (tsaClient != null && opts.tsaConfig() != null && !opts.tsaConfig().failOnError()) {
          LOG.warning("TSA timestamp failed; signing PDF without TSA: " + e.getMessage());
          try (ByteArrayOutputStream retryOut = new ByteArrayOutputStream();
               PdfReader retryReader = new PdfReader(new ByteArrayInputStream(pdfBytes))) {
            PdfSigner retrySigner = new PdfSigner(retryReader, retryOut, new StampingProperties().useAppendMode());
            if (opts.finalVersion() && !hadPriorSignatures) {
              retrySigner.setCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);
            }
            retrySigner.setFieldName("TrustSignSig" + System.nanoTime());
            PdfSignatureAppearance retryAppearance = retrySigner.getSignatureAppearance();
            retryAppearance.setPageNumber(signaturePageIndex + 1);
            retryAppearance.setPageRect(new Rectangle(
                widgetRect.getLowerLeftX(),
                widgetRect.getLowerLeftY(),
                widgetRect.getWidth(),
                widgetRect.getHeight()));
            retryAppearance.setReason(resolveReason(reason, opts.finalVersion()));
            if (location != null && !location.isBlank()) retryAppearance.setLocation(location.trim());
            retryAppearance.setCertificate(material.signingCertificate());
            retryAppearance.setLayer2Text(buildAppearanceText(material.signingCertificate(), retryAppearance.getReason(), location, opts.finalVersion()));
            retryAppearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
            retryAppearance.setReuseAppearance(false);
            retrySigner.setSignDate(java.util.Calendar.getInstance());
            retrySigner.signDetached(
                externalDigest,
                externalSignature,
                material.certificateChain(),
                null,
                null,
                null,
                131072,
                PdfSigner.CryptoStandard.CMS);
            return retryOut.toByteArray();
          }
        }
        throw e;
      }
      return out.toByteArray();
    }
  }

  private static String buildAppearanceText(
      X509Certificate cert,
      String reason,
      String location,
      boolean finalVersion) {
    String subject = extractDisplaySubject(cert);
    String when = TS_FMT.format(java.time.Instant.now());
    StringBuilder sb = new StringBuilder();
    if (finalVersion) sb.append("FINAL VERSION\nNo further edits permitted.\n");
    sb.append("Digitally signed by ").append(subject).append("\n");
    sb.append(when);
    if (reason != null && !reason.isBlank()) sb.append("\nReason: ").append(reason.trim());
    if (location != null && !location.isBlank()) sb.append("\nLocation: ").append(location.trim());
    return sb.toString();
  }

  private static String resolveReason(String reason, boolean finalVersion) {
    if (reason != null && !reason.isBlank()) {
      return finalVersion ? reason.trim() + FINAL_VERSION_REASON_SUFFIX : reason.trim();
    }
    return finalVersion
        ? "TrustSign digital signature" + FINAL_VERSION_REASON_SUFFIX
        : "TrustSign digital signature";
  }

  private static void requireNonEmptyPdf(byte[] pdfBytes) {
    if (pdfBytes == null || pdfBytes.length == 0) throw new IllegalArgumentException("pdfBytes is empty");
  }

  private static byte[] appendLtvRevision(byte[] signedPdfBytes, LtvEnabler.Config ltvConfig) throws Exception {
    try (PDDocument signedDoc = PDDocument.load(signedPdfBytes);
         ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      LtvEnabler.enableLTV(signedDoc, signedPdfBytes, ltvConfig);
      signedDoc.saveIncremental(out);
      return out.toByteArray();
    }
  }

  private static boolean signatureContentsLookSigned(byte[] contents) {
    if (contents == null || contents.length < 128) return false;
    int firstNonZero = -1;
    for (int i = 0; i < contents.length; i++) {
      if (contents[i] != 0) {
        firstNonZero = i;
        break;
      }
    }
    if (firstNonZero < 0) return false;
    return contents[firstNonZero] == (byte) 0x30;
  }

  private static boolean documentHasDocMdpP1LockFromCompletedSignature(PDDocument doc) throws IOException {
    for (PDSignature existing : doc.getSignatureDictionaries()) {
      if (existing == null) continue;
      byte[] contents = existing.getContents();
      if (!signatureContentsLookSigned(contents)) continue;
      if (signatureHasDocMdpP1(existing)) return true;
    }
    return false;
  }

  private static boolean signatureHasDocMdpP1(PDSignature sig) {
    COSArray refs = sig.getCOSObject().getCOSArray(COSName.REFERENCE);
    if (refs == null) return false;
    for (int i = 0; i < refs.size(); i++) {
      COSDictionary refDict = asCosDictionary(refs.get(i));
      if (refDict == null) continue;
      if (!COSName.DOCMDP.equals(refDict.getCOSName(COSName.TRANSFORM_METHOD))) continue;
      COSDictionary params = refDict.getCOSDictionary(COSName.TRANSFORM_PARAMS);
      if (params == null) continue;
      int p = params.getInt(MDP_P, -1);
      if (p == 1) return true;
    }
    return false;
  }

  private static COSDictionary asCosDictionary(COSBase base) {
    if (base instanceof COSDictionary d) return d;
    if (base instanceof COSObject obj) {
      COSBase resolved = obj.getObject();
      return resolved instanceof COSDictionary d ? d : null;
    }
    return null;
  }

  private static boolean documentHasCompletedPriorSignatures(PDDocument doc) throws IOException {
    for (PDSignature existing : doc.getSignatureDictionaries()) {
      if (existing == null) continue;
      byte[] contents = existing.getContents();
      if (signatureContentsLookSigned(contents)) return true;
    }
    return false;
  }

  private static byte[] applyFinalVersionDocumentMetadata(byte[] pdfBytes) throws IOException {
    try (PDDocument doc = PDDocument.load(pdfBytes);
         ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      PDDocumentInformation di = doc.getDocumentInformation();
      if (di == null) di = new PDDocumentInformation();
      String kw = di.getKeywords();
      if (kw == null || kw.isBlank()) di.setKeywords(FINAL_VERSION_KEYWORD);
      else if (!kw.contains("TrustSign:FinalVersion")) di.setKeywords(kw.trim() + "; " + FINAL_VERSION_KEYWORD);
      String subj = di.getSubject();
      String tag = "FINAL VERSION";
      if (subj == null || subj.isBlank()) di.setSubject(tag);
      else if (!subj.contains(tag)) di.setSubject(subj.trim() + " - " + tag);
      doc.setDocumentInformation(di);
      doc.save(out);
      return out.toByteArray();
    }
  }

  private static PDRectangle computeSignatureWidgetRect(PDDocument doc, int pageIndex, boolean finalVersion) {
    PDPage page = doc.getPage(pageIndex);
    PDRectangle visible = page.getCropBox();
    float vx = visible.getLowerLeftX();
    float vy = visible.getLowerLeftY();
    float vW = visible.getWidth();
    float vH = visible.getHeight();
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

  private static List<Integer> resolveStampPages(int pageCount, List<Integer> stampPageIndices) {
    if (stampPageIndices == null || stampPageIndices.isEmpty()) return List.of(0);
    if (stampPageIndices.contains(-1)) {
      List<Integer> all = new ArrayList<>();
      for (int i = 0; i < pageCount; i++) all.add(i);
      return all;
    }
    Set<Integer> unique = new LinkedHashSet<>();
    for (Integer idx : stampPageIndices) {
      if (idx == null) continue;
      if (idx >= 0 && idx < pageCount) unique.add(idx);
    }
    if (unique.isEmpty()) return List.of(0);
    return new ArrayList<>(unique);
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

