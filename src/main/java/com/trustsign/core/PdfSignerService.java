package com.trustsign.core;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.MultiWidgetPdfSigner;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.TSAClientBouncyCastle;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
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
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * iText-backed PDF signing with a visible signature appearance
 * (Acrobat-compatible detached CMS).
 * <p>
 * Thread-safety: static methods are safe for concurrent use; each call uses
 * local streams and readers.
 */
public final class PdfSignerService {

  public static final String FINAL_VERSION_KEYWORD = "TrustSign:FinalVersion=true";
  public static final String FINAL_VERSION_REASON_SUFFIX = " | FINAL VERSION (no modifications permitted)";

  private static final Logger LOG = Logger.getLogger(PdfSignerService.class.getName());

  private static final COSName MDP_P = COSName.getPDFName("P");

  /**
   * PKCS#1 digest name passed to iText / PKCS#11 (SHA256withRSA on the token).
   */
  private static final String SIGNATURE_DIGEST_ALGORITHM = "SHA-256";

  /** Reserved space for embedded PKCS#7 (bytes). */
  private static final int ESTIMATED_SIGNATURE_SIZE_BYTES = 131_072;

  /**
   * Initial estimate for RFC 3161 token size when configuring
   * {@link TSAClientBouncyCastle}.
   */
  private static final int TSA_TOKEN_SIZE_ESTIMATE_BYTES = 4096;

  private static final String SIGNATURE_FIELD_PREFIX = "TrustSignSig";

  private static final DateTimeFormatter APPEARANCE_TIMESTAMP_UTC = DateTimeFormatter
      .ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'")
      .withZone(ZoneOffset.UTC);

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

  /**
   * Pages that receive the visible signature widget (0-based indices) with a matching rectangle
   * per page, plus whether the document already had completed signatures.
   */
  private record PreSignState(List<Integer> stampPageIndices0Based, List<PDRectangle> widgetRects,
      boolean hadPriorSignatures) {
    PreSignState {
      if (stampPageIndices0Based == null || stampPageIndices0Based.isEmpty()) {
        throw new IllegalArgumentException("stampPageIndices0Based is empty");
      }
      if (widgetRects == null || widgetRects.size() != stampPageIndices0Based.size()) {
        throw new IllegalArgumentException("widgetRects must match stamp pages size");
      }
    }
  }

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

  /**
   * Signs {@code pdfBytes} incrementally with a new visible signature field.
   *
   * @throws DocMdpNoChangesLockException if the PDF is locked with DocMDP P=1 and
   *                                      override is not set
   * @throws IllegalArgumentException     for invalid inputs
   */
  public static byte[] signPdf(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      PdfSigningOptions options) throws Exception {
    requireNonEmptyPdf(pdfBytes);
    PdfSigningOptions opts = options == null ? PdfSigningOptions.DEFAULT : options;

    byte[] bytesToSign = opts.finalVersion() ? applyFinalVersionDocumentMetadata(pdfBytes) : pdfBytes;
    PreSignState pre = analyzeInputPdf(bytesToSign, stampPageIndices, opts);
    byte[] signed = signDetachedWithIText(bytesToSign, material, reason, location, pre, opts);

    if (opts.ltvConfig() != null && opts.ltvConfig().enabled()) {
      try {
        return appendLtvRevision(signed, opts.ltvConfig());
      } catch (Exception e) {
        throw new IllegalStateException("LTV embedding failed after signature: " + safeMessage(e), e);
      }
    }
    return signed;
  }

  private static PreSignState analyzeInputPdf(byte[] pdfBytes, List<Integer> stampPageIndices, PdfSigningOptions opts)
      throws IOException {
    try (PDDocument doc = PDDocument.load(pdfBytes)) {
      int pageCount = doc.getNumberOfPages();
      if (pageCount == 0) {
        throw new IllegalArgumentException("PDF has no pages");
      }
      if (documentHasDocMdpP1LockFromCompletedSignature(doc) && !opts.allowResignFinalVersion()) {
        throw new DocMdpNoChangesLockException();
      }
      boolean priorSigs = documentHasCompletedPriorSignatures(doc);
      List<Integer> resolved = resolveStampPages(pageCount, stampPageIndices);
      List<PDRectangle> rects = new ArrayList<>(resolved.size());
      for (int pageIndex : resolved) {
        rects.add(computeSignatureWidgetRect(doc, pageIndex, opts.finalVersion()));
      }
      return new PreSignState(resolved, rects, priorSigs);
    }
  }

  private static byte[] signDetachedWithIText(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      PreSignState pre,
      PdfSigningOptions opts) throws Exception {
    validateChainForSigning(material);

    IExternalDigest digest = new BouncyCastleDigest();
    IExternalSignature signature = new ProviderBoundPrivateKeySignature(
        material.privateKey(), SIGNATURE_DIGEST_ALGORITHM, material.cryptoProvider());
    TSAClientBouncyCastle tsa = buildTsaClient(opts.tsaConfig());

    try {
      return runDetachedSign(pdfBytes, material, reason, location, pre, opts, digest, signature, tsa);
    } catch (Exception e) {
      if (tsa != null && opts.tsaConfig() != null && !opts.tsaConfig().failOnError()) {
        LOG.log(Level.WARNING, "TSA timestamp failed; signing without TSA: {0}", safeMessage(e));
        try {
          return runDetachedSign(pdfBytes, material, reason, location, pre, opts, digest, signature, null);
        } catch (Exception e2) {
          throw unwrapOpaquePkcs11SigningFailure(e2);
        }
      }
      throw unwrapOpaquePkcs11SigningFailure(e);
    }
  }

  /**
   * iText's {@code PrivateKeySignature} uses {@link Signature#getInstance(String, String)}. If the
   * JVM picks a different provider than the token, JCA may try to translate the PKCS#11 key via
   * {@link PrivateKey#getEncoded()}, which is null for HSM keys and throws
   * {@code InvalidKeyException: Missing key encoding}. Binding the {@link Signature} to the key's
   * {@link Provider} avoids that translation.
   */
  private static final class ProviderBoundPrivateKeySignature implements IExternalSignature {

    private final PrivateKey privateKey;
    private final Provider provider;
    private final String hashAlgorithm;
    private final String encryptionAlgorithm;

    ProviderBoundPrivateKeySignature(PrivateKey privateKey, String digestAlgorithm, Provider provider) {
      if (privateKey == null) {
        throw new IllegalArgumentException("privateKey is null");
      }
      if (provider == null) {
        throw new IllegalArgumentException("provider is null");
      }
      this.privateKey = privateKey;
      this.provider = provider;
      String allowed = DigestAlgorithms.getAllowedDigest(digestAlgorithm);
      if (allowed == null) {
        throw new IllegalArgumentException("Unsupported digest algorithm: " + digestAlgorithm);
      }
      this.hashAlgorithm = DigestAlgorithms.getDigest(allowed);
      String keyAlg = privateKey.getAlgorithm();
      this.encryptionAlgorithm = "EC".equals(keyAlg) ? "ECDSA" : keyAlg;
    }

    @Override
    public String getHashAlgorithm() {
      return hashAlgorithm;
    }

    @Override
    public String getEncryptionAlgorithm() {
      return encryptionAlgorithm;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
      String algorithm = hashAlgorithm + "with" + encryptionAlgorithm;
      Signature sig = Signature.getInstance(algorithm, provider);
      sig.initSign(privateKey);
      sig.update(message);
      return sig.sign();
    }
  }

  private static Exception unwrapOpaquePkcs11SigningFailure(Exception e) {
    if (e instanceof InvalidKeyException ike && "Missing key encoding".equals(ike.getMessage())) {
      return new InvalidKeyException(
          "PKCS#11 signing failed (opaque key): ensure the signature algorithm is supported on the token "
              + "and the SunPKCS11 provider is used for signing. Original: "
              + ike.getMessage(),
          ike);
    }
    return e;
  }

  private static Rectangle toItextRectangle(PDRectangle r) {
    return new Rectangle(r.getLowerLeftX(), r.getLowerLeftY(), r.getWidth(), r.getHeight());
  }

  private static void validateChainForSigning(PdfSigningMaterial material) {
    for (Certificate c : material.certificateChain()) {
      if (!(c instanceof X509Certificate)) {
        throw new IllegalArgumentException(
            "certificateChain must contain only X509Certificate entries for PDF signing");
      }
    }
  }

  private static TSAClientBouncyCastle buildTsaClient(TsaClient.Config cfg) {
    if (cfg == null || !cfg.enabled()) {
      return null;
    }
    return new TSAClientBouncyCastle(
        cfg.url().trim(),
        null,
        null,
        TSA_TOKEN_SIZE_ESTIMATE_BYTES,
        cfg.normalizedHashAlgorithm());
  }

  private static byte[] runDetachedSign(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      PreSignState pre,
      PdfSigningOptions opts,
      IExternalDigest digest,
      IExternalSignature signature,
      TSAClientBouncyCastle tsaClient) throws Exception {
    try (ByteArrayOutputStream out = new ByteArrayOutputStream();
        PdfReader reader = new PdfReader(new ByteArrayInputStream(pdfBytes))) {
      List<Integer> pages1Based = new ArrayList<>(pre.stampPageIndices0Based().size());
      List<Rectangle> itextRects = new ArrayList<>(pre.stampPageIndices0Based().size());
      for (int i = 0; i < pre.stampPageIndices0Based().size(); i++) {
        pages1Based.add(pre.stampPageIndices0Based().get(i) + 1);
        itextRects.add(toItextRectangle(pre.widgetRects().get(i)));
      }
      PdfSigner signer = new MultiWidgetPdfSigner(
          reader, out, new StampingProperties().useAppendMode(), pages1Based, itextRects);
      applyCertificationAndField(signer, pre, opts);
      configureSignatureAppearance(signer, material, reason, location, pre, opts);
      signer.signDetached(
          digest,
          signature,
          material.certificateChain(),
          null,
          null,
          tsaClient,
          ESTIMATED_SIGNATURE_SIZE_BYTES,
          PdfSigner.CryptoStandard.CMS);
      return out.toByteArray();
    }
  }

  private static void applyCertificationAndField(PdfSigner signer, PreSignState pre, PdfSigningOptions opts) {
    if (opts.finalVersion() && !pre.hadPriorSignatures()) {
      signer.setCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);
    } else if (opts.finalVersion() && Boolean.getBoolean("trustsign.logFinalVersion")) {
      LOG.info("Final version requested but PDF already had signatures; DocMDP P=1 omitted.");
    }
    signer.setFieldName(newSignatureFieldName());
    signer.setSignDate(Calendar.getInstance());
  }

  private static String newSignatureFieldName() {
    return SIGNATURE_FIELD_PREFIX + System.nanoTime();
  }

  private static void configureSignatureAppearance(
      PdfSigner signer,
      PdfSigningMaterial material,
      String reason,
      String location,
      PreSignState pre,
      PdfSigningOptions opts) {
    PdfSignatureAppearance appearance = signer.getSignatureAppearance();
    PDRectangle r = pre.widgetRects().get(0);
    appearance.setPageNumber(pre.stampPageIndices0Based().get(0) + 1);
    appearance.setPageRect(toItextRectangle(r));

    String resolvedReason = resolveReason(reason, opts.finalVersion());
    appearance.setReason(resolvedReason);
    if (location != null && !location.isBlank()) {
      appearance.setLocation(location.trim());
    }
    appearance.setCertificate(material.signingCertificate());
    appearance.setLayer2Text(
        buildAppearanceText(material.signingCertificate(), resolvedReason, location, opts.finalVersion()));
    appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
    appearance.setReuseAppearance(false);
  }

  private static String buildAppearanceText(
      X509Certificate cert,
      String resolvedReason,
      String location,
      boolean finalVersion) {
    String subject = extractDisplaySubject(cert);
    String when = APPEARANCE_TIMESTAMP_UTC.format(java.time.Instant.now());
    StringBuilder sb = new StringBuilder();
    if (finalVersion) {
      sb.append("FINAL VERSION\nNo further edits permitted.\n");
    }
    sb.append("Digitally signed by ").append(subject).append('\n');
    sb.append(when);
    if (resolvedReason != null && !resolvedReason.isBlank()) {
      sb.append("\nReason: ").append(resolvedReason.trim());
    }
    if (location != null && !location.isBlank()) {
      sb.append("\nLocation: ").append(location.trim());
    }
    return sb.toString();
  }

  private static String resolveReason(String reason, boolean finalVersion) {
    if (reason != null && !reason.isBlank()) {
      String t = reason.trim();
      return finalVersion ? t + FINAL_VERSION_REASON_SUFFIX : t;
    }
    return finalVersion
        ? "TrustSign digital signature" + FINAL_VERSION_REASON_SUFFIX
        : "TrustSign digital signature";
  }

  private static void requireNonEmptyPdf(byte[] pdfBytes) {
    if (pdfBytes == null || pdfBytes.length == 0) {
      throw new IllegalArgumentException("pdfBytes is empty");
    }
  }

  private static String safeMessage(Throwable t) {
    if (t == null) {
      return "unknown";
    }
    String m = t.getMessage();
    return (m != null && !m.isBlank()) ? m : t.getClass().getSimpleName();
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
    if (contents == null || contents.length < 128) {
      return false;
    }
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
    return contents[firstNonZero] == (byte) 0x30;
  }

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
      if (params.getInt(MDP_P, -1) == 1) {
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
      if (signatureContentsLookSigned(existing.getContents())) {
        return true;
      }
    }
    return false;
  }

  private static byte[] applyFinalVersionDocumentMetadata(byte[] pdfBytes) throws IOException {
    try (PDDocument doc = PDDocument.load(pdfBytes);
        ByteArrayOutputStream out = new ByteArrayOutputStream()) {
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
    if (stampPageIndices == null || stampPageIndices.isEmpty()) {
      return List.of(0);
    }
    if (stampPageIndices.contains(-1)) {
      List<Integer> all = new ArrayList<>(pageCount);
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
