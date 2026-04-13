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
import java.io.InputStream;
import java.io.OutputStream;
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
import java.util.Arrays;
import java.util.Calendar;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

  private static final Logger LOG = LoggerFactory.getLogger(PdfSignerService.class);

  private static final COSName MDP_P = COSName.getPDFName("P");

  /**
   * PKCS#1 digest name passed to iText / PKCS#11 (SHA256withRSA on the token).
   */
  private static final String SIGNATURE_DIGEST_ALGORITHM = "SHA-256";

  /**
   * Reserved space for embedded PKCS#7 bytes.
   * Increased to handle larger envelopes with TSA, DSS/LTV material, and long
   * certificate chains.
   */
  private static final int ESTIMATED_SIGNATURE_SIZE_BYTES = 262_144;
  private static final int SIGN_RETRY_MAX_ATTEMPTS = 3;

  /**
   * Initial estimate for RFC 3161 token size when configuring
   * {@link TSAClientBouncyCastle}.
   */
  private static final int TSA_TOKEN_SIZE_ESTIMATE_BYTES = 4096;

  private static final String SIGNATURE_FIELD_PREFIX = "TrustSignSig";
  private static final byte[] SIGNED_DATA_OID = new byte[] {
      (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xf7, (byte) 0x0d, (byte) 0x01, (byte) 0x07,
      (byte) 0x02
  };

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

  public static sealed class PdfSigningException extends Exception
      permits InvalidPdfException, DocMdpLockedException, CryptoSigningException, TimestampException, LtvException {
    public PdfSigningException(String message) {
      super(message);
    }

    public PdfSigningException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Thrown when PDF input bytes are invalid for signing (empty input, malformed
   * structure,
   * or no pages). Caller should abort and ask the user for a valid PDF.
   */
  public static final class InvalidPdfException extends PdfSigningException {
    public InvalidPdfException(String message) {
      super(message);
    }

    public InvalidPdfException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Thrown when document-level permissions (DocMDP P=1) disallow further
   * modifications.
   * Caller should abort and inform the user that the document is locked.
   */
  public static non-sealed class DocMdpLockedException extends PdfSigningException {
    public DocMdpLockedException(String message) {
      super(message);
    }

    public DocMdpLockedException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Thrown for cryptographic signing failures (PKCS#11/JCA/provider errors).
   * Caller may retry after token/provider remediation; otherwise alert the user.
   */
  public static final class CryptoSigningException extends PdfSigningException {
    public CryptoSigningException(String message) {
      super(message);
    }

    public CryptoSigningException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Thrown when timestamping fails and the operation requires TSA success.
   * Caller should retry later or surface a timestamp service outage.
   */
  public static non-sealed class TimestampException extends PdfSigningException {
    public TimestampException(String message) {
      super(message);
    }

    public TimestampException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * Thrown when post-sign LTV embedding fails.
   * Caller should alert the user and decide whether non-LTV output is acceptable.
   */
  public static final class LtvException extends PdfSigningException {
    public LtvException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  public static final class TsaUnavailableException extends TimestampException {
    private final boolean signedWithoutTimestamp;
    private final Throwable tsaCause;

    public TsaUnavailableException(String message, boolean signedWithoutTimestamp, Throwable tsaCause) {
      super(message, tsaCause);
      this.signedWithoutTimestamp = signedWithoutTimestamp;
      this.tsaCause = tsaCause;
    }

    public boolean signedWithoutTimestamp() {
      return signedWithoutTimestamp;
    }

    public Throwable tsaCause() {
      return tsaCause;
    }
  }

  /**
   * Result wrapper for PDF signing.
   * <p>
   * Callers MUST check {@link #isTimestamped()} before accepting output for
   * long-term archival
   * use cases (e.g., retention policies requiring RFC 3161 timestamp evidence at
   * signing time).
   */
  public static final class PdfSigningResult {
    private final byte[] signedPdf;
    private final boolean timestamped;
    /**
     * Nullable: warning when TSA failed but failOnError=false fallback signing
     * succeeded.
     */
    private final TsaUnavailableException tsaWarning;

    public PdfSigningResult(byte[] signedPdf, boolean timestamped, TsaUnavailableException tsaWarning) {
      this.signedPdf = signedPdf;
      this.timestamped = timestamped;
      this.tsaWarning = tsaWarning;
    }

    public byte[] signedPdf() {
      return signedPdf;
    }

    public boolean isTimestamped() {
      return timestamped;
    }

    public TsaUnavailableException tsaWarning() {
      return tsaWarning;
    }
  }

  public static final class DocMdpNoChangesLockException extends DocMdpLockedException {
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
   * Pages that receive the visible signature widget (0-based indices) with a
   * matching rectangle
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

  private record DerLength(int value, int nextOffset) {
  }

  public static PdfSigningResult signPdf(
      byte[] pdfBytes,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider,
      X509Certificate signingCert,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      PdfSigningOptions options) throws PdfSigningException, IOException {
    try {
      return signPdf(
          pdfBytes,
          new PdfSigningMaterial(privateKey, chain, p11Provider, signingCert),
          reason,
          location,
          stampPageIndices,
          options);
    } catch (IllegalArgumentException e) {
      throw new InvalidPdfException("Invalid signing input: " + safeMessage(e), e);
    }
  }

  /**
   * Signs {@code pdfBytes} incrementally with a new visible signature field.
   *
   * @throws DocMdpNoChangesLockException if the PDF is locked with DocMDP P=1 and
   *                                      override is not set
   * @throws IllegalArgumentException     for invalid inputs
   */
  public static PdfSigningResult signPdf(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      PdfSigningOptions options) throws PdfSigningException, IOException {
    try {
      requireNonEmptyPdf(pdfBytes);
    } catch (IllegalArgumentException e) {
      throw new InvalidPdfException("Invalid PDF input: " + safeMessage(e), e);
    }
    PdfSigningOptions opts = options == null ? PdfSigningOptions.DEFAULT : options;
    long start = System.currentTimeMillis();
    LOG.info("Starting PDF signing. pages={}, finalVersion={}, tsaEnabled={}",
        stampPageIndices == null ? 0 : stampPageIndices.size(),
        opts.finalVersion(),
        opts.tsaConfig() != null && opts.tsaConfig().enabled());

    byte[] bytesToSign = opts.finalVersion() ? applyFinalVersionDocumentMetadata(pdfBytes) : pdfBytes;
    bytesToSign = ensureAnnotsArrayOnTargetPages(bytesToSign, stampPageIndices);
    PreSignState pre;
    try {
      pre = analyzeInputPdf(bytesToSign, stampPageIndices, opts);
    } catch (IOException e) {
      throw new InvalidPdfException("Invalid or corrupted PDF input: " + safeMessage(e), e);
    }
    PdfSigningResult result = signDetachedWithIText(bytesToSign, material, reason, location, pre, opts);

    if (opts.ltvConfig() != null && opts.ltvConfig().enabled()) {
      try {
        byte[] ltvSigned = appendLtvRevision(result.signedPdf(), opts.ltvConfig());
        PdfSigningResult out = new PdfSigningResult(ltvSigned, result.isTimestamped(), result.tsaWarning());
        LOG.info("PDF signing completed in {} ms. timestamped={}, tsaFallback={}",
            System.currentTimeMillis() - start, out.isTimestamped(), out.tsaWarning() != null);
        return out;
      } catch (Exception e) {
        throw new LtvException("LTV embedding failed after signature: " + safeMessage(e), e);
      }
    }
    LOG.info("PDF signing completed in {} ms. timestamped={}, tsaFallback={}",
        System.currentTimeMillis() - start, result.isTimestamped(), result.tsaWarning() != null);
    return result;
  }

  private static PreSignState analyzeInputPdf(byte[] pdfBytes, List<Integer> stampPageIndices, PdfSigningOptions opts)
      throws IOException, PdfSigningException {
    try (PDDocument doc = PDDocument.load(pdfBytes)) {
      int pageCount = doc.getNumberOfPages();
      if (pageCount == 0) {
        throw new InvalidPdfException("PDF has no pages");
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

  private static PdfSigningResult signDetachedWithIText(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      PreSignState pre,
      PdfSigningOptions opts) throws PdfSigningException, IOException {
    validateChainForSigning(material);

    IExternalDigest digest = new BouncyCastleDigest();
    IExternalSignature signature = new ProviderBoundPrivateKeySignature(
        material.privateKey(), SIGNATURE_DIGEST_ALGORITHM, material.cryptoProvider());
    TSAClientBouncyCastle tsa = buildTsaClient(opts.tsaConfig());

    try {
      byte[] signed = withRetry(() -> {
        try {
          return runDetachedSign(pdfBytes, material, reason, location, pre, opts, digest, signature, tsa);
        } catch (IOException | GeneralSecurityException | InvalidPdfException ex) {
          throw new RuntimeException(ex);
        }
      });
      return new PdfSigningResult(signed, tsa != null, null);
    } catch (RuntimeException re) {
      Throwable c = re.getCause() != null ? re.getCause() : re;
      if (c instanceof GeneralSecurityException e) {
        if (tsa != null && opts.tsaConfig() != null && !opts.tsaConfig().failOnError()) {
          String tsaUrl = opts.tsaConfig().url() == null ? "<unknown>" : opts.tsaConfig().url().trim();
          LOG.warn("TSA timestamp failed for URL {}; falling back without TSA. Cause: {}", tsaUrl, safeMessage(e));
          try {
            byte[] fallbackSigned = withRetry(() -> {
              try {
                return runDetachedSign(pdfBytes, material, reason, location, pre, opts, digest, signature, null);
              } catch (IOException | GeneralSecurityException | InvalidPdfException ex) {
                throw new RuntimeException(ex);
              }
            });
            TsaUnavailableException warning = new TsaUnavailableException(
                "TSA unavailable for " + tsaUrl + "; signed without timestamp",
                true,
                e);
            return new PdfSigningResult(fallbackSigned, false, warning);
          } catch (RuntimeException retryException) {
            Throwable retryCause = retryException.getCause() != null ? retryException.getCause() : retryException;
            if (retryCause instanceof GeneralSecurityException gse) {
              throw asCryptoSigningException(gse);
            }
            if (retryCause instanceof IOException io) {
              throw io;
            }
            throw new CryptoSigningException("PKCS#11 signing failed: " + safeMessage(retryCause), retryCause);
          }
        }
        if (tsa != null && opts.tsaConfig() != null && opts.tsaConfig().failOnError()) {
          String tsaUrl = opts.tsaConfig().url() == null ? "<unknown>" : opts.tsaConfig().url().trim();
          throw new TimestampException("TSA timestamp failed for URL " + tsaUrl + ": " + safeMessage(e), e);
        }
        throw asCryptoSigningException(e);
      }
      if (c instanceof IOException io) {
        if (tsa != null && opts.tsaConfig() != null && opts.tsaConfig().failOnError()) {
          String tsaUrl = opts.tsaConfig().url() == null ? "<unknown>" : opts.tsaConfig().url().trim();
          throw new TimestampException("TSA timestamp I/O failed for URL " + tsaUrl + ": " + safeMessage(io), io);
        }
        throw io;
      }
      if (c instanceof InvalidPdfException ipe) {
        throw ipe;
      }
      throw new CryptoSigningException("PKCS#11 signing failed: " + safeMessage(c), c);
    }
  }

  public static byte[] signPdfBytes(
      byte[] pdfBytes,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider,
      X509Certificate signingCert,
      String reason,
      String location,
      List<Integer> stampPageIndices) throws PdfSigningException, IOException {
    return signPdfBytes(
        pdfBytes,
        privateKey,
        chain,
        p11Provider,
        signingCert,
        reason,
        location,
        stampPageIndices,
        PdfSigningOptions.DEFAULT);
  }

  public static byte[] signPdfBytes(
      byte[] pdfBytes,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider,
      X509Certificate signingCert,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      PdfSigningOptions options) throws PdfSigningException, IOException {
    PdfSigningResult result = signPdf(
        pdfBytes,
        privateKey,
        chain,
        p11Provider,
        signingCert,
        reason,
        location,
        stampPageIndices,
        options);
    return requireTimestampWhenConfigured(result, options);
  }

  public static void signPdf(
      InputStream input,
      OutputStream output,
      PdfSigningMaterial material,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      PdfSigningOptions options) throws PdfSigningException, IOException {
    if (input == null) {
      throw new InvalidPdfException("input stream is null");
    }
    if (output == null) {
      throw new InvalidPdfException("output stream is null");
    }
    byte[] inBytes = input.readAllBytes();
    PdfSigningResult result = signPdf(inBytes, material, reason, location, stampPageIndices, options);
    output.write(result.signedPdf());
  }

  public static byte[] signPdfBytes(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      List<Integer> stampPageIndices) throws PdfSigningException, IOException {
    return signPdfBytes(pdfBytes, material, reason, location, stampPageIndices, PdfSigningOptions.DEFAULT);
  }

  public static byte[] signPdfBytes(
      byte[] pdfBytes,
      PdfSigningMaterial material,
      String reason,
      String location,
      List<Integer> stampPageIndices,
      PdfSigningOptions options) throws PdfSigningException, IOException {
    PdfSigningResult result = signPdf(pdfBytes, material, reason, location, stampPageIndices, options);
    return requireTimestampWhenConfigured(result, options);
  }

  private static byte[] requireTimestampWhenConfigured(PdfSigningResult result, PdfSigningOptions options)
      throws TsaUnavailableException {
    PdfSigningOptions opts = options == null ? PdfSigningOptions.DEFAULT : options;
    if (opts.tsaConfig() != null && opts.tsaConfig().enabled() && !result.isTimestamped()) {
      if (result.tsaWarning() != null) {
        throw result.tsaWarning();
      }
      throw new TsaUnavailableException("TSA enabled but signature is not timestamped", true, null);
    }
    return result.signedPdf();
  }

  /**
   * iText's {@code PrivateKeySignature} uses
   * {@link Signature#getInstance(String, String)}. If the
   * JVM picks a different provider than the token, JCA may try to translate the
   * PKCS#11 key via
   * {@link PrivateKey#getEncoded()}, which is null for HSM keys and throws
   * {@code InvalidKeyException: Missing key encoding}. Binding the
   * {@link Signature} to the key's
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

  private static GeneralSecurityException normalizePkcs11SecurityException(GeneralSecurityException e) {
    if (e instanceof InvalidKeyException ike && "Missing key encoding".equals(ike.getMessage())) {
      return new InvalidKeyException(
          "PKCS#11 signing failed (opaque key): ensure the signature algorithm is supported on the token "
              + "and the SunPKCS11 provider is used for signing. Original: "
              + ike.getMessage(),
          ike);
    }
    return e;
  }

  private static CryptoSigningException asCryptoSigningException(GeneralSecurityException e) {
    GeneralSecurityException normalized = normalizePkcs11SecurityException(e);
    return new CryptoSigningException("PKCS#11 signing failed: " + safeMessage(normalized), normalized);
  }

  private static <T> T withRetry(Supplier<T> action) {
    RuntimeException last = null;
    for (int attempt = 1; attempt <= SIGN_RETRY_MAX_ATTEMPTS; attempt++) {
      try {
        return action.get();
      } catch (RuntimeException e) {
        Throwable cause = e.getCause() != null ? e.getCause() : e;
        if (!isRetryableSigningFailure(cause) || attempt == SIGN_RETRY_MAX_ATTEMPTS) {
          throw e;
        }
        last = e;
        LOG.warn("Signing attempt {} failed ({}). Retrying...", attempt, safeMessage(cause));
      }
    }
    throw last == null ? new RuntimeException("Signing failed without exception") : last;
  }

  private static boolean isRetryableSigningFailure(Throwable t) {
    if (t == null) {
      return false;
    }
    if (t instanceof GeneralSecurityException) {
      return true;
    }
    String m = safeMessage(t).toLowerCase();
    return m.contains("pkcs#11") || m.contains("pkcs11") || m.contains("token")
        || m.contains("ckr_") || m.contains("sunpkcs11");
  }

  private static Rectangle toItextRectangle(PDRectangle r) {
    return new Rectangle(r.getLowerLeftX(), r.getLowerLeftY(), r.getWidth(), r.getHeight());
  }

  private static void validateChainForSigning(PdfSigningMaterial material) {
    if (material == null || material.certificateChain() == null || material.certificateChain().length == 0) {
      throw new IllegalArgumentException("certificateChain is empty");
    }
    X509Certificate[] chain = new X509Certificate[material.certificateChain().length];
    int i = 0;
    for (Certificate c : material.certificateChain()) {
      if (!(c instanceof X509Certificate)) {
        throw new IllegalArgumentException(
            "certificateChain must contain only X509Certificate entries for PDF signing");
      }
      chain[i++] = (X509Certificate) c;
    }
    validateCertificateChainOrder(chain);
  }

  private static void validateCertificateChainOrder(X509Certificate[] chain) {
    if (chain == null || chain.length == 0) {
      throw new IllegalArgumentException("certificateChain is empty");
    }
    for (int i = 0; i < chain.length - 1; i++) {
      X509Certificate current = chain[i];
      X509Certificate issuer = chain[i + 1];
      if (!current.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
        throw new IllegalArgumentException(
            "Invalid certificate chain order at index " + i + ": expected issuer "
                + current.getIssuerX500Principal().getName()
                + " but found " + issuer.getSubjectX500Principal().getName());
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
      TSAClientBouncyCastle tsaClient) throws IOException, GeneralSecurityException, InvalidPdfException {
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
      // MultiWidgetPdfSigner (and iText PdfSigner) currently exposes only one shared
      // PdfSignatureAppearance object, not per-widget appearance accessors.
      // TODO: If iText exposes per-widget appearance APIs, configure each widget
      // index here.
      configureSignatureAppearance(
          signer,
          material,
          reason,
          location,
          pre.stampPageIndices0Based().get(0),
          pre.widgetRects().get(0),
          opts);
      signer.signDetached(
          digest,
          signature,
          material.certificateChain(),
          null,
          null,
          tsaClient,
          ESTIMATED_SIGNATURE_SIZE_BYTES,
          PdfSigner.CryptoStandard.CMS);
      return ensureSignatureWidgetsLinkedToPageAnnots(
          out.toByteArray(),
          pre.stampPageIndices0Based());
    }
  }

  /**
   * Some viewers render signature widgets only when each widget reference is
   * present in its page /Annots array. Ensure every /Sig widget kid is linked.
   */
  private static byte[] ensureSignatureWidgetsLinkedToPageAnnots(byte[] signedPdfBytes, List<Integer> expectedPages0Based)
      throws IOException, InvalidPdfException {
    try (PDDocument doc = PDDocument.load(signedPdfBytes)) {
      COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
      COSDictionary acroForm = catalog.getCOSDictionary(COSName.ACRO_FORM);
      if (acroForm == null) {
        throw new InvalidPdfException("Signed PDF is missing AcroForm");
      }
      COSArray fields = acroForm.getCOSArray(COSName.FIELDS);
      if (fields == null || fields.size() == 0) {
        throw new InvalidPdfException("Signed PDF contains no form fields");
      }
      boolean changed = false;
      for (int i = 0; i < fields.size(); i++) {
        COSDictionary fieldDict = asCosDictionary(fields.get(i));
        if (fieldDict == null || !COSName.SIG.equals(fieldDict.getCOSName(COSName.FT))) {
          continue;
        }
        COSArray kids = fieldDict.getCOSArray(COSName.KIDS);
        if (kids == null || kids.size() == 0) {
          continue;
        }
        for (int k = 0; k < kids.size(); k++) {
          COSBase kidRef = kids.get(k);
          COSDictionary kidDict = asCosDictionary(kidRef);
          if (kidDict == null || !COSName.getPDFName("Widget").equals(kidDict.getCOSName(COSName.SUBTYPE))) {
            continue;
          }
          COSDictionary pageDict = asCosDictionary(kidDict.getDictionaryObject(COSName.P));
          if (pageDict == null) {
            continue;
          }
          COSBase annotsBase = pageDict.getDictionaryObject(COSName.ANNOTS);
          COSArray annots;
          if (annotsBase instanceof COSArray arr) {
            annots = arr;
          } else {
            annots = new COSArray();
            pageDict.setItem(COSName.ANNOTS, annots);
            changed = true;
          }
          boolean exists = false;
          for (int a = 0; a < annots.size(); a++) {
            COSBase existing = annots.get(a);
            if (existing == kidRef || asCosDictionary(existing) == kidDict) {
              exists = true;
              break;
            }
          }
          if (!exists) {
            annots.add(kidRef);
            changed = true;
          }
        }
      }
      if (!changed) {
        validateSignatureWidgetCoverage(doc, expectedPages0Based);
        return signedPdfBytes;
      }
      try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
        doc.save(out);
        byte[] normalized = out.toByteArray();
        try (PDDocument reloaded = PDDocument.load(normalized)) {
          validateSignatureWidgetCoverage(reloaded, expectedPages0Based);
        }
        return normalized;
      }
    }
  }

  private static void validateSignatureWidgetCoverage(PDDocument doc, List<Integer> expectedPages0Based)
      throws InvalidPdfException {
    if (expectedPages0Based == null || expectedPages0Based.isEmpty()) {
      return;
    }
    for (int pageIndex : expectedPages0Based) {
      if (pageIndex < 0 || pageIndex >= doc.getNumberOfPages()) {
        throw new InvalidPdfException("Invalid expected stamp page index: " + pageIndex);
      }
      COSDictionary pageDict = doc.getPage(pageIndex).getCOSObject();
      COSBase annotsBase = pageDict.getDictionaryObject(COSName.ANNOTS);
      if (!(annotsBase instanceof COSArray annots) || annots.size() == 0) {
        throw new InvalidPdfException("Missing signature widget annotations on stamped page " + (pageIndex + 1));
      }
      boolean hasSigWidget = false;
      for (int a = 0; a < annots.size(); a++) {
        COSDictionary annot = asCosDictionary(annots.get(a));
        if (annot == null || !COSName.getPDFName("Widget").equals(annot.getCOSName(COSName.SUBTYPE))) {
          continue;
        }
        COSName ft = annot.getCOSName(COSName.FT);
        if (ft == null) {
          COSDictionary parent = asCosDictionary(annot.getDictionaryObject(COSName.PARENT));
          ft = parent != null ? parent.getCOSName(COSName.FT) : null;
        }
        if (COSName.SIG.equals(ft)) {
          hasSigWidget = true;
          break;
        }
      }
      if (!hasSigWidget) {
        throw new InvalidPdfException("No visible signature widget linked on stamped page " + (pageIndex + 1));
      }
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
      int pageIndex0Based,
      PDRectangle rect,
      PdfSigningOptions opts) {
    PdfSignatureAppearance appearance = signer.getSignatureAppearance();
    appearance.setPageNumber(pageIndex0Based + 1);
    appearance.setPageRect(toItextRectangle(rect));

    // String resolvedReason = resolveReason(reason, opts.finalVersion());

    if (reason != null && !reason.isBlank()) {
      appearance.setReason(reason.trim());
    }
    if (location != null && !location.isBlank()) {
      appearance.setLocation(location);
    }
    appearance.setCertificate(material.signingCertificate());
    appearance.setLayer2Text(
        buildAppearanceText(material.signingCertificate(), reason, location, opts.finalVersion()));
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
      // sb.append("FINAL VERSION\nNo further edits permitted.\n");
      sb.append("FINAL VERSION\n");
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

  // private static String resolveReason(String reason, boolean finalVersion) {
  //   if (reason != null && !reason.isBlank()) {
  //     String t = reason.trim();
  //     return finalVersion ? t + FINAL_VERSION_REASON_SUFFIX : t;
  //   }
  //   return finalVersion
  //       ? "TrustSign digital signature" + FINAL_VERSION_REASON_SUFFIX
  //       : "TrustSign digital signature";
  // }

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

  /**
   * Ensures target pages have an /Annots array before iText widget insertion.
   * This avoids a renderer gap where page 1 can miss visible signature widgets
   * even though the widget exists in AcroForm Kids.
   */
  private static byte[] ensureAnnotsArrayOnTargetPages(byte[] pdfBytes, List<Integer> stampPageIndices)
      throws IOException, InvalidPdfException {
    try (PDDocument doc = PDDocument.load(pdfBytes)) {
      int pageCount = doc.getNumberOfPages();
      if (pageCount == 0) {
        throw new InvalidPdfException("PDF has no pages");
      }
      List<Integer> targetPages = resolveStampPages(pageCount, stampPageIndices);
      boolean changed = false;
      for (int pageIndex : targetPages) {
        PDPage page = doc.getPage(pageIndex);
        COSDictionary pageDict = page.getCOSObject();
        COSBase annots = pageDict.getDictionaryObject(COSName.ANNOTS);
        if (!(annots instanceof COSArray)) {
          pageDict.setItem(COSName.ANNOTS, new COSArray());
          changed = true;
        }
      }
      if (!changed) {
        return pdfBytes;
      }
      try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
        doc.save(out);
        return out.toByteArray();
      }
    }
  }

  private static boolean signatureContentsLookSigned(byte[] contents) {
    if (contents == null || contents.length < 128) {
      return false;
    }
    int offset = 0;
    if ((contents[offset] & 0xff) != 0x30) {
      return false;
    }
    DerLength outerLen = readDerLength(contents, offset + 1);
    if (outerLen == null) {
      return false;
    }
    int outerContentEnd = outerLen.nextOffset() + outerLen.value();
    if (outerContentEnd > contents.length) {
      return false;
    }
    offset = outerLen.nextOffset();
    if ((contents[offset] & 0xff) != 0x06) {
      return false;
    }
    DerLength oidLen = readDerLength(contents, offset + 1);
    if (oidLen == null || oidLen.value() != SIGNED_DATA_OID.length) {
      return false;
    }
    int oidStart = oidLen.nextOffset();
    int oidEnd = oidStart + oidLen.value();
    if (oidEnd > contents.length) {
      return false;
    }
    return Arrays.equals(Arrays.copyOfRange(contents, oidStart, oidEnd), SIGNED_DATA_OID);
  }

  private static DerLength readDerLength(byte[] data, int offset) {
    if (data == null || offset < 0 || offset >= data.length) {
      return null;
    }
    int first = data[offset] & 0xff;
    if ((first & 0x80) == 0) {
      return new DerLength(first, offset + 1);
    }
    int numLenBytes = first & 0x7f;
    if (numLenBytes == 0 || numLenBytes > 4 || offset + 1 + numLenBytes > data.length) {
      return null;
    }
    int len = 0;
    for (int i = 0; i < numLenBytes; i++) {
      len = (len << 8) | (data[offset + 1 + i] & 0xff);
    }
    return new DerLength(len, offset + 1 + numLenBytes);
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

  private static List<Integer> resolveStampPages(int pageCount, List<Integer> stampPageIndices)
      throws InvalidPdfException {
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
    if (stampPageIndices.contains(-2)) {
      return List.of(pageCount - 1);
    }
    Set<Integer> unique = new LinkedHashSet<>();
    for (Integer idx : stampPageIndices) {
      if (idx == null) {
        throw new InvalidPdfException("stampPageIndices contains null");
      }
      if (idx <= -1001) {
        int startPage1 = -1000 - idx;
        int startIndex = startPage1 - 1;
        if (startIndex < 0 || startIndex >= pageCount) {
          throw new InvalidPdfException("startPage is out-of-range: " + startPage1);
        }
        for (int p = startIndex; p < pageCount; p++) {
          unique.add(p);
        }
        continue;
      }
      if (idx < 0 || idx >= pageCount) {
        throw new InvalidPdfException("stampPageIndices contains out-of-range index: " + idx);
      }
      unique.add(idx);
    }
    if (unique.isEmpty()) {
      throw new InvalidPdfException("stampPageIndices resolved to empty set");
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
