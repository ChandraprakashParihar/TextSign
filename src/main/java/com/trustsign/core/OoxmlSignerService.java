package com.trustsign.core;

import org.apache.poi.EncryptedDocumentException;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackageAccess;
import org.apache.poi.openxml4j.opc.PackagePartName;
import org.apache.poi.openxml4j.opc.PackagingURIHelper;
import org.apache.poi.poifs.crypt.dsig.SignatureConfig;
import org.apache.poi.poifs.crypt.dsig.SignatureInfo;
import org.apache.poi.poifs.crypt.dsig.facets.KeyInfoSignatureFacet;
import org.apache.poi.poifs.crypt.dsig.facets.OOXMLSignatureFacet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Adds a real, native OOXML digital signature to any OOXML package — .xlsx
 * (Excel), .docx (Word), or .pptx (PowerPoint) — recognized by Office itself
 * (File &gt; Info &gt; View Signatures), unlike a detached/appended
 * signature. The OOXML digital-signature mechanism (Open Packaging
 * Conventions + Apache POI's {@code poifs.crypt.dsig}) is entirely
 * format-agnostic: it operates on the {@link OPCPackage} container that
 * underlies all three formats, not on spreadsheet/document/presentation
 * content, so one implementation serves all three.
 */
public final class OoxmlSignerService {

  private static final Logger LOG = LoggerFactory.getLogger(OoxmlSignerService.class);

  /**
   * The OOXML formats this service supports, plus the per-format metadata
   * needed for user-facing messages and to sanity-check that an upload
   * actually is what the caller claims (e.g. reject a .pptx posted to the
   * Word endpoint) via presence of that format's well-known main part.
   */
  public enum OoxmlFormat {
    XLSX("Excel workbook", "workbook.xlsx", "/xl/workbook.xml"),
    DOCX("Word document", "document.docx", "/word/document.xml"),
    PPTX("PowerPoint presentation", "presentation.pptx", "/ppt/presentation.xml");

    private final String label;
    private final String defaultFilename;
    private final String mainPartName;

    OoxmlFormat(String label, String defaultFilename, String mainPartName) {
      this.label = label;
      this.defaultFilename = defaultFilename;
      this.mainPartName = mainPartName;
    }

    public String label() {
      return label;
    }

    public String defaultFilename() {
      return defaultFilename;
    }
  }

  /**
   * Serializes registration/teardown of the temporary narrow signature
   * provider below across concurrent OOXML-signing calls — see
   * {@link #withShimmedSunRsaSign}.
   */
  private static final Object PROVIDER_ELEVATION_LOCK = new Object();

  public static byte[] sign(
      byte[] ooxmlBytes,
      OoxmlFormat format,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider) throws Exception {
    if (ooxmlBytes == null || ooxmlBytes.length == 0) {
      throw new IllegalArgumentException("file bytes are empty");
    }
    if (format == null) {
      throw new IllegalArgumentException("format is null");
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

    List<X509Certificate> certChain = new ArrayList<>();
    for (Certificate c : chain) {
      if (c instanceof X509Certificate x509) {
        certChain.add(x509);
      }
    }
    if (certChain.isEmpty()) {
      throw new IllegalArgumentException("certificate chain does not contain X509Certificate entries");
    }

    X509Certificate signer = certChain.get(0);
    long start = System.currentTimeMillis();
    LOG.info("Starting {} signing. fileBytes={}, signerSubject={}, signerSerial={}",
        format.label(), ooxmlBytes.length, signer.getSubjectX500Principal().getName(),
        signer.getSerialNumber().toString(16));

    // OPCPackage.open(InputStream) is read-only; modifying + saving a package
    // requires opening it from a File with READ_WRITE access, so the uploaded
    // bytes are staged to a temp file for the duration of signing.
    Path tempFile = createRestrictedTempFile();
    try {
      Files.write(tempFile, ooxmlBytes);
      try (OPCPackage pkg = openForSigning(tempFile, format)) {
        SignatureConfig sigConfig = new SignatureConfig();
        sigConfig.setKey(privateKey);
        sigConfig.setSigningCertificateChain(certChain);
        // POI's default facet list (OOXMLSignatureFacet, KeyInfoSignatureFacet,
        // XAdESSignatureFacet, Office2010SignatureFacet) produces a valid
        // signature that POI's own validator accepts, but real Microsoft
        // Office's native signature reader does not understand the extra
        // objects it adds — confirmed by diffing against a signature from a
        // different tool (System.IO.Packaging-based) that Office DOES accept:
        // that file has only a Manifest + KeyInfo, nothing else. Office's
        // "Unknown signer" / "01-01-1601" (the Windows FILETIME epoch, i.e. a
        // failed date parse) are exactly the symptoms of Office choking on a
        // SigningTime/date field it doesn't expect. This was diagnosed against
        // Excel specifically, but the signature mechanism (and therefore the
        // fix) is shared by Word/PowerPoint — same OPC container, same POI
        // signing code path.
        //
        // Dropping XAdESSignatureFacet/Office2010SignatureFacet from the list
        // isn't enough on its own: OOXMLSignatureFacet.preSign unconditionally
        // calls its own addSignatureInfo(), which independently emits an
        // "idOfficeObject" containing a Microsoft SignatureInfoV1 element —
        // that method is separate from Office2010SignatureFacet and has no
        // config flag to disable it. MinimalOOXMLSignatureFacet below
        // overrides that one protected method to a no-op, keeping only
        // addManifestObject()'s output (Manifest + SignatureProperties/
        // SignatureTime), which matches the known-good reference format.
        sigConfig.setSignatureFacets(List.of(new MinimalOOXMLSignatureFacet(), new KeyInfoSignatureFacet()));
        sigConfig.setIncludeKeyValue(true);
        // The known-good reference file embeds only the leaf certificate in
        // KeyInfo/X509Data (confirmed by counting <X509Certificate> elements:
        // 1 there vs POI's default of 4 — the full leaf+SubCA+CA+root chain).
        // Relying parties are expected to build the rest of the chain via the
        // leaf cert's AIA extension, same as this codebase's PDF signing does.
        sigConfig.setIncludeEntireCertificateChain(false);
        // Apache Santuario 3.0.6 (the XML-DSig engine POI/SignatureConfig
        // delegates to) hardcodes a cap of 30 <Reference> elements per
        // <Manifest> whenever secure validation is on (POI's default) —
        // confirmed by decompiling DOMManifest.class, not documented in any
        // config option. A real OOXML package routinely exceeds this: even a
        // minimal single-slide .pptx (theme + slide master + default slide
        // layouts + the one slide) needs more than 30 manifest references,
        // so this isn't a corner case — it reproducibly breaks PowerPoint
        // signing (and would break Word/Excel files with enough parts too)
        // with "MarshalException: A maximum of 30 references per Manifest
        // are allowed with secure validation" during self-verification.
        // There is no narrower POI/Santuario knob to just raise the limit —
        // secure validation is a single on/off switch. Disabling it here is
        // an accepted trade-off given the endpoint's context: uploads are
        // already bounded by this server's multipart size limit, which
        // already caps how many parts (and therefore references) a package
        // can plausibly contain, and this is an authenticated internal
        // signing service, not a public endpoint processing arbitrary
        // untrusted XML at scale — the DoS scenario secure validation
        // defends against.
        sigConfig.setSecureValidation(false);

        SignatureInfo signatureInfo = new SignatureInfo();
        signatureInfo.setOpcPackage(pkg);
        signatureInfo.setSignatureConfig(sigConfig);
        // Do NOT call signatureInfo.setProvider(p11Provider) here: that
        // property selects the provider for the JSR-105 XMLSignatureFactory
        // "DOM" mechanism itself (confirmed via testing — passing a
        // non-XML-mechanism provider like a PKCS#11 token or BouncyCastle
        // throws NoSuchMechanismException), not the provider used for the RSA
        // signing operation. POI offers no separate hook to force that.
        //
        // POI's internal RSA operation (org.apache.poi.poifs.crypt.dsig.
        // SignatureOutputStream) does NOT do a priority-based JCA lookup at
        // all — confirmed from POI's own source: it hardcodes
        // Signature.getInstance(alg, isMSCapi(key) ? "SunMSCAPI" : "SunRsaSign").
        // A PKCS#11 key is never MSCAPI, so it always resolves to the real
        // "SunRsaSign" by NAME, which then throws InvalidKeyException: Missing
        // key encoding trying to inspect the token's non-extractable key (a
        // known, unresolved upstream limitation — see OpenSC/OpenSC#3247).
        // Because the lookup is name-qualified, no amount of provider-priority
        // reordering can redirect it (two earlier attempts at that — elevating
        // p11Provider itself, then a narrow custom-named Signature-only
        // provider — both left this specific call unaffected).
        //
        // Fix: temporarily replace what's registered under the name
        // "SunRsaSign" with a shim that is scoped to this exact PrivateKey
        // object. For our key, it delegates to Signature.getInstance(alg,
        // p11Provider) (the standard explicit-binding pattern used elsewhere
        // in this codebase); for every other key (i.e. anything from an
        // unrelated, concurrent operation) and every non-Signature service
        // (KeyFactory, KeyPairGenerator, etc.), it forwards unchanged to the
        // real original SunRsaSign provider object — which remains fully
        // usable via its own object reference even while its registry name is
        // shadowed. Synchronized and torn down in a finally block so the
        // shadowing window is as short as possible and never leaks.
        withShimmedSunRsaSign(privateKey, p11Provider, signatureInfo::confirmSignature);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        pkg.save(out);
        byte[] signedBytes = out.toByteArray();

        // Never hand back a signature we can prove is broken: re-validate
        // immediately, server-side, with the same logic /verify-* uses. This
        // also makes the failure mode loud and diagnosable (which specific
        // signature POI itself considers invalid, and why) instead of only
        // surfacing when a client opens the file in Office.
        long verifyStart = System.currentTimeMillis();
        OoxmlVerifyService.Result selfCheck = OoxmlVerifyService.verify(signedBytes);
        long verifyMs = System.currentTimeMillis() - verifyStart;
        if (!selfCheck.ok()) {
          LOG.warn("{} self-verification failed after signing in {} ms: {}", format.label(), verifyMs, selfCheck.reason());
          throw new IllegalStateException(
              "Produced signature failed self-verification: " + selfCheck.reason()
                  + (selfCheck.signatures().isEmpty() ? "" : " (" + selfCheck.signatures().get(0).reason() + ")"));
        }

        LOG.info("{} signing completed in {} ms (self-verification {} ms).",
            format.label(), System.currentTimeMillis() - start, verifyMs);
        return signedBytes;
      }
    } catch (Exception e) {
      LOG.warn("{} signing failed after {} ms for signerSerial={}: {}",
          format.label(), System.currentTimeMillis() - start, signer.getSerialNumber().toString(16), safeMsg(e));
      throw e;
    } finally {
      Files.deleteIfExists(tempFile);
    }
  }

  /**
   * Creates the staging temp file with owner-only access where the platform
   * supports POSIX permissions (Files.createTempFile already restricts to the
   * owner by default per its javadoc, but this makes the intent explicit and
   * defends against a platform where that default doesn't hold). Also
   * registers {@code deleteOnExit()} as a second line of defense alongside
   * the caller's finally-block delete — covers a normal JVM shutdown that
   * skips the finally block (e.g. System.exit from unrelated code), though
   * neither this nor any other in-process mechanism can run on a hard kill
   * (SIGKILL/OOM-killer/power loss); a periodic ops-level sweep of the temp
   * directory for orphaned "trustsign-ooxml-*" files is the correct backstop
   * for that case, not application code.
   */
  private static Path createRestrictedTempFile() throws java.io.IOException {
    boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    Path tempFile;
    if (posix) {
      Set<PosixFilePermission> ownerOnly = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
      FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(ownerOnly);
      tempFile = Files.createTempFile("trustsign-ooxml-", ".ooxml", attr);
    } else {
      tempFile = Files.createTempFile("trustsign-ooxml-", ".ooxml");
    }
    tempFile.toFile().deleteOnExit();
    return tempFile;
  }

  /**
   * Same as {@link OOXMLSignatureFacet} except it omits the Microsoft
   * "idOfficeObject"/SignatureInfoV1 object — see the comment where this is
   * used in {@link #sign} for why: Office's own signature reader doesn't
   * recognize it and rejects the whole signature as a result.
   */
  private static final class MinimalOOXMLSignatureFacet extends OOXMLSignatureFacet {
    @Override
    protected void addSignatureInfo(
        SignatureInfo signatureInfo, Document document, List<Reference> references, List<XMLObject> objects) {
      // Intentionally no-op — see class Javadoc.
    }
  }

  private interface ThrowingAction {
    void run() throws Exception;
  }

  private static final String SUN_RSA_SIGN = "SunRsaSign";

  /**
   * Temporarily replaces the JCA registry entry for {@code "SunRsaSign"} —
   * the exact provider name POI's SignatureOutputStream hardcodes for any
   * non-MSCAPI key — with a shim scoped to {@code expectedKey}, for the
   * duration of {@code action}. Restores the real provider afterward, even if
   * {@code action} throws. Synchronized so overlapping OOXML-signing calls
   * can't interleave their own shim/restore steps.
   *
   * <p>This mutates JVM-global JCA state, which is a real and deliberate
   * trade-off, not an oversight: {@code Signature.getInstance(alg, "SunRsaSign")}
   * is a name-qualified lookup, and the JCA API has no way to intercept a
   * name-qualified lookup other than controlling what is registered under
   * that exact name — there is no "scoped" or "thread-local" provider
   * registry. Concretely:
   * <ul>
   *   <li><b>Concurrent unrelated signing (JWT/TLS/other PDF signing, etc.)
   *   is not broken by this.</b> Any code elsewhere in the JVM that resolves
   *   "SunRsaSign" while this shim is installed gets a {@link Provider.Service}
   *   whose {@code newInstance} always returns a working {@link Signature}; the
   *   shim only special-cases the exact {@code expectedKey} instance (by
   *   reference) inside {@code engineInitSign} — every other key, from any
   *   other concurrent caller, is forwarded unchanged to the real, original
   *   "SunRsaSign" provider object.
   *   <li><b>The remaining, unavoidable risk</b> is the brief gap between
   *   {@code Security.removeProvider(SUN_RSA_SIGN)} and the following
   *   {@code Security.insertProviderAt(...)}: for those two back-to-back JVM
   *   calls (no I/O or blocking between them), the name "SunRsaSign" resolves
   *   to nothing. Unrelated code that happens to call
   *   {@code Signature.getInstance(alg, "SunRsaSign")} in that exact window
   *   would get a transient {@code NoSuchProviderException} — the JCA API
   *   offers no atomic "replace" operation to close this gap. This is a
   *   correctness-neutral (no wrong output, no security exposure), narrow,
   *   accepted trade-off given POI leaves no other integration point.
   * </ul>
   */
  private static void withShimmedSunRsaSign(
      PrivateKey expectedKey, Provider p11Provider, ThrowingAction action) throws Exception {
    synchronized (PROVIDER_ELEVATION_LOCK) {
      Provider real = Security.getProvider(SUN_RSA_SIGN);
      if (real == null) {
        // Nothing to shim against on this JVM — fall through and let it fail
        // with whatever error it would have without this workaround.
        action.run();
        return;
      }
      int originalPosition = currentProviderPosition(real);
      Security.removeProvider(SUN_RSA_SIGN);
      Security.insertProviderAt(keyAwareShim(real, expectedKey, p11Provider), 1);
      try {
        action.run();
      } finally {
        Security.removeProvider(SUN_RSA_SIGN);
        Security.insertProviderAt(real, originalPosition > 0 ? originalPosition : 1);
      }
    }
  }

  private static int currentProviderPosition(Provider provider) {
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      if (providers[i] == provider) {
        return i + 1;
      }
    }
    return -1;
  }

  /**
   * Builds a same-named replacement for {@code real} ("SunRsaSign") that
   * forwards every service unchanged to {@code real} itself, EXCEPT
   * "Signature" services when initialized with {@code expectedKey} — those
   * are redirected to {@code Signature.getInstance(alg, p11Provider)}, the
   * standard explicit-binding pattern already used elsewhere in this
   * codebase. Any other key (e.g. from an unrelated concurrent operation)
   * hitting a Signature service here still resolves to {@code real}'s own
   * implementation, so this is safe to run alongside unrelated concurrent
   * signing/verification.
   */
  private static Provider keyAwareShim(Provider real, PrivateKey expectedKey, Provider p11Provider) {
    // putService(...) is `protected` on Provider — must be called from code
    // that is itself part of the subclass, hence the instance initializer
    // block below rather than calling it externally on a reference.
    return new Provider(real.getName(), real.getVersionStr(), "TrustSign PKCS#11-aware shim for " + real.getName()) {
      {
        for (Provider.Service realService : real.getServices()) {
          boolean isSignature = "Signature".equals(realService.getType());
          putService(new Provider.Service(
              this, realService.getType(), realService.getAlgorithm(), realService.getClassName(),
              List.of(), null) {
            @Override
            public Object newInstance(Object constructorParameter) throws java.security.NoSuchAlgorithmException {
              if (isSignature) {
                return new KeyAwareSignatureSpi(realService.getAlgorithm(), expectedKey, p11Provider, real);
              }
              return realService.newInstance(constructorParameter);
            }
          });
        }
      }
    };
  }

  /**
   * A {@link SignatureSpi} that routes to {@code p11Provider} only when
   * initialized with {@code expectedKey} (reference equality — the exact
   * object threaded through from {@code SignatureConfig.setKey}); every other
   * key (sign or verify) is forwarded to {@code fallbackProvider} (the real,
   * original "SunRsaSign"). Only ever reached via {@link #keyAwareShim}'s
   * {@code newInstance} override, never instantiated by JCA's normal no-arg
   * reflection path.
   *
   * <p>Reference equality is safe against the current POI 5.5.1 call chain —
   * verified directly from POI's own source, not assumed:
   * {@code SignatureInfo.confirmSignature()} reads {@code signatureConfig.getKey()}
   * once into a local {@code key} variable (SignatureInfo.java:256), and that
   * exact reference is what reaches {@code SignatureOutputStream}'s
   * constructor (SignatureInfo.java:287) and ultimately
   * {@code signature.initSign(key)} inside {@code SignatureOutputStream.init()}
   * — no wrapping or copying anywhere in between. If a future POI version
   * changes that (e.g. wraps the key), this check fails closed, not open: a
   * key that doesn't match {@code expectedKey} by reference falls back to
   * {@code fallbackProvider}, reproducing the original, loud
   * {@code InvalidKeyException: Missing key encoding} rather than silently
   * misrouting anything.
   */
  private static final class KeyAwareSignatureSpi extends SignatureSpi {
    private final String algorithm;
    private final PrivateKey expectedKey;
    private final Provider targetProvider;
    private final Provider fallbackProvider;
    private Signature delegate;

    KeyAwareSignatureSpi(String algorithm, PrivateKey expectedKey, Provider targetProvider, Provider fallbackProvider) {
      this.algorithm = algorithm;
      this.expectedKey = expectedKey;
      this.targetProvider = targetProvider;
      this.fallbackProvider = fallbackProvider;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
      try {
        Provider chosen = (privateKey == expectedKey) ? targetProvider : fallbackProvider;
        delegate = Signature.getInstance(algorithm, chosen);
        delegate.initSign(privateKey);
      } catch (GeneralSecurityException e) {
        throw new InvalidKeyException(e);
      }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
      try {
        // Verification never involves our PKCS#11 private key; always use the real provider.
        delegate = Signature.getInstance(algorithm, fallbackProvider);
        delegate.initVerify(publicKey);
      } catch (GeneralSecurityException e) {
        throw new InvalidKeyException(e);
      }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
      try {
        delegate.update(b);
      } catch (GeneralSecurityException e) {
        throw new SignatureException(e);
      }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
      try {
        delegate.update(b, off, len);
      } catch (GeneralSecurityException e) {
        throw new SignatureException(e);
      }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
      try {
        return delegate.sign();
      } catch (GeneralSecurityException e) {
        throw new SignatureException(e);
      }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
      try {
        return delegate.verify(sigBytes);
      } catch (GeneralSecurityException e) {
        throw new SignatureException(e);
      }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
      throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
      throw new UnsupportedOperationException();
    }
  }

  /**
   * Confirms {@code ooxmlBytes} is a readable, non-encrypted OOXML package
   * that actually looks like {@code expectedFormat} — checked via presence of
   * that format's well-known main part (e.g. {@code /xl/workbook.xml} for
   * Excel) — before any token/certificate work is done. Catches both "not a
   * valid OOXML file at all" and "valid OOXML but the wrong kind, e.g. a
   * .pptx posted to the Word endpoint" with a clear 400 instead of a cryptic
   * POI exception or a silently mislabeled but "successful" signature.
   */
  public static void validateOpenable(byte[] ooxmlBytes, OoxmlFormat expectedFormat) throws Exception {
    try (OPCPackage pkg = OPCPackage.open(new ByteArrayInputStream(ooxmlBytes))) {
      PackagePartName mainPart = PackagingURIHelper.createPartName(expectedFormat.mainPartName);
      if (pkg.getPart(mainPart) == null) {
        throw new IllegalArgumentException(
            "Uploaded file does not look like a " + expectedFormat.label()
                + " (missing " + expectedFormat.mainPartName + "). Wrong endpoint, or wrong file?");
      }
    } catch (EncryptedDocumentException e) {
      throw new IllegalArgumentException(
          expectedFormat.label() + " is password-protected/encrypted and cannot be signed", e);
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "Uploaded file is not a valid " + expectedFormat.label() + " (OOXML) package: " + safeMsg(e), e);
    }
  }

  /**
   * Opens the staged file as a read-write OPC package, translating POI's own
   * "this isn't a valid/encrypted OOXML package" failures into a clear error
   * instead of a raw POI exception.
   */
  private static OPCPackage openForSigning(Path tempFile, OoxmlFormat format) throws Exception {
    try {
      return OPCPackage.open(tempFile.toFile(), PackageAccess.READ_WRITE);
    } catch (EncryptedDocumentException e) {
      throw new IllegalArgumentException(format.label() + " is password-protected/encrypted and cannot be signed", e);
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "Uploaded file is not a valid " + format.label() + " (OOXML) package: " + safeMsg(e), e);
    }
  }

  private static String safeMsg(Throwable t) {
    String m = t.getMessage();
    return (m != null && !m.isBlank()) ? m : t.getClass().getSimpleName();
  }

  private OoxmlSignerService() {}
}
