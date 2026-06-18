package com.trustsign.core;

import com.itextpdf.signatures.IExternalSignature;
import com.trustsign.hsm.HsmPkcs11ConfigurationService;
import com.trustsign.hsm.Pkcs11CertificateLinker;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * PDF signing via PKCS#11 using libraries from {@code config.hsm}, with PIN and signer certificate (.cer) supplied per request.
 * Slot selection and PKCS#11 configuration are handled by {@link HsmPkcs11ConfigurationService} (multi-slot HSM).
 * Delegates PDF construction to {@link PdfSignerService} after resolving key material from the token.
 *
 * When Java's KeyStore cannot find the private key (CKA_ID mismatch — common with Utimaco, Thales HSMs),
 * falls back to direct PKCS#11 signing via {@link Pkcs11CertificateLinker} which uses C_FindObjects + C_Sign,
 * the same approach used by C#/C++ signing utilities.
 */
public final class HsmPdfSignerService {

  private static final Logger LOG = LoggerFactory.getLogger(HsmPdfSignerService.class);

  public record SignResult(byte[] signedPdf, X509Certificate signingCertificate) {}

  public static SignResult signPdfWithMetadata(
      byte[] pdfBytes,
      char[] pin,
      byte[] cerBytes,
      List<String> libraryCandidates,
      int slotProbeCount,
      String reason,
      String location,
      List<Integer> stampPages,
      PdfSignerService.PdfSigningOptions signingOptions) throws Exception {
    if (pdfBytes == null || pdfBytes.length == 0) throw new IllegalArgumentException("pdfBytes is empty");
    if (pin == null || pin.length == 0) throw new IllegalArgumentException("pin is required");
    if (cerBytes == null || cerBytes.length == 0) throw new IllegalArgumentException("cer is required");
    if (libraryCandidates == null || libraryCandidates.isEmpty())
      throw new IllegalStateException("No PKCS#11 library paths configured for HSM.");

    List<X509Certificate> provided = SigningCertificateParser.parseFromUpload(cerBytes);
    if (provided.isEmpty()) throw new IllegalArgumentException("cer did not contain a usable X.509 certificate");

    char[] pinCopy = Arrays.copyOf(pin, pin.length);
    try {
      // 1. Try standard Java KeyStore approach (works when CKA_ID links key ↔ cert)
      try {
        HsmPkcs11ConfigurationService.MatchedSlotLoad matched =
            HsmPkcs11ConfigurationService.loadMatchingSlot(pinCopy, libraryCandidates, provided, slotProbeCount);
        return signWithMatchedSlot(pdfBytes, pinCopy, matched, reason, location, stampPages, signingOptions);
      } catch (RuntimeException keystoreEx) {
        LOG.warn("KeyStore approach failed: {}. Trying direct PKCS#11 signing...", keystoreEx.getMessage());
      }

      // 2. Fallback: direct PKCS#11 C_Sign (bypasses KeyStore CKA_ID limitation)
      return signWithDirectPkcs11(pdfBytes, pinCopy, libraryCandidates, slotProbeCount,
          provided, reason, location, stampPages, signingOptions);
    } finally {
      Arrays.fill(pinCopy, '\0');
    }
  }

  private static SignResult signWithMatchedSlot(
      byte[] pdfBytes,
      char[] pinCopy,
      HsmPkcs11ConfigurationService.MatchedSlotLoad matched,
      String reason,
      String location,
      List<Integer> stampPages,
      PdfSignerService.PdfSigningOptions signingOptions) throws Exception {
    KeyStore ks = matched.keyStore();
    TokenCertificateSelector.Selection selection = matched.selection();

    PrivateKey key = (PrivateKey) ks.getKey(selection.alias(), pinCopy);
    if (key == null) {
      throw new IllegalStateException("No private key found for alias '" + selection.alias() + "'");
    }

    Certificate[] chain = certificateChainOrSingle(selection);
    PdfSignerService.PdfSigningMaterial material = new PdfSignerService.PdfSigningMaterial(
        key, chain, matched.provider(), selection.certificate());
    CertificateValidator.validateForSigning(material.signingCertificate(), material.x509ChainOrNull());

    PdfSignerService.PdfSigningOptions opts =
        signingOptions != null ? signingOptions : PdfSignerService.PdfSigningOptions.DEFAULT;
    PdfSignerService.PdfSigningResult signed = PdfSignerService.signPdf(
        pdfBytes, material, reason, location, stampPages, opts);
    return new SignResult(signed.signedPdf(), material.signingCertificate());
  }

  /**
   * Direct PKCS#11 signing — finds the RSA private key via C_FindObjects (matching modulus)
   * and signs via C_Sign, exactly like C#/C++ utilities do. No CKA_ID linking needed.
   */
  private static SignResult signWithDirectPkcs11(
      byte[] pdfBytes,
      char[] pin,
      List<String> libraryCandidates,
      int slotProbeCount,
      List<X509Certificate> provided,
      String reason,
      String location,
      List<Integer> stampPages,
      PdfSignerService.PdfSigningOptions signingOptions) throws Exception {

    int slots = HsmPkcs11ConfigurationService.normalizeSlotProbeCount(slotProbeCount);
    Provider foundProvider = null;
    String directSignError = null;

    for (String lib : libraryCandidates) {
      if (lib == null || lib.isBlank()) continue;
      java.nio.file.Path libPath = java.nio.file.Paths.get(lib);
      if (!java.nio.file.Files.isRegularFile(libPath)) continue;

      for (int slotIdx = 0; slotIdx < slots; slotIdx++) {
        Provider p11 = null;
        try {
          p11 = HsmPkcs11ConfigurationService.createProviderForSlot(libPath, slotIdx);
          if (java.security.Security.getProvider(p11.getName()) == null) {
            java.security.Security.addProvider(p11);
          }
          KeyStore ks = KeyStore.getInstance("PKCS11", p11);
          ks.load(null, pin);
          LOG.info("Direct PKCS#11: slot {} loaded OK, searching for matching RSA key...", slotIdx);

          long keyHandle = Pkcs11CertificateLinker.findMatchingKeyHandle(p11, provided);
          if (keyHandle >= 0) {
            LOG.info("Direct PKCS#11: FOUND matching RSA key on lib={} slot={} handle={}", lib, slotIdx, keyHandle);
            foundProvider = p11;
            break;
          } else {
            LOG.warn("Direct PKCS#11: slot {} loaded but findMatchingKeyHandle returned {} (no match or reflection failed)", slotIdx, keyHandle);
            if (directSignError == null) {
              directSignError = "Slot " + slotIdx + " loaded but no RSA key matched the uploaded certificate's modulus";
            }
          }
        } catch (Exception e) {
          // Only log non-PIN-init errors (slots 1-9 being uninitialized is normal)
          String msg = e.getMessage();
          if (msg != null && msg.contains("CKR_USER_PIN_NOT_INITIALIZED")) {
            LOG.debug("Direct PKCS#11: slot {} PIN not initialized, skipping", slotIdx);
          } else {
            LOG.warn("Direct PKCS#11: slot {} error: [{}] {}", slotIdx, e.getClass().getSimpleName(), msg);
            if (directSignError == null) directSignError = msg;
          }
        }
      }
      if (foundProvider != null) break;
    }

    if (foundProvider == null) {
      String hint = directSignError != null ? directSignError
          : "No matching RSA private key found on any accessible slot";
      throw new RuntimeException(
          "Both KeyStore and direct PKCS#11 approaches failed. " + hint +
          ". Verify: (1) the uploaded .cer matches a private key on the HSM, " +
          "(2) the JVM has --add-opens flags for jdk.crypto.cryptoki.", null);
    }

    X509Certificate signingCert = provided.get(0);
    Certificate[] chain = provided.toArray(new Certificate[0]);
    CertificateValidator.validateForSigning(signingCert,
        provided.stream().map(c -> (X509Certificate) c).toArray(X509Certificate[]::new));

    IExternalSignature directSig = new Pkcs11DirectSignature(foundProvider, provided);
    PdfSignerService.PdfSigningOptions opts =
        signingOptions != null ? signingOptions : PdfSignerService.PdfSigningOptions.DEFAULT;
    PdfSignerService.PdfSigningResult signed = PdfSignerService.signPdfWithExternalSignature(
        pdfBytes, directSig, chain, signingCert, foundProvider, reason, location, stampPages, opts);
    return new SignResult(signed.signedPdf(), signingCert);
  }

  /**
   * IExternalSignature that signs via direct PKCS#11 C_Sign, bypassing Java's KeyStore.
   */
  private static final class Pkcs11DirectSignature implements IExternalSignature {
    private final Provider provider;
    private final List<X509Certificate> certs;

    Pkcs11DirectSignature(Provider provider, List<X509Certificate> certs) {
      this.provider = provider;
      this.certs = certs;
    }

    @Override
    public String getHashAlgorithm() { return "SHA-256"; }

    @Override
    public String getEncryptionAlgorithm() { return "RSA"; }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
      byte[] sig = Pkcs11CertificateLinker.tryDirectSign(provider, message, certs);
      if (sig == null) {
        throw new GeneralSecurityException("Direct PKCS#11 C_Sign failed — no matching key or signing error");
      }
      return sig;
    }
  }

  private static Certificate[] certificateChainOrSingle(TokenCertificateSelector.Selection selection) {
    Certificate[] chain = selection.chain();
    if (chain != null && chain.length > 0) {
      return chain;
    }
    return new Certificate[] { selection.certificate() };
  }

  private HsmPdfSignerService() {}
}
