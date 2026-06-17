package com.trustsign.core;

import com.trustsign.hsm.HsmPkcs11ConfigurationService;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * PDF signing via PKCS#11 using libraries from {@code config.hsm}, with PIN and signer certificate (.cer) supplied per request.
 * Slot selection and PKCS#11 configuration are handled by {@link HsmPkcs11ConfigurationService} (multi-slot HSM).
 * Delegates PDF construction to {@link PdfSignerService} after resolving key material from the token.
 */
public final class HsmPdfSignerService {

  public record SignResult(byte[] signedPdf, X509Certificate signingCertificate) {}

  /**
   * Sign PDF using uploaded .cer for key matching (existing flow).
   */
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

    char[] pinCopy = Arrays.copyOf(pin, pin.length);
    try {
      List<X509Certificate> provided = SigningCertificateParser.parseFromUpload(cerBytes);
      if (provided.isEmpty()) throw new IllegalArgumentException("cer did not contain a usable X.509 certificate");

      HsmPkcs11ConfigurationService.MatchedSlotLoad matched =
          HsmPkcs11ConfigurationService.loadMatchingSlot(pinCopy, libraryCandidates, provided, slotProbeCount);
      return signWithMatchedSlot(pdfBytes, pinCopy, matched, reason, location, stampPages, signingOptions);
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

  private static Certificate[] certificateChainOrSingle(TokenCertificateSelector.Selection selection) {
    Certificate[] chain = selection.chain();
    if (chain != null && chain.length > 0) {
      return chain;
    }
    return new Certificate[] { selection.certificate() };
  }

  private HsmPdfSignerService() {}
}
