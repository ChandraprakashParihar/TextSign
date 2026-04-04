package com.trustsign.core;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * PDF signing via PKCS#11 using libraries from {@code config.hsm}, with PIN and signer public key supplied per request.
 * Delegates PDF construction to {@link PdfSignerService} after resolving key material from the token.
 */
public final class HsmPdfSignerService {

  public record SignResult(byte[] signedPdf, X509Certificate signingCertificate) {}

  public static SignResult signPdfWithMetadata(
      byte[] pdfBytes,
      char[] pin,
      String publicKeyPemOrBase64,
      List<String> libraryCandidates,
      String reason,
      String location,
      List<Integer> stampPages) throws Exception {
    validateRequest(pdfBytes, pin, publicKeyPemOrBase64, libraryCandidates);

    char[] pinCopy = Arrays.copyOf(pin, pin.length);
    try {
      PdfSignerService.PdfSigningMaterial material = loadSigningMaterial(pinCopy, publicKeyPemOrBase64, libraryCandidates);
      CertificateValidator.validateForSigning(material.signingCertificate(), material.x509ChainOrNull());

      byte[] signed = PdfSignerService.signPdf(pdfBytes, material, reason, location, stampPages);
      return new SignResult(signed, material.signingCertificate());
    } finally {
      Arrays.fill(pinCopy, '\0');
    }
  }

  private static void validateRequest(
      byte[] pdfBytes,
      char[] pin,
      String publicKeyPemOrBase64,
      List<String> libraryCandidates) {
    if (pdfBytes == null || pdfBytes.length == 0) {
      throw new IllegalArgumentException("pdfBytes is empty");
    }
    if (pin == null || pin.length == 0) {
      throw new IllegalArgumentException("pin is required");
    }
    if (publicKeyPemOrBase64 == null || publicKeyPemOrBase64.isBlank()) {
      throw new IllegalArgumentException("publicKey is required");
    }
    if (libraryCandidates == null || libraryCandidates.isEmpty()) {
      throw new IllegalStateException(
          "No PKCS#11 library paths configured for HSM. Set config.json \"hsm\" (preferredLibrary and/or OS candidate lists).");
    }
  }

  private static PdfSignerService.PdfSigningMaterial loadSigningMaterial(
      char[] pinCopy,
      String publicKeyPemOrBase64,
      List<String> libraryCandidates) throws Exception {
    List<PublicKey> requested = SigningPublicKeyParser.parsePublicKeys(publicKeyPemOrBase64);
    if (requested.isEmpty()) {
      throw new IllegalArgumentException("publicKey did not contain a usable RSA public key or certificate");
    }

    Pkcs11Token.Loaded loaded = Pkcs11Token.load(pinCopy, libraryCandidates);
    KeyStore ks = loaded.keyStore();

    TokenCertificateSelector.Selection selection = TokenCertificateSelector.select(ks, requested);
    if (selection == null) {
      throw new IllegalStateException("No certificate on the HSM token matches the provided public key");
    }

    PrivateKey key = (PrivateKey) ks.getKey(selection.alias(), pinCopy);
    if (key == null) {
      throw new IllegalStateException("No private key found for the matching certificate");
    }

    Certificate[] chain = certificateChainOrSingle(selection);
    return new PdfSignerService.PdfSigningMaterial(
        key,
        chain,
        loaded.provider(),
        selection.certificate());
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
