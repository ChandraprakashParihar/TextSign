package com.trustsign.core;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates enveloped XML-DSig signature(s) produced by {@link XmlSignerService}
 * (or any standards-compliant XML-DSig signer).
 */
public final class XmlVerifyService {

  public record CertificateDetails(
      String subject,
      String issuer,
      String serialNumber,
      String validFrom,
      String validTo,
      String algorithm) {}

  public record SignatureReport(boolean ok, String reason, CertificateDetails certificate) {}

  public record Result(boolean ok, String reason, int signatureCount, List<SignatureReport> signatures) {}

  public static Result verify(byte[] signedXmlBytes) {
    if (signedXmlBytes == null || signedXmlBytes.length == 0) {
      return new Result(false, "signedXmlBytes is empty", 0, List.of());
    }
    try {
      Document doc = XmlSecurity.parseHardened(signedXmlBytes);
      NodeList signatureNodes = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
      if (signatureNodes.getLength() == 0) {
        return new Result(false, "No XML Signature element found", 0, List.of());
      }

      XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
      List<SignatureReport> reports = new ArrayList<>();
      boolean allOk = true;

      for (int i = 0; i < signatureNodes.getLength(); i++) {
        Element sigElement = (Element) signatureNodes.item(i);
        X509KeySelector keySelector = new X509KeySelector();
        DOMValidateContext valContext = new DOMValidateContext(keySelector, sigElement);
        boolean coreValid;
        String reason;
        try {
          XMLSignature signature = fac.unmarshalXMLSignature(valContext);
          coreValid = signature.validate(valContext);
          reason = coreValid ? "Signature valid" : "Signature or reference validation failed";
        } catch (Exception e) {
          coreValid = false;
          reason = safeMsg(e);
        }
        CertificateDetails certDetails = keySelector.resolvedCertificate() == null
            ? null
            : toCertificateDetails(keySelector.resolvedCertificate());
        reports.add(new SignatureReport(coreValid, reason, certDetails));
        if (!coreValid) {
          allOk = false;
        }
      }

      return new Result(
          allOk,
          allOk ? "All signatures valid" : "One or more signatures failed validation",
          signatureNodes.getLength(),
          reports);
    } catch (Exception e) {
      return new Result(false, safeMsg(e), 0, List.of());
    }
  }

  private static CertificateDetails toCertificateDetails(X509Certificate cert) {
    DateTimeFormatter fmt = DateTimeFormatter.ISO_INSTANT;
    return new CertificateDetails(
        cert.getSubjectX500Principal().getName(),
        cert.getIssuerX500Principal().getName(),
        cert.getSerialNumber() == null ? null : cert.getSerialNumber().toString(16),
        cert.getNotBefore() == null ? null : fmt.format(cert.getNotBefore().toInstant()),
        cert.getNotAfter() == null ? null : fmt.format(cert.getNotAfter().toInstant()),
        cert.getSigAlgName());
  }

  private static String safeMsg(Throwable t) {
    String m = t.getMessage();
    return (m != null && !m.isBlank()) ? m : t.getClass().getSimpleName();
  }

  /**
   * Resolves the verification key from the signature's own embedded
   * {@code KeyInfo}/{@code X509Data} — the standard JSR-105 pattern for
   * XML-DSig validation when the signer certificate travels with the document
   * rather than being supplied out-of-band.
   */
  private static final class X509KeySelector extends KeySelector {
    private X509Certificate resolvedCertificate;

    X509Certificate resolvedCertificate() {
      return resolvedCertificate;
    }

    @Override
    public KeySelectorResult select(
        KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context)
        throws KeySelectorException {
      if (keyInfo == null) {
        throw new KeySelectorException("Signature has no KeyInfo");
      }
      for (Object infoContent : keyInfo.getContent()) {
        if (!(infoContent instanceof X509Data x509Data)) {
          continue;
        }
        for (Object dataContent : x509Data.getContent()) {
          if (dataContent instanceof X509Certificate cert) {
            resolvedCertificate = cert;
            PublicKey key = cert.getPublicKey();
            return () -> key;
          }
        }
      }
      throw new KeySelectorException("No X509Certificate found in KeyInfo");
    }
  }

  private XmlVerifyService() {}
}
