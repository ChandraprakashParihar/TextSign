package com.trustsign.core;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public final class PdfVerifyService {
  public record SignatureReport(
      boolean ok,
      String reason,
      String name,
      String subFilter,
      String signDate,
      CertificateDetails certificate) {}

  public record CertificateDetails(
      String subject,
      String issuer,
      String serialNumber,
      String validFrom,
      String validTo,
      String algorithm) {}

  public record Result(boolean ok, String reason, int signatureCount, List<SignatureReport> signatures) {}

  public static Result verify(byte[] pdfBytes) {
    if (pdfBytes == null || pdfBytes.length == 0) {
      return new Result(false, "PDF is empty", 0, List.of());
    }
    try (PDDocument doc = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
      List<PDSignature> pdfSignatures = doc.getSignatureDictionaries();
      if (pdfSignatures == null || pdfSignatures.isEmpty()) {
        return new Result(false, "No PDF signature found", 0, List.of());
      }

      List<SignatureReport> reports = new ArrayList<>();
      boolean allValid = true;
      for (PDSignature sig : pdfSignatures) {
        byte[] content = sig.getSignedContent(pdfBytes);
        byte[] cms = sig.getContents(pdfBytes);
        CmsVerifyService.Result cmsResult = CmsVerifyService.verify(content, cms);
        if (!cmsResult.ok()) {
          allValid = false;
        }
        reports.add(new SignatureReport(
            cmsResult.ok(),
            cmsResult.reason(),
            sig.getName(),
            sig.getSubFilter(),
            sig.getSignDate() != null ? sig.getSignDate().toInstant().toString() : null,
            toCertificateDetails(cmsResult.signerCert())));
      }
      return new Result(
          allValid,
          allValid ? "All PDF signatures are valid" : "One or more PDF signatures are invalid",
          reports.size(),
          reports);
    } catch (Exception e) {
      String msg = e.getMessage();
      if (msg == null || msg.isBlank()) {
        msg = e.getClass().getSimpleName();
      }
      return new Result(false, msg, 0, List.of());
    }
  }

  private static CertificateDetails toCertificateDetails(X509Certificate cert) {
    if (cert == null) {
      return null;
    }
    return new CertificateDetails(
        cert.getSubjectX500Principal().getName(),
        cert.getIssuerX500Principal().getName(),
        cert.getSerialNumber().toString(16),
        cert.getNotBefore().toInstant().toString(),
        cert.getNotAfter().toInstant().toString(),
        cert.getSigAlgName());
  }

  private PdfVerifyService() {}
}
