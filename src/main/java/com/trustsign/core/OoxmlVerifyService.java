package com.trustsign.core;

import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.poifs.crypt.dsig.SignatureConfig;
import org.apache.poi.poifs.crypt.dsig.SignatureInfo;
import org.apache.poi.poifs.crypt.dsig.SignaturePart;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates native OOXML digital signature(s) in a signed OOXML package —
 * .xlsx (Excel), .docx (Word), or .pptx (PowerPoint) — produced by
 * {@link OoxmlSignerService} or by Office itself. Format-agnostic: OOXML
 * digital signatures are a property of the Open Packaging Conventions
 * container, not of spreadsheet/document/presentation content, so this needs
 * no format parameter at all.
 */
public final class OoxmlVerifyService {

  public record CertificateDetails(
      String subject,
      String issuer,
      String serialNumber,
      String validFrom,
      String validTo,
      String algorithm) {}

  public record SignatureReport(boolean ok, String reason, CertificateDetails certificate) {}

  public record Result(boolean ok, String reason, int signatureCount, List<SignatureReport> signatures) {}

  public static Result verify(byte[] signedOoxmlBytes) {
    if (signedOoxmlBytes == null || signedOoxmlBytes.length == 0) {
      return new Result(false, "signedOoxmlBytes is empty", 0, List.of());
    }
    try (OPCPackage pkg = OPCPackage.open(new ByteArrayInputStream(signedOoxmlBytes))) {
      SignatureConfig sigConfig = new SignatureConfig();
      // See the matching comment in OoxmlSignerService.sign() — Apache
      // Santuario hardcodes a 30-reference-per-Manifest cap under secure
      // validation that a real OOXML package routinely exceeds. Must be
      // disabled here too: this verify path is what both the self-check
      // during signing and the standalone /verify-* endpoints use.
      sigConfig.setSecureValidation(false);
      SignatureInfo signatureInfo = new SignatureInfo();
      signatureInfo.setOpcPackage(pkg);
      signatureInfo.setSignatureConfig(sigConfig);

      List<SignatureReport> reports = new ArrayList<>();
      boolean any = false;
      boolean allOk = true;
      for (SignaturePart part : signatureInfo.getSignatureParts()) {
        any = true;
        boolean valid;
        String reason;
        X509Certificate signer = null;
        try {
          valid = part.validate();
          signer = part.getSigner();
          reason = valid ? "Signature valid" : "Signature invalid";
        } catch (Exception e) {
          valid = false;
          reason = safeMsg(e);
        }
        reports.add(new SignatureReport(valid, reason, signer == null ? null : toCertificateDetails(signer)));
        if (!valid) {
          allOk = false;
        }
      }
      if (!any) {
        return new Result(false, "No OOXML digital signature found in file", 0, List.of());
      }
      return new Result(
          allOk,
          allOk ? "All signatures valid" : "One or more signatures failed validation",
          reports.size(),
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

  private OoxmlVerifyService() {}
}
