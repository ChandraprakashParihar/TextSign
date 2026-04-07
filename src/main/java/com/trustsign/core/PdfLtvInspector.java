package com.trustsign.core;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/** Debug helper to inspect DSS/VRI state for Acrobat LTV diagnosis. */
public final class PdfLtvInspector {
  public record SignatureVriReport(
      String name,
      String subFilter,
      String vriKeySha1,
      boolean vriEntryPresent) {}

  public record Result(
      boolean ok,
      String reason,
      int signatureCount,
      boolean dssPresent,
      boolean vriPresent,
      int certsCount,
      int ocspsCount,
      int crlsCount,
      int vriEntryCount,
      List<SignatureVriReport> signatures) {}

  public static Result inspect(byte[] pdfBytes) {
    if (pdfBytes == null || pdfBytes.length == 0) {
      return new Result(false, "PDF is empty", 0, false, false, 0, 0, 0, 0, List.of());
    }
    try (PDDocument doc = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
      List<PDSignature> sigs = doc.getSignatureDictionaries();
      COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
      COSDictionary dss = catalog.getCOSDictionary(COSName.getPDFName("DSS"));
      boolean dssPresent = dss != null;
      COSDictionary vri = dss != null ? dss.getCOSDictionary(COSName.getPDFName("VRI")) : null;
      boolean vriPresent = vri != null;

      COSArray certs = dss != null ? dss.getCOSArray(COSName.getPDFName("Certs")) : null;
      COSArray ocsps = dss != null ? dss.getCOSArray(COSName.getPDFName("OCSPs")) : null;
      COSArray crls = dss != null ? dss.getCOSArray(COSName.getPDFName("CRLs")) : null;
      int certsCount = certs != null ? certs.size() : 0;
      int ocspsCount = ocsps != null ? ocsps.size() : 0;
      int crlsCount = crls != null ? crls.size() : 0;
      int vriEntryCount = countDictionaryEntries(vri);

      List<SignatureVriReport> reports = new ArrayList<>();
      for (PDSignature sig : sigs) {
        byte[] contents = sig.getContents(pdfBytes);
        String key = (contents != null && contents.length > 0) ? sha1UpperHex(contents) : null;
        boolean present = key != null && vri != null && vri.getDictionaryObject(COSName.getPDFName(key)) != null;
        reports.add(new SignatureVriReport(sig.getName(), sig.getSubFilter(), key, present));
      }

      return new Result(
          true,
          "PDF LTV structure parsed",
          sigs.size(),
          dssPresent,
          vriPresent,
          certsCount,
          ocspsCount,
          crlsCount,
          vriEntryCount,
          reports);
    } catch (Exception e) {
      String msg = e.getMessage();
      if (msg == null || msg.isBlank()) msg = e.getClass().getSimpleName();
      return new Result(false, msg, 0, false, false, 0, 0, 0, 0, List.of());
    }
  }

  private static int countDictionaryEntries(COSDictionary dict) {
    if (dict == null) return 0;
    int c = 0;
    for (COSName key : dict.keySet()) {
      COSBase base = dict.getDictionaryObject(key);
      if (base instanceof COSObject o) base = o.getObject();
      if (base != null) c++;
    }
    return c;
  }

  private static String sha1UpperHex(byte[] data) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    byte[] digest = md.digest(data);
    StringBuilder sb = new StringBuilder(digest.length * 2);
    for (byte b : digest) sb.append(String.format("%02X", b));
    return sb.toString();
  }

  private PdfLtvInspector() {}
}
