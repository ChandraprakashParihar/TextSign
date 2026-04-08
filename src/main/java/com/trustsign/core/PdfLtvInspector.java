package com.trustsign.core;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Debug helper to inspect DSS/VRI state for Acrobat LTV diagnosis. */
public final class PdfLtvInspector {
  public record SignatureVriReport(
      String name,
      String subFilter,
      /**
       * Acrobat-style VRI key: uppercase hex SHA-1 of PKCS#7 DER (leading/trailing padding in
       * {@code /Contents} stripped). This is what viewers typically use to look up {@code /VRI}.
       */
      String vriKeySha1Pkcs7Der,
      boolean vriEntryPresentPkcs7Der,
      /**
       * Legacy key: SHA-1 of the entire {@code /Contents} byte buffer (includes null padding).
       * Some writers embed VRI under this key instead.
       */
      String vriKeySha1FullContentsBuffer,
      boolean vriEntryPresentFullContentsBuffer,
      /** True when CMS contains {@code id-aa-signatureTimeStampToken} (RFC 3161 on signature value). */
      boolean cmsSignatureTimestampPresent,
      /** Certificates shipped inside the embedded timestamp token (0 if none / parse failed). */
      int embeddedTimestampCertCount) {}

  public record CertificateRevocationReport(
      String subject,
      String issuer,
      String serialNumberHex,
      String revocationSource) {}

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
      List<CertificateRevocationReport> certificateRevocation,
      List<SignatureVriReport> signatures) {}

  public static Result inspect(byte[] pdfBytes) {
    if (pdfBytes == null || pdfBytes.length == 0) {
      return new Result(false, "PDF is empty", 0, false, false, 0, 0, 0, 0, List.of(), List.of());
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

      List<CertificateRevocationReport> certRevocation = inspectDssRevocation(certs, ocsps, crls);

      List<SignatureVriReport> reports = new ArrayList<>();
      ASN1ObjectIdentifier tsOid = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14");
      for (PDSignature sig : sigs) {
        byte[] contents = sig.getContents(pdfBytes);
        String keyDer = null;
        String keyFull = null;
        boolean presentDer = false;
        boolean presentFull = false;
        if (contents != null && contents.length > 0) {
          try {
            keyDer = LtvEnabler.vriDictionaryKeyHex(contents);
          } catch (Exception ignore) {
            keyDer = null;
          }
          try {
            keyFull = LtvEnabler.sha1UpperHex(contents);
          } catch (Exception ignore) {
            keyFull = null;
          }
          if (vri != null && keyDer != null) {
            presentDer = vri.getDictionaryObject(COSName.getPDFName(keyDer)) != null;
          }
          if (vri != null && keyFull != null) {
            presentFull = vri.getDictionaryObject(COSName.getPDFName(keyFull)) != null;
          }
        }
        boolean tsPresent = false;
        int tsCertCount = 0;
        if (contents != null && contents.length > 0) {
          try {
            byte[] pkcs7Der = LtvEnabler.pkcs7DerFromContents(contents);
            CMSSignedData cms = new CMSSignedData(pkcs7Der);
            for (SignerInformation si : cms.getSignerInfos().getSigners()) {
              AttributeTable unsigned = si.getUnsignedAttributes();
              if (unsigned == null) continue;
              Attribute tsAttr = unsigned.get(tsOid);
              if (tsAttr == null) continue;
              tsPresent = true;
              ASN1Set vals = tsAttr.getAttrValues();
              for (int i = 0; i < vals.size(); i++) {
                byte[] enc = vals.getObjectAt(i).toASN1Primitive().getEncoded();
                TimeStampToken tst = new TimeStampToken(new CMSSignedData(enc));
                tsCertCount += tst.getCertificates().getMatches(null).size();
              }
            }
          } catch (Exception ignore) {
            // padded / non-CMS contents — leave timestamp fields false/0
          }
        }
        reports.add(new SignatureVriReport(
            sig.getName(),
            sig.getSubFilter(),
            keyDer,
            presentDer,
            keyFull,
            presentFull,
            tsPresent,
            tsCertCount));
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
          certRevocation,
          reports);
    } catch (Exception e) {
      String msg = e.getMessage();
      if (msg == null || msg.isBlank()) msg = e.getClass().getSimpleName();
      return new Result(false, msg, 0, false, false, 0, 0, 0, 0, List.of(), List.of());
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

  private static List<CertificateRevocationReport> inspectDssRevocation(
      COSArray certs,
      COSArray ocsps,
      COSArray crls) {
    if (certs == null || certs.size() == 0) {
      return List.of();
    }
    try {
      Set<String> ocspSerials = new HashSet<>();
      if (ocsps != null) {
        for (int i = 0; i < ocsps.size(); i++) {
          byte[] b = readStreamBytes(ocsps.getObject(i));
          if (b == null || b.length == 0) continue;
          try {
            OCSPResp resp = new OCSPResp(b);
            Object ro = resp.getResponseObject();
            if (ro instanceof BasicOCSPResp basic) {
              for (SingleResp sr : basic.getResponses()) {
                if (sr == null || sr.getCertID() == null || sr.getCertID().getSerialNumber() == null) continue;
                ocspSerials.add(sr.getCertID().getSerialNumber().toString(16).toLowerCase());
              }
            }
          } catch (Exception ignore) {
          }
        }
      }

      Set<String> crlIssuers = new HashSet<>();
      if (crls != null) {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < crls.size(); i++) {
          byte[] b = readStreamBytes(crls.getObject(i));
          if (b == null || b.length == 0) continue;
          try {
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(b));
            if (crl.getIssuerX500Principal() != null) {
              crlIssuers.add(crl.getIssuerX500Principal().getName());
            }
          } catch (Exception ignore) {
          }
        }
      }

      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      List<CertificateRevocationReport> out = new ArrayList<>();
      for (int i = 0; i < certs.size(); i++) {
        byte[] b = readStreamBytes(certs.getObject(i));
        if (b == null || b.length == 0) continue;
        try {
          X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(b));
          String serialHex = cert.getSerialNumber() != null ? cert.getSerialNumber().toString(16) : "";
          String issuer = cert.getIssuerX500Principal() != null ? cert.getIssuerX500Principal().getName() : "";
          String src;
          if (serialHex != null && ocspSerials.contains(serialHex.toLowerCase())) {
            src = "ocsp";
          } else if (issuer != null && crlIssuers.contains(issuer)) {
            src = "crl";
          } else {
            src = "none";
          }
          out.add(new CertificateRevocationReport(
              cert.getSubjectX500Principal() != null ? cert.getSubjectX500Principal().getName() : "",
              issuer,
              serialHex,
              src));
        } catch (Exception ignore) {
        }
      }
      return out;
    } catch (Exception e) {
      return List.of();
    }
  }

  private static byte[] readStreamBytes(COSBase base) throws Exception {
    if (base instanceof COSObject o) {
      base = o.getObject();
    }
    if (base instanceof COSStream s) {
      try (InputStream in = s.createRawInputStream()) {
        return in.readAllBytes();
      }
    }
    return null;
  }

  private PdfLtvInspector() {}
}
