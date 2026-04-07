package com.trustsign.core;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Selector;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/** Embeds DSS (/Certs, /OCSPs, /CRLs) for long-term offline validation. */
public final class LtvEnabler {
  private static final Logger LOG = Logger.getLogger(LtvEnabler.class.getName());

  public record Config(
      boolean enabled,
      boolean failOnMissingRevocationData,
      int ocspConnectTimeoutMs,
      int ocspReadTimeoutMs,
      int crlConnectTimeoutMs,
      int crlReadTimeoutMs) {
    public static final Config DISABLED = new Config(false, false, 10_000, 15_000, 10_000, 15_000);
  }

  /** Requested API: enable LTV on an already signed document using defaults. */
  public static void enableLTV(PDDocument document) throws Exception {
    enableLTV(document, new Config(true, false, 10_000, 15_000, 10_000, 15_000));
  }

  public static void enableLTV(PDDocument document, Config cfg) throws Exception {
    if (document == null) throw new IllegalArgumentException("document is null");
    if (cfg == null || !cfg.enabled()) return;

    List<byte[]> certs = new ArrayList<>();
    List<byte[]> ocsps = new ArrayList<>();
    List<byte[]> crls = new ArrayList<>();
    Set<String> certDedup = new LinkedHashSet<>();
    Set<String> ocspDedup = new LinkedHashSet<>();
    Set<String> crlDedup = new LinkedHashSet<>();
    Map<String, VriData> vri = new LinkedHashMap<>();

    for (PDSignature sig : document.getSignatureDictionaries()) {
      if (sig == null) continue;
      byte[] contents = sig.getContents();
      if (contents == null || contents.length == 0) continue;
      String vriKey = signatureVriKey(contents);
      VriData perSig = vri.computeIfAbsent(vriKey, k -> new VriData());
      CMSSignedData cms = new CMSSignedData(contents);
      var certStore = cms.getCertificates();
      for (SignerInformation si : cms.getSignerInfos().getSigners()) {
        @SuppressWarnings("unchecked")
        var matches = certStore.getMatches((Selector<org.bouncycastle.cert.X509CertificateHolder>) si.getSID());
        if (matches == null || matches.isEmpty()) continue;
        var signerHolder = (org.bouncycastle.cert.X509CertificateHolder) matches.iterator().next();
        X509Certificate signer = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(signerHolder);

        List<X509Certificate> chain = buildLikelyChain(certStore, signer);
        for (X509Certificate c : chain) {
          byte[] cBytes = c.getEncoded();
          String key = java.util.Base64.getEncoder().encodeToString(cBytes);
          if (certDedup.add(key)) certs.add(cBytes);
          perSig.certs.add(cBytes);
        }

        boolean revocationEmbedded = false;
        try {
          X509Certificate issuer = findIssuer(chain, signer);
          if (issuer != null) {
            byte[] ocsp = OcspClient.fetchOcspResponse(signer, issuer, cfg.ocspConnectTimeoutMs(), cfg.ocspReadTimeoutMs());
            String k = java.util.Base64.getEncoder().encodeToString(ocsp);
            if (ocspDedup.add(k)) ocsps.add(ocsp);
            perSig.ocsps.add(ocsp);
            revocationEmbedded = true;
          }
        } catch (Exception e) {
          LOG.warning("OCSP fetch failed: " + e.getMessage());
        }

        if (!revocationEmbedded) {
          try {
            X509Certificate issuer = findIssuer(chain, signer);
            if (issuer != null) {
              byte[] crl = CrlFetcher.fetchCrl(signer, issuer, cfg.crlConnectTimeoutMs(), cfg.crlReadTimeoutMs());
              String k = java.util.Base64.getEncoder().encodeToString(crl);
              if (crlDedup.add(k)) crls.add(crl);
              perSig.crls.add(crl);
              revocationEmbedded = true;
            }
          } catch (Exception e) {
            LOG.warning("CRL fetch failed: " + e.getMessage());
          }
        }

        if (!revocationEmbedded && cfg.failOnMissingRevocationData()) {
          throw new IllegalStateException("LTV revocation data missing for signer cert: "
              + signer.getSubjectX500Principal().getName());
        }
      }
    }

    upsertDss(document, certs, ocsps, crls, vri);
  }

  /** Used during signing before saveIncremental. */
  public static void embedValidationData(PDDocument document, X509Certificate[] chain, Config cfg) throws Exception {
    if (cfg == null || !cfg.enabled() || chain == null || chain.length == 0) return;
    List<byte[]> certs = new ArrayList<>();
    List<byte[]> ocsps = new ArrayList<>();
    List<byte[]> crls = new ArrayList<>();
    for (X509Certificate c : chain) certs.add(c.getEncoded());

    X509Certificate signer = chain[0];
    X509Certificate issuer = chain.length > 1 ? chain[1] : null;
    boolean revocationEmbedded = false;
    if (issuer != null) {
      try {
        ocsps.add(OcspClient.fetchOcspResponse(signer, issuer, cfg.ocspConnectTimeoutMs(), cfg.ocspReadTimeoutMs()));
        revocationEmbedded = true;
      } catch (Exception e) {
        LOG.warning("OCSP fetch failed during signing: " + e.getMessage());
      }
      if (!revocationEmbedded) {
        try {
          crls.add(CrlFetcher.fetchCrl(signer, issuer, cfg.crlConnectTimeoutMs(), cfg.crlReadTimeoutMs()));
          revocationEmbedded = true;
        } catch (Exception e) {
          LOG.warning("CRL fetch failed during signing: " + e.getMessage());
        }
      }
    }
    if (!revocationEmbedded && cfg.failOnMissingRevocationData()) {
      throw new IllegalStateException("LTV revocation data missing for signing certificate");
    }
    upsertDss(document, certs, ocsps, crls, Map.of());
  }

  private static void upsertDss(
      PDDocument doc,
      List<byte[]> certs,
      List<byte[]> ocsps,
      List<byte[]> crls,
      Map<String, VriData> vriData)
      throws Exception {
    COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
    COSName DSS = COSName.getPDFName("DSS");
    COSDictionary dss = catalog.getCOSDictionary(DSS);
    if (dss == null) {
      dss = new COSDictionary();
      catalog.setItem(DSS, dss);
    }
    COSArray certArr = new COSArray();
    COSArray ocspArr = new COSArray();
    COSArray crlArr = new COSArray();

    for (byte[] b : certs) certArr.add(new PDStream(doc, new ByteArrayInputStream(b)).getCOSObject());
    for (byte[] b : ocsps) ocspArr.add(new PDStream(doc, new ByteArrayInputStream(b)).getCOSObject());
    for (byte[] b : crls) crlArr.add(new PDStream(doc, new ByteArrayInputStream(b)).getCOSObject());

    dss.setItem(COSName.getPDFName("Certs"), certArr);
    dss.setItem(COSName.getPDFName("OCSPs"), ocspArr);
    dss.setItem(COSName.getPDFName("CRLs"), crlArr);
    if (vriData != null && !vriData.isEmpty()) {
      COSDictionary vri = new COSDictionary();
      for (Map.Entry<String, VriData> e : vriData.entrySet()) {
        COSDictionary entry = new COSDictionary();
        COSArray vCert = new COSArray();
        COSArray vOcsp = new COSArray();
        COSArray vCrl = new COSArray();
        for (byte[] b : e.getValue().certs) vCert.add(new PDStream(doc, new ByteArrayInputStream(b)).getCOSObject());
        for (byte[] b : e.getValue().ocsps) vOcsp.add(new PDStream(doc, new ByteArrayInputStream(b)).getCOSObject());
        for (byte[] b : e.getValue().crls) vCrl.add(new PDStream(doc, new ByteArrayInputStream(b)).getCOSObject());
        entry.setItem(COSName.getPDFName("Cert"), vCert);
        entry.setItem(COSName.getPDFName("OCSP"), vOcsp);
        entry.setItem(COSName.getPDFName("CRL"), vCrl);
        vri.setItem(COSName.getPDFName(e.getKey()), entry);
      }
      dss.setItem(COSName.getPDFName("VRI"), vri);
    }
    dss.setNeedToBeUpdated(true);
    catalog.setNeedToBeUpdated(true);
  }

  private static String signatureVriKey(byte[] signatureContents) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
    byte[] digest = md.digest(signatureContents);
    StringBuilder sb = new StringBuilder(digest.length * 2);
    for (byte b : digest) {
      sb.append(String.format("%02X", b));
    }
    return sb.toString();
  }

  private static final class VriData {
    final List<byte[]> certs = new ArrayList<>();
    final List<byte[]> ocsps = new ArrayList<>();
    final List<byte[]> crls = new ArrayList<>();
  }

  private static List<X509Certificate> buildLikelyChain(
      org.bouncycastle.util.Store<org.bouncycastle.cert.X509CertificateHolder> store,
      X509Certificate signer) throws Exception {
    List<X509Certificate> out = new ArrayList<>();
    out.add(signer);
    var all = store.getMatches(null);
    boolean progressed;
    do {
      progressed = false;
      X509Certificate tail = out.get(out.size() - 1);
      for (var h : all) {
        X509Certificate c = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(h);
        if (out.stream().anyMatch(x -> x.getSerialNumber().equals(c.getSerialNumber())
            && x.getIssuerX500Principal().equals(c.getIssuerX500Principal()))) continue;
        if (tail.getIssuerX500Principal().equals(c.getSubjectX500Principal())) {
          out.add(c);
          progressed = true;
          break;
        }
      }
    } while (progressed);
    return out;
  }

  private static X509Certificate findIssuer(List<X509Certificate> chain, X509Certificate cert) {
    for (X509Certificate c : chain) {
      if (cert.getIssuerX500Principal().equals(c.getSubjectX500Principal())) return c;
    }
    return null;
  }

  /**
   * Result of probing OCSP then CRL (same order as embedding) for operations dashboards.
   */
  public record RevocationProbeResult(
      boolean ocspOk,
      Long ocspLatencyMs,
      String ocspError,
      boolean crlAttempted,
      boolean crlOk,
      Long crlLatencyMs,
      String crlError,
      /** Non-null when at least one path succeeded: {@code ocsp} or {@code crl}. */
      String source) {

    public boolean ok() {
      return ocspOk || crlOk;
    }
  }

  /**
   * Fetches and validates revocation material for {@code signer} with {@code issuer} (OCSP first, then CRL).
   */
  public static RevocationProbeResult probeRevocation(
      X509Certificate signer, X509Certificate issuer, Config cfg) {
    if (signer == null || issuer == null) {
      return new RevocationProbeResult(
          false, null, "signer or issuer is null", false, false, null, null, null);
    }
    if (cfg == null || !cfg.enabled()) {
      return new RevocationProbeResult(
          false, null, "LTV disabled in probe config", false, false, null, null, null);
    }
    long t0 = System.nanoTime();
    try {
      OcspClient.fetchOcspResponse(signer, issuer, cfg.ocspConnectTimeoutMs(), cfg.ocspReadTimeoutMs());
      long ocspMs = Math.max(0L, (System.nanoTime() - t0) / 1_000_000L);
      return new RevocationProbeResult(true, ocspMs, null, false, false, null, null, "ocsp");
    } catch (Exception e) {
      long ocspMs = Math.max(0L, (System.nanoTime() - t0) / 1_000_000L);
      String ocspErr = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
      long t1 = System.nanoTime();
      try {
        CrlFetcher.fetchCrl(signer, issuer, cfg.crlConnectTimeoutMs(), cfg.crlReadTimeoutMs());
        long crlMs = Math.max(0L, (System.nanoTime() - t1) / 1_000_000L);
        return new RevocationProbeResult(false, ocspMs, ocspErr, true, true, crlMs, null, "crl");
      } catch (Exception e2) {
        long crlMs = Math.max(0L, (System.nanoTime() - t1) / 1_000_000L);
        String crlErr = e2.getMessage() != null ? e2.getMessage() : e2.getClass().getSimpleName();
        return new RevocationProbeResult(false, ocspMs, ocspErr, true, false, crlMs, crlErr, null);
      }
    }
  }

  private LtvEnabler() {}
}

