package com.trustsign.core;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Selector;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Embeds DSS (/Certs, /OCSPs, /CRLs) for long-term offline validation. */
public final class LtvEnabler {
  private static final Logger LOG = LoggerFactory.getLogger(LtvEnabler.class);

  /** CMS id-aa-signatureTimeStampToken (RFC 3161 timestamp on signature value). */
  private static final ASN1ObjectIdentifier ID_AA_SIGNATURE_TIMESTAMP_TOKEN =
      new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14");

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
    enableLTV(document, null, new Config(true, false, 10_000, 15_000, 10_000, 15_000));
  }

  public static void enableLTV(PDDocument document, Config cfg) throws Exception {
    enableLTV(document, null, cfg);
  }

  /**
   * @param pdfSourceBytes full signed PDF bytes (recommended). When non-null, signature PKCS#7 bytes are read
   *                       with {@link PDSignature#getContents(byte[])} so incremental updates resolve correctly.
   */
  public static void enableLTV(PDDocument document, byte[] pdfSourceBytes, Config cfg) throws Exception {
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
      byte[] contents =
          pdfSourceBytes != null ? sig.getContents(pdfSourceBytes) : sig.getContents();
      if (contents == null || contents.length == 0) continue;
      byte[] pkcs7Der;
      try {
        pkcs7Der = pkcs7DerFromContents(contents);
      } catch (IOException e) {
        LOG.warn("PKCS#7 DER extraction failed; using raw /Contents: {}", e.getMessage());
        pkcs7Der = contents;
      }
      String vriKeyDer = sha1UpperHex(pkcs7Der);
      String vriKeyFullContents = sha1UpperHex(contents);
      VriData perSig = vri.computeIfAbsent(vriKeyDer, k -> new VriData());
      if (!vriKeyDer.equals(vriKeyFullContents) && !vri.containsKey(vriKeyFullContents)) {
        vri.put(vriKeyFullContents, perSig);
      }
      CMSSignedData cms = new CMSSignedData(pkcs7Der);
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

        // Revocation for the full document chain (leaf + intermediates). Acrobat LTV expects chain coverage,
        // not only the end-entity signer.
        boolean signerLeafRevocationOk = false;
        for (int i = 0; i < chain.size(); i++) {
          X509Certificate cert = chain.get(i);
          // Stop at self-signed (root).
          if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            break;
          }
          X509Certificate issuer = findIssuer(chain, cert);
          if (issuer == null) {
            break;
          }
          String ctx = i == 0 ? "Document signer" : "Document chain";
          boolean got = tryEmbedOcspThenCrl(
              cert,
              issuer,
              cfg,
              ocsps,
              crls,
              ocspDedup,
              crlDedup,
              perSig,
              ctx);
          if (i == 0) {
            signerLeafRevocationOk = got;
          }
        }

        if (!signerLeafRevocationOk && cfg.failOnMissingRevocationData()) {
          throw new IllegalStateException("LTV revocation data missing for signer cert: "
              + signer.getSubjectX500Principal().getName());
        }

        // Acrobat "LTV enabled" requires validation data for the RFC 3161 timestamp chain too.
        embedTimestampValidationData(si, cfg, certs, ocsps, crls, certDedup, ocspDedup, crlDedup, perSig);
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
    Set<String> ocspDedup = new LinkedHashSet<>();
    Set<String> crlDedup = new LinkedHashSet<>();
    boolean revocationEmbedded =
        issuer != null
            && tryEmbedOcspThenCrl(
                signer, issuer, cfg, ocsps, crls, ocspDedup, crlDedup, null, "Document signer (pre-save)");
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
    dss.setItem(COSName.TYPE, COSName.DSS);

    /*
     * Acrobat expects VRI /Cert, /OCSP, /CRL entries to reference the *same* stream objects as
     * /DSS /Certs, /OCSPs, /CRLs — not duplicate streams with identical bytes.
     */
    Map<String, COSBase> certStreams = new LinkedHashMap<>();
    Map<String, COSBase> ocspStreams = new LinkedHashMap<>();
    Map<String, COSBase> crlStreams = new LinkedHashMap<>();

    COSArray certArr = new COSArray();
    for (byte[] b : certs) {
      certArr.add(cosStreamFor(doc, b, certStreams));
    }
    COSArray ocspArr = new COSArray();
    for (byte[] b : ocsps) {
      ocspArr.add(cosStreamFor(doc, b, ocspStreams));
    }
    COSArray crlArr = new COSArray();
    for (byte[] b : crls) {
      crlArr.add(cosStreamFor(doc, b, crlStreams));
    }

    dss.setItem(COSName.getPDFName("Certs"), certArr);
    if (!ocsps.isEmpty()) {
      dss.setItem(COSName.getPDFName("OCSPs"), ocspArr);
    } else {
      dss.removeItem(COSName.getPDFName("OCSPs"));
    }
    if (!crls.isEmpty()) {
      dss.setItem(COSName.getPDFName("CRLs"), crlArr);
    } else {
      dss.removeItem(COSName.getPDFName("CRLs"));
    }
    if (vriData != null && !vriData.isEmpty()) {
      COSDictionary vri = new COSDictionary();
      for (Map.Entry<String, VriData> e : vriData.entrySet()) {
        COSDictionary entry = new COSDictionary();
        COSArray vCert = new COSArray();
        COSArray vOcsp = new COSArray();
        COSArray vCrl = new COSArray();
        for (byte[] b : e.getValue().certs) {
          COSBase ref = certStreams.get(b64Key(b));
          if (ref != null) vCert.add(ref);
        }
        for (byte[] b : e.getValue().ocsps) {
          COSBase ref = ocspStreams.get(b64Key(b));
          if (ref != null) vOcsp.add(ref);
        }
        for (byte[] b : e.getValue().crls) {
          COSBase ref = crlStreams.get(b64Key(b));
          if (ref != null) vCrl.add(ref);
        }
        if (vCert.size() > 0) {
          entry.setItem(COSName.getPDFName("Cert"), vCert);
        }
        if (vOcsp.size() > 0) {
          entry.setItem(COSName.getPDFName("OCSP"), vOcsp);
        }
        if (vCrl.size() > 0) {
          entry.setItem(COSName.getPDFName("CRL"), vCrl);
        }
        vri.setItem(COSName.getPDFName(e.getKey()), entry);
      }
      dss.setItem(COSName.getPDFName("VRI"), vri);
    }
    dss.setNeedToBeUpdated(true);
    catalog.setNeedToBeUpdated(true);
  }

  private static String b64Key(byte[] b) {
    return java.util.Base64.getEncoder().encodeToString(b);
  }

  private static COSBase cosStreamFor(PDDocument doc, byte[] b, Map<String, COSBase> cache) throws IOException {
    String key = b64Key(b);
    COSBase existing = cache.get(key);
    if (existing != null) {
      return existing;
    }
    PDStream stream = new PDStream(doc, new ByteArrayInputStream(b));
    COSBase cos = stream.getCOSObject();
    cache.put(key, cos);
    return cos;
  }

  /**
   * PKCS#7 bytes for CMS parsing and for the Acrobat-style VRI key (first ASN.1 object; strips leading
   * zeros and trailing padding in the signature {@code /Contents} buffer).
   */
  public static byte[] pkcs7DerFromContents(byte[] contents) throws IOException {
    if (contents == null || contents.length == 0) {
      return contents;
    }
    int start = 0;
    while (start < contents.length && contents[start] == 0) {
      start++;
    }
    if (start >= contents.length) {
      throw new IOException("signature /Contents is all zero bytes");
    }
    try (ASN1InputStream ais =
        new ASN1InputStream(new ByteArrayInputStream(contents, start, contents.length - start))) {
      ASN1Primitive p = ais.readObject();
      if (p == null) {
        return Arrays.copyOfRange(contents, start, contents.length);
      }
      return p.getEncoded();
    }
  }

  /** Uppercase hex SHA-1, used as PDF VRI dictionary entry name. */
  public static String sha1UpperHex(byte[] data) throws Exception {
    if (data == null) {
      return null;
    }
    MessageDigest md = MessageDigest.getInstance("SHA-1");
    byte[] digest = md.digest(data);
    StringBuilder sb = new StringBuilder(digest.length * 2);
    for (byte b : digest) {
      sb.append(String.format("%02X", b));
    }
    return sb.toString();
  }

  /**
   * Acrobat-style VRI key: SHA-1 of PKCS#7 DER only (see {@link #pkcs7DerFromContents(byte[])}).
   */
  public static String vriDictionaryKeyHex(byte[] signatureContents) throws Exception {
    return sha1UpperHex(pkcs7DerFromContents(signatureContents));
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
   * Fetches OCSP (preferred) or CRL for {@code cert} signed by {@code issuer}, appends to DSS/VRI
   * lists with de-duplication. Returns true if at least one response was embedded.
   */
  private static boolean tryEmbedOcspThenCrl(
      X509Certificate cert,
      X509Certificate issuer,
      Config cfg,
      List<byte[]> ocsps,
      List<byte[]> crls,
      Set<String> ocspDedup,
      Set<String> crlDedup,
      VriData perSigOrNull,
      String logCtx) {
    try {
      byte[] ocsp = OcspClient.fetchOcspResponse(cert, issuer, cfg.ocspConnectTimeoutMs(), cfg.ocspReadTimeoutMs());
      String k = java.util.Base64.getEncoder().encodeToString(ocsp);
      if (ocspDedup.add(k)) ocsps.add(ocsp);
      if (perSigOrNull != null) perSigOrNull.ocsps.add(ocsp);
      return true;
    } catch (Exception e) {
      LOG.warn("{} OCSP fetch failed: {}", logCtx, e.getMessage());
    }
    try {
      byte[] crl = CrlFetcher.fetchCrl(cert, issuer, cfg.crlConnectTimeoutMs(), cfg.crlReadTimeoutMs());
      String k = java.util.Base64.getEncoder().encodeToString(crl);
      if (crlDedup.add(k)) crls.add(crl);
      if (perSigOrNull != null) perSigOrNull.crls.add(crl);
      return true;
    } catch (Exception e) {
      LOG.warn("{} CRL fetch failed: {}", logCtx, e.getMessage());
    }
    return false;
  }

  /**
   * When the CMS signature carries {@code id-aa-signatureTimeStampToken}, Acrobat expects DSS/VRI
   * to include the TSA certificate chain and revocation material for that chain as well.
   */
  private static void embedTimestampValidationData(
      SignerInformation documentSi,
      Config cfg,
      List<byte[]> certs,
      List<byte[]> ocsps,
      List<byte[]> crls,
      Set<String> certDedup,
      Set<String> ocspDedup,
      Set<String> crlDedup,
      VriData perSig) {
    AttributeTable unsigned = documentSi.getUnsignedAttributes();
    if (unsigned == null) return;
    Attribute tsAttr = unsigned.get(ID_AA_SIGNATURE_TIMESTAMP_TOKEN);
    if (tsAttr == null) return;

    var converter = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter();
    ASN1Set vals = tsAttr.getAttrValues();
    for (int vi = 0; vi < vals.size(); vi++) {
      byte[] encoded;
      try {
        encoded = vals.getObjectAt(vi).toASN1Primitive().getEncoded();
      } catch (Exception e) {
        LOG.warn("Failed to encode timestamp attribute value: {}", e.getMessage());
        continue;
      }
      final TimeStampToken tst;
      try {
        tst = new TimeStampToken(new CMSSignedData(encoded));
      } catch (Exception e) {
        LOG.warn("Failed to parse embedded signature timestamp token: {}", e.getMessage());
        continue;
      }
      var tsCertStore = tst.getCertificates();
      SignerId sid = tst.getSID();
      @SuppressWarnings("unchecked")
      var matches = tsCertStore.getMatches((Selector<org.bouncycastle.cert.X509CertificateHolder>) sid);
      if (matches == null || matches.isEmpty()) {
        LOG.warn("Timestamp token had no certificate matching TSA SignerId");
        continue;
      }
      X509Certificate tsaSigner;
      try {
        tsaSigner = converter.getCertificate(matches.iterator().next());
      } catch (Exception e) {
        LOG.warn("Failed to convert TSA certificate: {}", e.getMessage());
        continue;
      }

      List<X509Certificate> tsChain;
      try {
        tsChain = buildLikelyChain(tsCertStore, tsaSigner);
      } catch (Exception e) {
        LOG.warn("Failed to build TSA chain: {}", e.getMessage());
        continue;
      }

      for (X509Certificate c : tsChain) {
        try {
          byte[] cBytes = c.getEncoded();
          String key = java.util.Base64.getEncoder().encodeToString(cBytes);
          if (certDedup.add(key)) certs.add(cBytes);
          perSig.certs.add(cBytes);
        } catch (Exception e) {
          LOG.warn("Failed to encode TSA cert: {}", e.getMessage());
        }
      }

      boolean tsaLeafRevocationOk = false;
      for (int i = 0; i < tsChain.size(); i++) {
        X509Certificate cert = tsChain.get(i);
        if (cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
          break;
        }
        X509Certificate issuer = findIssuer(tsChain, cert);
        if (issuer == null) {
          break;
        }
        String ctx = i == 0 ? "TSA signer" : "TSA chain";
        boolean got = tryEmbedOcspThenCrl(
            cert, issuer, cfg, ocsps, crls, ocspDedup, crlDedup, perSig, ctx);
        if (i == 0) {
          tsaLeafRevocationOk = got;
        }
      }

      if (!tsaLeafRevocationOk && cfg.failOnMissingRevocationData()) {
        throw new IllegalStateException(
            "LTV revocation data missing for TSA signer cert: "
                + tsaSigner.getSubjectX500Principal().getName());
      }
    }
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

