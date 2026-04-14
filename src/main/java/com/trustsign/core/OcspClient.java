package com.trustsign.core;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

final class OcspClient {
  static byte[] fetchOcspResponse(
      X509Certificate cert,
      X509Certificate issuer,
      int connectTimeoutMs,
      int readTimeoutMs) throws Exception {
    List<String> urls = extractOcspUrls(cert);
    if (urls.isEmpty()) {
      throw new IllegalStateException("No OCSP URL in certificate AIA");
    }
    Exception last = null;
    for (String url : urls) {
      try {
        byte[] ocsp = request(url, cert, issuer, connectTimeoutMs, readTimeoutMs);
        validate(ocsp, cert, issuer);
        return ocsp;
      } catch (Exception e) {
        last = e;
      }
    }
    throw new IllegalStateException("OCSP fetch failed for all endpoints: " + urls, last);
  }

  private static byte[] request(String url, X509Certificate cert, X509Certificate issuer, int cto, int rto)
      throws Exception {
    var digCalc = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
    CertificateID certId = new CertificateID(digCalc, new JcaX509CertificateHolder(issuer), cert.getSerialNumber());
    OCSPReq req = new OCSPReqBuilder().addRequest(certId).build();
    byte[] reqBytes = req.getEncoded();

    HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
    conn.setConnectTimeout(Math.max(1000, cto));
    conn.setReadTimeout(Math.max(1000, rto));
    conn.setRequestMethod("POST");
    conn.setDoOutput(true);
    conn.setRequestProperty("Content-Type", "application/ocsp-request");
    conn.setRequestProperty("Accept", "application/ocsp-response");
    try (OutputStream os = conn.getOutputStream()) {
      os.write(reqBytes);
    }
    int code = conn.getResponseCode();
    InputStream is = code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream();
    if (is == null) throw new IllegalStateException("OCSP HTTP " + code + " empty body");
    byte[] resp;
    try (InputStream in = is) {
      resp = in.readAllBytes();
    }
    if (code < 200 || code >= 300) throw new IllegalStateException("OCSP HTTP " + code);
    return resp;
  }

  private static void validate(byte[] ocspRespBytes, X509Certificate cert, X509Certificate issuer) throws Exception {
    OCSPResp resp = new OCSPResp(ocspRespBytes);
    if (resp.getStatus() != OCSPResp.SUCCESSFUL) {
      throw new IllegalStateException("OCSP responder status=" + resp.getStatus());
    }
    Object obj = resp.getResponseObject();
    if (!(obj instanceof BasicOCSPResp basic)) {
      throw new IllegalStateException("OCSP response is not BasicOCSPResp");
    }
    SingleResp[] rs = basic.getResponses();
    if (rs == null || rs.length == 0) {
      throw new IllegalStateException("OCSP response has no entries");
    }
    var status = rs[0].getCertStatus();
    if (status != org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
      throw new IllegalStateException("OCSP cert status is not GOOD");
    }
    // Signature can be by issuer OR delegated OCSP responder cert (id-kp-OCSPSigning).
    boolean signatureValid = basic.isSignatureValid(
        new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(issuer.getPublicKey()));
    if (!signatureValid) {
      var responderCerts = basic.getCerts();
      for (var holder : responderCerts) {
        X509Certificate responder =
            new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(holder);
        if (!basic.isSignatureValid(
            new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(responder.getPublicKey()))) {
          continue;
        }
        if (!isOcspSigningCert(responder)) {
          continue;
        }
        if (!issuer.getSubjectX500Principal().equals(responder.getIssuerX500Principal())) {
          continue;
        }
        try {
          responder.verify(issuer.getPublicKey());
          signatureValid = true;
          break;
        } catch (Exception ignored) {
          // Try next responder certificate candidate if available.
        }
      }
    }
    if (!signatureValid) {
      throw new IllegalStateException("OCSP response signature invalid for issuer/delegated responder");
    }
    // cert/issuer are intentionally read for validation semantics
    if (cert.getSerialNumber() == null || issuer.getSubjectX500Principal() == null) {
      throw new IllegalStateException("Certificate metadata missing");
    }
  }

  private static boolean isOcspSigningCert(X509Certificate cert) {
    try {
      byte[] ext = cert.getExtensionValue(Extension.extendedKeyUsage.getId());
      if (ext == null) return false;
      ASN1Primitive p =
          ASN1Primitive.fromByteArray(((ASN1OctetString) ASN1Primitive.fromByteArray(ext)).getOctets());
      ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(p);
      return eku != null && eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning);
    } catch (Exception e) {
      return false;
    }
  }

  private static List<String> extractOcspUrls(X509Certificate cert) throws Exception {
    byte[] ext = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
    if (ext == null) return List.of();
    ASN1Primitive p = ASN1Primitive.fromByteArray(((ASN1OctetString) ASN1Primitive.fromByteArray(ext)).getOctets());
    AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(p);
    List<String> urls = new ArrayList<>();
    for (AccessDescription ad : aia.getAccessDescriptions()) {
      if (!ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) continue;
      GeneralName gn = ad.getAccessLocation();
      if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
        String u = gn.getName().toString();
        URI uri = URI.create(u);
        if (uri.getScheme() != null && (uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https"))) {
          urls.add(u);
        }
      }
    }
    return urls;
  }

  private OcspClient() {}
}

