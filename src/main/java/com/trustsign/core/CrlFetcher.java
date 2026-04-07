package com.trustsign.core;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

final class CrlFetcher {
  static byte[] fetchCrl(X509Certificate cert, X509Certificate issuer, int connectTimeoutMs, int readTimeoutMs)
      throws Exception {
    List<String> urls = extractCrlUrls(cert);
    if (urls.isEmpty()) {
      throw new IllegalStateException("No CRL distribution points in certificate");
    }
    Exception last = null;
    for (String url : urls) {
      try {
        byte[] crlBytes = download(url, connectTimeoutMs, readTimeoutMs);
        validate(crlBytes, issuer);
        return crlBytes;
      } catch (Exception e) {
        last = e;
      }
    }
    throw new IllegalStateException("CRL fetch failed for all endpoints: " + urls, last);
  }

  private static byte[] download(String url, int cto, int rto) throws Exception {
    HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
    conn.setConnectTimeout(Math.max(1000, cto));
    conn.setReadTimeout(Math.max(1000, rto));
    conn.setRequestMethod("GET");
    int code = conn.getResponseCode();
    InputStream is = code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream();
    if (is == null) throw new IllegalStateException("CRL HTTP " + code + " empty body");
    byte[] body;
    try (InputStream in = is) {
      body = in.readAllBytes();
    }
    if (code < 200 || code >= 300) throw new IllegalStateException("CRL HTTP " + code);
    return body;
  }

  private static void validate(byte[] crlBytes, X509Certificate issuer) throws Exception {
    X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509")
        .generateCRL(new java.io.ByteArrayInputStream(crlBytes));
    crl.verify(issuer.getPublicKey());
    if (crl.getNextUpdate() == null) {
      throw new IllegalStateException("CRL nextUpdate missing");
    }
  }

  private static List<String> extractCrlUrls(X509Certificate cert) throws Exception {
    byte[] ext = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
    if (ext == null) return List.of();
    ASN1Primitive p = ASN1Primitive.fromByteArray(((ASN1OctetString) ASN1Primitive.fromByteArray(ext)).getOctets());
    CRLDistPoint dp = CRLDistPoint.getInstance(p);
    List<String> urls = new ArrayList<>();
    for (DistributionPoint point : dp.getDistributionPoints()) {
      DistributionPointName name = point.getDistributionPoint();
      if (name == null || name.getType() != DistributionPointName.FULL_NAME) continue;
      GeneralNames gns = GeneralNames.getInstance(name.getName());
      for (GeneralName gn : gns.getNames()) {
        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
          String u = gn.getName().toString();
          URI uri = URI.create(u);
          if (uri.getScheme() != null && (uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https"))) {
            urls.add(u);
          }
        }
      }
    }
    return urls;
  }

  private CrlFetcher() {}
}

