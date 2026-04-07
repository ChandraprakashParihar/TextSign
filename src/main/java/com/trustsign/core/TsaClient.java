package com.trustsign.core;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.SecureRandom;

/** RFC 3161 TSA client for signature timestamp tokens. */
public final class TsaClient {

  public record Config(
      String url,
      String hashAlgorithm,
      boolean failOnError,
      int connectTimeoutMs,
      int readTimeoutMs) {
    public static final Config DISABLED = new Config(null, "SHA-256", false, 10_000, 15_000);

    public boolean enabled() {
      return url != null && !url.isBlank();
    }

    public String normalizedHashAlgorithm() {
      if (hashAlgorithm == null || hashAlgorithm.isBlank()) {
        return "SHA-256";
      }
      String a = hashAlgorithm.trim().toUpperCase(java.util.Locale.ROOT);
      if (a.equals("SHA256")) return "SHA-256";
      return a;
    }
  }

  private final Config cfg;
  private final SecureRandom rng = new SecureRandom();

  public TsaClient(Config cfg) {
    this.cfg = cfg == null ? Config.DISABLED : cfg;
  }

  /** Timestamp token over signature value bytes (RFC 3161, id-aa-signatureTimeStampToken usage). */
  public byte[] requestTimestampToken(byte[] signatureValue) throws Exception {
    if (!cfg.enabled()) {
      throw new IllegalStateException("TSA is disabled");
    }
    String hashAlg = cfg.normalizedHashAlgorithm();
    MessageDigest md = MessageDigest.getInstance(hashAlg);
    byte[] digest = md.digest(signatureValue);

    ASN1ObjectIdentifier oid = switch (hashAlg) {
      case "SHA-256" -> TSPAlgorithms.SHA256;
      default -> throw new IllegalArgumentException("Unsupported TSA hash algorithm: " + hashAlg);
    };

    TimeStampRequestGenerator gen = new TimeStampRequestGenerator();
    gen.setCertReq(true);
    TimeStampRequest req = gen.generate(oid, digest, java.math.BigInteger.valueOf(Math.abs(rng.nextLong())));
    byte[] reqBytes = req.getEncoded();

    HttpURLConnection conn = (HttpURLConnection) new URL(cfg.url().trim()).openConnection();
    conn.setConnectTimeout(Math.max(cfg.connectTimeoutMs(), 1000));
    conn.setReadTimeout(Math.max(cfg.readTimeoutMs(), 1000));
    conn.setRequestMethod("POST");
    conn.setDoOutput(true);
    conn.setRequestProperty("Content-Type", "application/timestamp-query");
    conn.setRequestProperty("Accept", "application/timestamp-reply");

    try (OutputStream os = conn.getOutputStream()) {
      os.write(reqBytes);
    }

    int code = conn.getResponseCode();
    InputStream is = code >= 200 && code < 300 ? conn.getInputStream() : conn.getErrorStream();
    if (is == null) {
      throw new IllegalStateException("TSA HTTP " + code + " with empty response body");
    }
    byte[] respBytes;
    try (InputStream in = is) {
      respBytes = in.readAllBytes();
    }
    if (code < 200 || code >= 300) {
      throw new IllegalStateException("TSA HTTP " + code + " response: " + new String(respBytes));
    }

    TimeStampResponse resp = new TimeStampResponse(respBytes);
    resp.validate(req);
    if (resp.getStatus() != 0 && resp.getStatus() != 1) {
      throw new IllegalStateException("TSA rejected request, status=" + resp.getStatus() + " failureInfo="
          + (resp.getFailInfo() != null ? resp.getFailInfo().intValue() : -1));
    }
    TimeStampToken token = resp.getTimeStampToken();
    if (token == null) {
      throw new IllegalStateException("TSA response missing TimeStampToken");
    }
    return token.getEncoded();
  }
}

