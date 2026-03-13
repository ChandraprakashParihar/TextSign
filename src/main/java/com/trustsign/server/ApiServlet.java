package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.ConfigLoader;
import com.trustsign.core.Pkcs11Token;
import com.trustsign.core.OsPkcs11Resolver;
import com.trustsign.core.SessionManager;
import com.trustsign.core.TextSignerService;
import com.trustsign.core.TextVerifyService;
import com.trustsign.core.CertificateValidator;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.swing.JPasswordField;
import javax.swing.JOptionPane;
import com.fasterxml.jackson.databind.JsonNode;

import java.awt.GraphicsEnvironment;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public final class ApiServlet extends HttpServlet {
  private final SessionManager sessions;

  public ApiServlet(SessionManager sessions) {
    this.sessions = sessions;
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String path = normPath(req.getPathInfo());

    try {
      switch (path) {
        case "/health" -> {
          writeJson(resp, 200, Map.of("status", "ok", "ts", Instant.now().toString()));
          return;
        }
        
        case "/certificates" -> {
          requireSession(req);

          AgentConfig cfg = ConfigLoader.load(resolveConfigFile());
          List<String> libs = OsPkcs11Resolver.candidates(cfg);
          if (libs.isEmpty()) {
            writeJson(resp, 400, Map.of("error", "No PKCS#11 libraries configured for this OS"));
            return;
          }

          char[] pin = promptPin();
          Pkcs11Token.Loaded loaded;
          try {
            loaded = Pkcs11Token.load(pin, libs);
          } catch (RuntimeException e) {
            String detail = buildTokenErrorDetail(e);
            writeJson(resp, 400, Map.of(
                "error", "Token load failed",
                "details", detail
            ));
            return;
          }

          var certs = Pkcs11Token.listCertificates(loaded.keyStore());

          writeJson(resp, 200, Map.of(
              "libraryPath", loaded.libraryPath(),
              "certCount", certs.size(),
              "certificates", certs
          ));
          return;
        }
        default -> {
          writeJson(resp, 404, Map.of("error", "Not found"));
          return;
        }
      }
    } catch (SecurityException se) {
      writeJson(resp, 403, Map.of("error", se.getMessage()));
    } catch (Exception e) {
      writeJson(resp, 500, Map.of("error", "Internal error", "details", safeMsg(e)));
    }
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String path = normPath(req.getPathInfo());

    try {
      switch (path) {
        case "/session" -> {
          SessionManager.Session s = sessions.createSessionMinutes(10);
          writeJson(resp, 200, Map.of("token", s.token(), "expiresAt", s.expiresAt().toString()));
          return;
        }

        case "/auto-sign-text" -> {
          var mp = Multipart.read(req, 2 * 1024 * 1024); // 2 MB text payload max
          byte[] data = mp.file("file");
          String outputDir = mp.field("outputDir");

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing text file field: file"));
            return;
          }
          if (outputDir == null || outputDir.isBlank()) {
            writeJson(resp, 400, Map.of("error", "Missing field: outputDir"));
            return;
          }

          char[] pin = promptPin();

          AgentConfig cfg = ConfigLoader.load(resolveConfigFile());
          List<String> libs = resolvePkcs11Libraries(cfg);
          if (libs.isEmpty()) {
            writeJson(resp, 400, Map.of("error", "No PKCS#11 libraries configured for this OS"));
            return;
          }

          Pkcs11Token.Loaded loaded;
          try {
            loaded = Pkcs11Token.load(pin, libs);
          } catch (RuntimeException e) {
            String detail = buildTokenErrorDetail(e);
            writeJson(resp, 400, Map.of(
                "error", "Token load failed",
                "details", detail
            ));
            return;
          }

          KeyStore ks = loaded.keyStore();

          PublicKey requestedPublicKey;
          try {
            requestedPublicKey = loadConfiguredPublicKey();
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to load configured public key", "details", safeMsg(e)));
            return;
          }

          String matchedAlias = null;
          X509Certificate matchedCert = null;
          Certificate[] chain = null;
          for (java.util.Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
            String a = e.nextElement();
            Certificate cert = ks.getCertificate(a);
            if (cert instanceof X509Certificate x509) {
              if (x509.getPublicKey().equals(requestedPublicKey)) {
                matchedAlias = a;
                matchedCert = x509;
                chain = ks.getCertificateChain(a);
                break;
              }
            }
          }

          if (matchedAlias == null || chain == null || chain.length == 0) {
            writeJson(resp, 400, Map.of("error", "No certificate on token matches provided public key"));
            return;
          }

          PrivateKey key = (PrivateKey) ks.getKey(matchedAlias, pin);
          if (key == null) {
            writeJson(resp, 400, Map.of("error", "No private key found for matching certificate"));
            return;
          }

          byte[] signature = TextSignerService.signDetached(data, key, chain, loaded.provider());

          String originalText = new String(data, java.nio.charset.StandardCharsets.UTF_8);
          String sigB64 = Base64.getEncoder().encodeToString(signature);

          X509Certificate signingCert = null;
          X509Certificate[] x509Chain = null;
          if (matchedCert != null) {
            signingCert = matchedCert;
          }
          if (chain[0] instanceof X509Certificate) {
            x509Chain = java.util.Arrays.stream(chain)
                .filter(c -> c instanceof X509Certificate)
                .map(c -> (X509Certificate) c)
                .toArray(X509Certificate[]::new);
          }
          if (signingCert != null) {
            CertificateValidator.validateForSigning(signingCert, x509Chain);
          }
          String certB64 = signingCert != null
              ? Base64.getEncoder().encodeToString(signingCert.getEncoded())
              : "";

          StringBuilder sb = new StringBuilder();
          sb.append(originalText);
          if (!originalText.endsWith("\n")) {
            sb.append("\n");
          }
          sb.append("<START-SIGNATURE>").append(sigB64).append("</START-SIGNATURE>\n");
          sb.append("<START-CERTIFICATE>").append(certB64).append("</START-CERTIFICATE>\n");
          sb.append("<SIGNER-VERSION>TrustSign</SIGNER-VERSION>\n");

          String inputFilename = mp.filename("file");
          if (inputFilename == null || inputFilename.isBlank()) {
            inputFilename = "text.txt";
          }
          File outDirFile = new File(outputDir);
          outDirFile.mkdirs();
          String baseName = inputFilename;
          String ext = "";
          int dot = inputFilename.lastIndexOf('.');
          if (dot > 0 && dot < inputFilename.length() - 1) {
            baseName = inputFilename.substring(0, dot);
            ext = inputFilename.substring(dot);
          }
          File outFile = new File(outDirFile, baseName + "-signed" + ext);

          java.nio.file.Files.writeString(
              outFile.toPath(),
              sb.toString(),
              java.nio.charset.StandardCharsets.UTF_8
          );

          writeJson(resp, 200, Map.of(
              "ok", true,
              "subjectDn", signingCert != null ? signingCert.getSubjectX500Principal().getName() : "",
              "serialNumber", signingCert != null ? signingCert.getSerialNumber().toString(16) : "",
              "outputPath", outFile.getAbsolutePath()
          ));
          return;
        }

        case "/sign-text" -> {
          requireSession(req);

          var mp = Multipart.read(req, 2 * 1024 * 1024); // 2 MB text payload max
          byte[] data = mp.file("file");

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing text file field: file"));
            return;
          }

          char[] pin = promptPin();

          AgentConfig cfg = ConfigLoader.load(resolveConfigFile());
          List<String> libs = resolvePkcs11Libraries(cfg);
          if (libs.isEmpty()) {
            writeJson(resp, 400, Map.of("error", "No PKCS#11 libraries configured for this OS"));
            return;
          }

          Pkcs11Token.Loaded loaded;
          try {
            loaded = Pkcs11Token.load(pin, libs);
          } catch (RuntimeException e) {
            String detail = buildTokenErrorDetail(e);
            writeJson(resp, 400, Map.of(
                "error", "Token load failed",
                "details", detail
            ));
            return;
          }

          KeyStore ks = loaded.keyStore();

          PublicKey requestedPublicKey;
          try {
            requestedPublicKey = loadConfiguredPublicKey();
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to load configured public key", "details", safeMsg(e)));
            return;
          }

          String matchedAlias = null;
          X509Certificate matchedCert = null;
          Certificate[] chain = null;
          for (java.util.Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
            String a = e.nextElement();
            Certificate cert = ks.getCertificate(a);
            if (cert instanceof X509Certificate x509) {
              if (x509.getPublicKey().equals(requestedPublicKey)) {
                matchedAlias = a;
                matchedCert = x509;
                chain = ks.getCertificateChain(a);
                break;
              }
            }
          }

          if (matchedAlias == null || chain == null || chain.length == 0) {
            writeJson(resp, 400, Map.of("error", "No certificate on token matches provided public key"));
            return;
          }

          PrivateKey key = (PrivateKey) ks.getKey(matchedAlias, pin);
          if (key == null) {
            writeJson(resp, 400, Map.of("error", "No private key found for matching certificate"));
            return;
          }

          byte[] signature = TextSignerService.signDetached(data, key, chain, loaded.provider());

          String originalText = new String(data, java.nio.charset.StandardCharsets.UTF_8);
          String sigB64 = Base64.getEncoder().encodeToString(signature);

          X509Certificate signingCert = null;
          X509Certificate[] x509Chain = null;
          if (matchedCert != null) {
            signingCert = matchedCert;
          }
          if (chain[0] instanceof X509Certificate) {
            x509Chain = java.util.Arrays.stream(chain)
                .filter(c -> c instanceof X509Certificate)
                .map(c -> (X509Certificate) c)
                .toArray(X509Certificate[]::new);
          }
          if (signingCert != null) {
            CertificateValidator.validateForSigning(signingCert, x509Chain);
          }
          String certB64 = signingCert != null
              ? Base64.getEncoder().encodeToString(signingCert.getEncoded())
              : "";

          StringBuilder sb = new StringBuilder();
          sb.append(originalText);
          if (!originalText.endsWith("\n")) {
            sb.append("\n");
          }
          sb.append("<START-SIGNATURE>").append(sigB64).append("</START-SIGNATURE>\n");
          sb.append("<START-CERTIFICATE>").append(certB64).append("</START-CERTIFICATE>\n");
          sb.append("<SIGNER-VERSION>TrustSign</SIGNER-VERSION>\n");

          resp.setStatus(200);
          resp.setContentType("text/plain; charset=UTF-8");
          String filename = mp.filename("file");
          if (filename == null || filename.isBlank()) filename = "text";
          resp.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
          resp.setHeader("X-Signer-SubjectDN", signingCert != null
              ? signingCert.getSubjectX500Principal().getName()
              : "");
          resp.setHeader("X-Signer-SerialNumber", signingCert != null
              ? signingCert.getSerialNumber().toString(16)
              : "");
          resp.getOutputStream().write(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
          return;
        }

        case "/verify-text" -> {
          var mp = Multipart.read(req, 2 * 1024 * 1024);
          byte[] data = mp.file("file");
          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("ok", false, "reason", "Missing text file field: file"));
            return;
          }
          String signed = new String(data, java.nio.charset.StandardCharsets.UTF_8);
          TextVerifyService.Result result = TextVerifyService.verify(signed);
          writeJson(resp, 200, Map.of("ok", result.ok(), "reason", result.reason()));
          return;
        }

        default -> {
          writeJson(resp, 404, Map.of("error", "Not found"));
          return;
        }
      }
    } catch (SecurityException se) {
      writeJson(resp, 403, Map.of("error", se.getMessage()));
    } catch (Exception e) {
      writeJson(resp, 500, Map.of("error", "Internal error", "details", safeMsg(e)));
    }
  }

  private void requireSession(HttpServletRequest req) {
    String token = req.getHeader("X-Session-Token");
    sessions.requireValid(token);
  }

  private static String normPath(String pathInfo) {
    if (pathInfo == null || pathInfo.isBlank()) return "";
    return pathInfo.startsWith("/") ? pathInfo : "/" + pathInfo;
  }

  private void writeJson(HttpServletResponse resp, int status, Object body) throws IOException {
    resp.setStatus(status);
    resp.setContentType("application/json");
    Json.MAPPER.writeValue(resp.getOutputStream(), body);
  }

  /**
   * Loads the signer public key from a configured location on disk.
   *
   * Resolution order:
   * - System property "trustsign.publicKey.path" if set
   * - "config/public-key.pem" relative to working directory
   * - "../config/public-key.pem" (for running from build output dir)
   */
  private static PublicKey loadConfiguredPublicKey() throws Exception {
    String path = System.getProperty("trustsign.publicKey.path");
    if (path == null || path.isBlank()) {
      File f1 = new File("config/public-key.pem");
      if (f1.exists()) {
        path = f1.getPath();
      } else {
        File f2 = new File("../config/public-key.pem");
        if (f2.exists()) {
          path = f2.getPath();
        } else {
          throw new IOException("No configured public key file found (checked config/public-key.pem and ../config/public-key.pem)");
        }
      }
    }

    String pem = java.nio.file.Files.readString(
        java.nio.file.Paths.get(path),
        java.nio.charset.StandardCharsets.UTF_8
    );
    return parsePublicKey(pem);
  }

  /**
   * Parses a public key. Supports:
   * - PEM encoded SubjectPublicKeyInfo ("-----BEGIN PUBLIC KEY-----")
   * - PEM encoded X.509 certificate ("-----BEGIN CERTIFICATE-----")
   * - raw base64-encoded DER SubjectPublicKeyInfo
   */
  private static PublicKey parsePublicKey(String pemOrBase64) throws Exception {
    String trimmed = pemOrBase64.trim();
    if (trimmed.contains("BEGIN CERTIFICATE")) {
      // Handle a full X.509 certificate PEM by extracting its public key
      String certPem = trimmed
          .replace("-----BEGIN CERTIFICATE-----", "")
          .replace("-----END CERTIFICATE-----", "")
          .replaceAll("\\s", "");
      byte[] certDer = java.util.Base64.getDecoder().decode(certPem);
      java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
      java.security.cert.X509Certificate cert =
          (java.security.cert.X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certDer));
      return cert.getPublicKey();
    }

    String normalized = trimmed
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s", "");
    byte[] der = java.util.Base64.getDecoder().decode(normalized);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
    // RSA is the typical algorithm for signing tokens here; if needed this
    // can be extended to detect EC, etc.
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePublic(spec);
  }
  private char[] promptPin() {
    // WARNING: Hardcoded PIN for development/testing only.
    // Do NOT use this approach in production.
    String pinStr = "12345678"; // <-- change this to your token PIN
    if (pinStr.isEmpty()) throw new SecurityException("Empty PIN not allowed");
    return pinStr.toCharArray();
  }

  private File resolveConfigFile() {
    File f1 = new File("config/config.json");
    if (f1.exists()) return f1;
    File f2 = new File("../config/config.json");
    if (f2.exists()) return f2;
    return f1;
  }

  private static List<String> resolvePkcs11Libraries(AgentConfig cfg) throws IOException {
    AgentConfig.Pkcs11Config pkcs = cfg.pkcs11();
    if (pkcs == null) return List.of();

    if (pkcs.preferredLibrary() != null && !pkcs.preferredLibrary().isBlank()) {
      return List.of(pkcs.preferredLibrary());
    }

    String os = System.getProperty("os.name", "").toLowerCase();
    if (os.contains("win")) {
      return pkcs.windowsCandidates() != null ? pkcs.windowsCandidates() : List.of();
    } else if (os.contains("mac")) {
      return pkcs.macCandidates() != null ? pkcs.macCandidates() : List.of();
    } else {
      return pkcs.linuxCandidates() != null ? pkcs.linuxCandidates() : List.of();
    }
  }

  private String safeMsg(Exception e) {
    String msg = e.getMessage();
    if (msg == null || msg.isBlank()) return e.getClass().getSimpleName();
    if (msg.length() > 300) return msg.substring(0, 300);
    return msg;
  }

  private static String buildTokenErrorDetail(RuntimeException e) {
    Throwable t = e;
    String msg = null;
    while (t != null) {
      msg = t.getMessage();
      if (msg != null && !msg.isBlank()) break;
      t = t.getCause();
    }
    if (msg != null && !msg.isBlank()) {
      if (msg.length() > 400) return msg.substring(0, 400);
      return msg;
    }
    return "Connect your PKCS#11 token, check the library path and PIN, and try again.";
  }
}

