package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.ConfigLoader;
import com.trustsign.core.Pkcs11Token;
import com.trustsign.core.OsPkcs11Resolver;
import com.trustsign.core.SessionManager;
import com.trustsign.core.SignedFileAnalyzer;
import com.trustsign.core.TextSignerService;
import com.trustsign.core.TextVerifyService;
import com.trustsign.core.CertificateValidator;
import com.trustsign.core.LicenceEnforcer;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public final class ApiServlet extends HttpServlet {
  private static final Logger LOG = Logger.getLogger(ApiServlet.class.getName());
  private static final Pattern SAFE_FILENAME = Pattern.compile("[^a-zA-Z0-9._-]");

  private final SessionManager sessions;
  private final LicenceEnforcer licenceEnforcer;

  public ApiServlet(SessionManager sessions, LicenceEnforcer licenceEnforcer) {
    this.sessions = sessions;
    this.licenceEnforcer = licenceEnforcer;
  }

  /**
   * Loads config from resolved path. On failure writes error response and returns null.
   */
  private AgentConfig loadConfig(HttpServletResponse resp) throws IOException {
    File f = resolveConfigFile();
    if (!f.exists()) {
      writeJson(resp, 500, Map.of("error", "Config file not found", "path", f.getAbsolutePath()));
      return null;
    }
    try {
      return ConfigLoader.load(f);
    } catch (Exception e) {
      LOG.warning("Config load failed: " + e.getMessage());
      writeJson(resp, 500, Map.of("error", "Invalid config", "details", safeMsg(e)));
      return null;
    }
  }

  /**
   * Resolves outputDir to a directory. Rejects path traversal (..).
   * When basePath is null, the user can pass any directory path (absolute or relative to working dir).
   * When basePath is set (outputBaseDir in config), outputDir must be under that base.
   */
  private static File resolveSafeOutputDir(String outputDir, Path basePath) {
    if (outputDir == null || outputDir.isBlank()) {
      throw new IllegalArgumentException("outputDir is required");
    }
    Path requested = Paths.get(outputDir.trim()).normalize();
    if (requested.toString().contains("..")) {
      throw new SecurityException("outputDir must not contain '..'");
    }
    Path base = Paths.get(System.getProperty("user.dir", ".")).toAbsolutePath().normalize();
    Path resolved = requested.isAbsolute() ? requested.normalize().toAbsolutePath() : base.resolve(requested).normalize().toAbsolutePath();
    if (basePath != null) {
      Path allowedBase = basePath.toAbsolutePath().normalize();
      if (!resolved.startsWith(allowedBase)) {
        throw new SecurityException("outputDir must be under configured outputBaseDir (" + allowedBase + ")");
      }
    }
    return resolved.toFile();
  }

  /** Sanitizes a filename for Content-Disposition header (no path, no control chars). */
  private static String sanitizeFilename(String filename) {
    if (filename == null || filename.isBlank()) return "signed.txt";
    String name = Paths.get(filename).getFileName().toString();
    if (name == null || name.isBlank()) return "signed.txt";
    name = SAFE_FILENAME.matcher(name).replaceAll("_");
    if (name.length() > 200) name = name.substring(0, 200);
    return name.isEmpty() ? "signed.txt" : name;
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    LicenceEnforcer.Result licence = licenceEnforcer.check();
    if (!licence.allowed()) {
      writeJson(resp, 403, Map.of("error", "Licence", "message", licence.message()));
      return;
    }
    String path = normPath(req.getPathInfo());

    try {
      switch (path) {
        case "/health" -> {
          writeJson(resp, 200, Map.of("status", "ok", "ts", Instant.now().toString()));
          return;
        }
        case "/pkcs11/candidates" -> {
          AgentConfig cfg = loadConfig(resp);
          if (cfg == null) return;
          List<String> libs = OsPkcs11Resolver.candidates(cfg);
          List<Map<String, Object>> list = libs.stream()
              .map(p -> Map.<String, Object>of(
                  "path", p,
                  "exists", Files.isRegularFile(Paths.get(p))
              ))
              .toList();
          Map<String, Object> body = new java.util.HashMap<>(Map.of("candidates", list));
          if (OsPkcs11Resolver.current() == OsPkcs11Resolver.Os.WINDOWS) {
            body.put("discovered", discoverPkcs11OnWindows());
          }
          writeJson(resp, 200, body);
          return;
        }
        case "/certificates" -> {
          requireSession(req);

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null) return;
          List<String> libs = OsPkcs11Resolver.candidates(cfg);
          if (libs.isEmpty()) {
            writeJson(resp, 400, Map.of("error", "No PKCS#11 libraries configured for this OS"));
            return;
          }

          char[] pin = resolvePin(cfg);
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
      LOG.warning("GET error: " + e.getMessage());
      writeJson(resp, 500, Map.of("error", "Internal error", "details", safeMsg(e)));
    }
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    LicenceEnforcer.Result licence = licenceEnforcer.check();
    if (!licence.allowed()) {
      writeJson(resp, 403, Map.of("error", "Licence", "message", licence.message()));
      return;
    }
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

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null) return;

          Path outputBase = null;
          if (cfg.outputBaseDir() != null && !cfg.outputBaseDir().isBlank()) {
            outputBase = Paths.get(cfg.outputBaseDir());
            if (!outputBase.isAbsolute()) {
              outputBase = Paths.get(System.getProperty("user.dir", ".")).resolve(outputBase).normalize();
            }
          }
          File outDirFile;
          try {
            outDirFile = resolveSafeOutputDir(outputDir, outputBase);
          } catch (SecurityException | IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", "Invalid outputDir", "details", e.getMessage()));
            return;
          }

          char[] pin = resolvePin(cfg);
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
            requestedPublicKey = loadConfiguredPublicKeyOrThrow();
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

          // Normalize line endings to \n so signing is consistent (Windows CRLF vs Unix LF).
          String originalText = new String(data, java.nio.charset.StandardCharsets.UTF_8);
          String normalizedText = originalText.replace("\r\n", "\n").replace("\r", "\n");
          // Sign exactly the bytes that will appear before <START-SIGNATURE> in the output file.
          // If trustsign.signContentWithoutTrailingNewline=true, sign without the trailing newline (for verifiers that strip it).
          byte[] contentToSign;
          if (Boolean.getBoolean("trustsign.signContentWithoutTrailingNewline")) {
            String contentForSigning = normalizedText.endsWith("\n")
                ? normalizedText.substring(0, normalizedText.length() - 1) : normalizedText;
            contentToSign = contentForSigning.getBytes(java.nio.charset.StandardCharsets.UTF_8);
          } else {
            byte[] normBytes = normalizedText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            contentToSign = normalizedText.endsWith("\n") ? normBytes : java.util.Arrays.copyOf(normBytes, normBytes.length + 1);
            if (!normalizedText.endsWith("\n")) contentToSign[normBytes.length] = '\n';
          }
          // Use SHA1withRSA so output is verifiable on Icegate (they expect this algorithm).
          byte[] sigBytes = TextSignerService.signRawSha1WithRsa(contentToSign, key, loaded.provider());

          String sigB64 = Base64.getEncoder().encodeToString(sigBytes);

          X509Certificate signingCert = matchedCert;
          X509Certificate[] x509Chain = null;
          if (chain[0] instanceof X509Certificate) {
            x509Chain = java.util.Arrays.stream(chain)
                .filter(c -> c instanceof X509Certificate)
                .map(c -> (X509Certificate) c)
                .toArray(X509Certificate[]::new);
          }
          CertificateValidator.validateForSigning(signingCert, x509Chain);
          String certB64 = Base64.getEncoder().encodeToString(signingCert.getEncoded());

          String signerVersion = (cfg.signerVersion() != null && !cfg.signerVersion().isBlank())
              ? cfg.signerVersion() : "TrustSign";

          StringBuilder sb = new StringBuilder();
          sb.append(normalizedText);
          if (!normalizedText.endsWith("\n")) {
            sb.append("\n");
          }
          sb.append("<START-SIGNATURE>").append(sigB64).append("</START-SIGNATURE>\n");
          sb.append("<START-CERTIFICATE>").append(certB64).append("</START-CERTIFICATE>\n");
          sb.append("<SIGNER-VERSION>").append(signerVersion).append("</SIGNER-VERSION>\n");

          String inputFilename = mp.filename("file");
          if (inputFilename == null || inputFilename.isBlank()) {
            inputFilename = "text.txt";
          }
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

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null) return;
          char[] pin = resolvePin(cfg);
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
            requestedPublicKey = loadConfiguredPublicKeyOrThrow();
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

          byte[] signature = TextSignerService.signRawSha1WithRsa(data, key, loaded.provider());

          String originalText = new String(data, java.nio.charset.StandardCharsets.UTF_8);
          String sigB64 = Base64.getEncoder().encodeToString(signature);

          X509Certificate signingCert = matchedCert;
          X509Certificate[] x509Chain = null;
          if (chain[0] instanceof X509Certificate) {
            x509Chain = java.util.Arrays.stream(chain)
                .filter(c -> c instanceof X509Certificate)
                .map(c -> (X509Certificate) c)
                .toArray(X509Certificate[]::new);
          }
          CertificateValidator.validateForSigning(signingCert, x509Chain);
          String certB64 = Base64.getEncoder().encodeToString(signingCert.getEncoded());

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
          String filename = sanitizeFilename(mp.filename("file"));
          resp.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
          resp.setHeader("X-Signer-SubjectDN", signingCert.getSubjectX500Principal().getName());
          resp.setHeader("X-Signer-SerialNumber", signingCert.getSerialNumber().toString(16));
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
          String signed = new String(data, StandardCharsets.UTF_8);
          // TextVerifyService.Result result = TextVerifyService.verify(signed);
          TextVerifyService.Result result = TextVerifyService.verifySha256WithRsa(signed);
          writeJson(resp, 200, Map.of("ok", result.ok(), "reason", result.reason()));
          return;
        }

        case "/analyze-signed-file" -> {
          var mp = Multipart.read(req, 2 * 1024 * 1024);
          byte[] data = mp.file("file");
          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing file field: file"));
            return;
          }
          String signedText = new String(data, StandardCharsets.UTF_8);
          int sigStart = signedText.indexOf("<START-SIGNATURE>");
          byte[] rawBeforeSig = sigStart > 0 ? Arrays.copyOf(data, sigStart) : new byte[0];
          SignedFileAnalyzer.Result analysis = SignedFileAnalyzer.analyze(signedText, rawBeforeSig);
          writeJson(resp, 200, analysis);
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
      LOG.warning("POST error: " + e.getMessage());
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

  /**
   * On Windows, searches common locations for PKCS#11 DLLs (pkcs11.dll or *pkcs*.dll / *p11*.dll)
   * so the user can set preferredLibrary if the driver is installed in a non-standard path.
   */
  private static List<Map<String, Object>> discoverPkcs11OnWindows() {
    List<Map<String, Object>> out = new java.util.ArrayList<>();
    java.util.Set<String> seen = new java.util.HashSet<>();

    String sysRoot = System.getenv("SystemRoot");
    String[] roots = {
        System.getenv("ProgramFiles"),
        System.getenv("ProgramFiles(x86)"),
        sysRoot != null ? sysRoot + "\\System32" : null,
        sysRoot != null ? sysRoot + "\\SysWOW64" : null
    };

    for (String rootStr : roots) {
      if (rootStr == null || rootStr.isBlank()) continue;
      Path root = Paths.get(rootStr);
      if (!Files.isDirectory(root)) continue;

      if (rootStr.contains("System32") || rootStr.contains("SysWOW64")) {
        addDllsInDir(root, seen, out);
        continue;
      }

      int count = 0;
      try (var stream = Files.list(root)) {
        for (Path dir : stream.toList()) {
          if (count >= 100) break;
          if (!Files.isDirectory(dir)) continue;
          count++;
          for (String rel : new String[] { "", "bin/", "x64/", "x86/" }) {
            Path base = rel.isEmpty() ? dir : dir.resolve(rel);
            if (!Files.isDirectory(base) && !rel.isEmpty()) continue;
            if (rel.isEmpty() && !Files.isDirectory(base)) continue;
            addDllsInDir(base, seen, out);
          }
        }
      } catch (Exception ignore) { }
    }
    return out;
  }

  private static void addDllsInDir(Path dir, java.util.Set<String> seen, List<Map<String, Object>> out) {
    try (var stream = Files.list(dir)) {
      for (Path p : stream.toList()) {
        if (!Files.isRegularFile(p)) continue;
        String name = p.getFileName().toString().toLowerCase();
        if (!name.endsWith(".dll")) continue;
        if (name.contains("pkcs") || name.contains("p11") || name.equals("pkcs11.dll")) {
          String path = p.toAbsolutePath().toString();
          if (seen.add(path)) {
            out.add(Map.of("path", path, "exists", true));
          }
        }
      }
    } catch (Exception ignore) { }
  }

  private void writeJson(HttpServletResponse resp, int status, Object body) throws IOException {
    resp.setStatus(status);
    resp.setContentType("application/json");
    Json.MAPPER.writeValue(resp.getOutputStream(), body);
  }

  /**
   * Loads the signer public key from a configured location on disk.
   * Resolution order: trustsign.publicKey.path, config/public-key.pem, ../config/public-key.pem.
   */
  private static PublicKey loadConfiguredPublicKeyOrThrow() throws Exception {
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
  /**
   * Resolves the token PIN from: 1) env TRUSTSIGN_TOKEN_PIN, 2) config pkcs11.pin.
   * Client can set either in config.json ("pkcs11": { "pin": "their-pin" }) or via environment variable.
   */
  private char[] resolvePin(AgentConfig cfg) {
    String pinStr = System.getenv("TRUSTSIGN_TOKEN_PIN");
    if (pinStr == null || pinStr.isBlank()) {
      if (cfg.pkcs11() != null && cfg.pkcs11().pin() != null && !cfg.pkcs11().pin().isBlank()) {
        pinStr = cfg.pkcs11().pin();
      }
    }
    if (pinStr == null || pinStr.isBlank()) {
      throw new SecurityException(
          "Token PIN not configured. Set it in config.json (pkcs11.pin) or set environment variable TRUSTSIGN_TOKEN_PIN.");
    }
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
    if (cfg.pkcs11() == null) return List.of();
    return OsPkcs11Resolver.candidates(cfg);
  }

  private String safeMsg(Exception e) {
    String msg = e.getMessage();
    if (msg == null || msg.isBlank()) return e.getClass().getSimpleName();
    if (msg.length() > 300) return msg.substring(0, 300);
    return msg;
  }

  private static String buildTokenErrorDetail(RuntimeException e) {
    Throwable root = e;
    while (root.getCause() != null) root = root.getCause();
    String causeMsg = root.getMessage();
    if (causeMsg != null && !causeMsg.isBlank()) {
      String out = causeMsg.length() > 400 ? causeMsg.substring(0, 400) : causeMsg;
      if (root != e) return out + " (from " + root.getClass().getSimpleName() + ")";
      return out;
    }
    String topMsg = e.getMessage();
    if (topMsg != null && !topMsg.isBlank()) return topMsg;
    return "Connect your PKCS#11 token, check the library path and PIN, and try again.";
  }
}

