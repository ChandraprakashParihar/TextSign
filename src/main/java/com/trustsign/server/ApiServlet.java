package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.AgentConfig.ServerConfig;
import com.trustsign.core.ConfigLoader;
import com.trustsign.core.HsmPdfSignerService;
import com.trustsign.core.PdfSignerService;
import com.trustsign.core.PdfSignerService.PdfSigningOptions;
import com.trustsign.core.PdfVerifyService;
import com.trustsign.core.Pkcs11Token;
import com.trustsign.core.OsPkcs11Resolver;
import com.trustsign.core.SessionManager;
import com.trustsign.core.SignedFileAnalyzer;
import com.trustsign.core.TextSignerService;
import com.trustsign.core.TextVerifyService;
import com.trustsign.core.CertificateValidator;
import com.trustsign.core.LicenceEnforcer;
import com.trustsign.hsm.HsmPkcs11ConfigurationService;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ApiServlet extends HttpServlet {
  private static final Logger LOG = Logger.getLogger(ApiServlet.class.getName());
  private static final Pattern SAFE_FILENAME = Pattern.compile("[^a-zA-Z0-9._-]");

  private final SessionManager sessions;
  private final LicenceEnforcer licenceEnforcer;
  private final SigningConcurrencyGate signingGate;
  private final int multipartPdfMaxBytes;
  private final int multipartTextMaxBytes;
  /** Former 5 MiB cap for verify-text / debug; bounded by PDF limit. */
  private final int multipartMediumMaxBytes;

  public ApiServlet(SessionManager sessions, LicenceEnforcer licenceEnforcer, SigningConcurrencyGate signingGate) {
    this(sessions, licenceEnforcer, signingGate, null);
  }

  public ApiServlet(
      SessionManager sessions,
      LicenceEnforcer licenceEnforcer,
      SigningConcurrencyGate signingGate,
      ServerConfig serverLimits) {
    this.sessions = sessions;
    this.licenceEnforcer = licenceEnforcer;
    this.signingGate = signingGate != null ? signingGate : SigningConcurrencyGate.unlimited();
    int pdfMb = ServerConfig.multipartPdfMaxFileMbOrDefault(serverLimits);
    int textMb = ServerConfig.multipartTextMaxFileMbOrDefault(serverLimits);
    this.multipartPdfMaxBytes = pdfMb * 1024 * 1024;
    this.multipartTextMaxBytes = textMb * 1024 * 1024;
    this.multipartMediumMaxBytes = Math.min(multipartPdfMaxBytes, Math.max(multipartTextMaxBytes, 5 * 1024 * 1024));
  }

  /**
   * Returns true if the client IP is allowed according to
   * config.allowedClientIps.
   * When allowedClientIps is null or empty, all IPs are allowed.
   */
  private boolean isClientIpAllowed(HttpServletRequest req) {
    String remoteIp = req.getRemoteAddr();
    try {
      File cfgFile = resolveConfigFile();
      if (!cfgFile.exists()) {
        LOG.warning("Config file not found for IP check: " + cfgFile.getAbsolutePath());
        return false;
      }
      AgentConfig cfg = ConfigLoader.load(cfgFile);
      List<String> allowed = cfg.allowedClientIps();
      if (allowed == null || allowed.isEmpty()) {
        return true;
      }
      boolean ok = allowed.contains(remoteIp);
      if (!ok) {
        LOG.warning("Rejecting request from disallowed IP: " + remoteIp);
      }
      return ok;
    } catch (Exception e) {
      LOG.warning("Failed to evaluate client IP allowlist: " + e.getMessage());
      return false;
    }
  }

  /**
   * Loads config from resolved path. On failure writes error response and returns
   * null.
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
   * When basePath is null, the user can pass any directory path (absolute or
   * relative to working dir).
   * When basePath is set (outputBaseDir in config), outputDir must be under that
   * base.
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
    Path resolved = requested.isAbsolute() ? requested.normalize().toAbsolutePath()
        : base.resolve(requested).normalize().toAbsolutePath();
    if (basePath != null) {
      Path allowedBase = basePath.toAbsolutePath().normalize();
      if (!resolved.startsWith(allowedBase)) {
        throw new SecurityException("outputDir must be under configured outputBaseDir (" + allowedBase + ")");
      }
    }
    File dir = resolved.toFile();
    if (dir.exists() && !dir.isDirectory()) {
      throw new IllegalArgumentException("outputDir must be a directory (but is a file): " + dir.getAbsolutePath());
    }
    if (!dir.exists()) {
      boolean created = dir.mkdirs();
      if (!created && !dir.exists()) {
        throw new IllegalArgumentException("outputDir cannot be created or is not writable: " + dir.getAbsolutePath());
      }
    }
    if (!dir.canWrite()) {
      throw new IllegalArgumentException("outputDir is not writable: " + dir.getAbsolutePath());
    }
    return dir;
  }

  /**
   * Sanitizes a filename for Content-Disposition header (no path, no control
   * chars).
   */
  private static String sanitizeFilename(String filename) {
    if (filename == null || filename.isBlank())
      return "signed.txt";
    String name = Paths.get(filename).getFileName().toString();
    if (name == null || name.isBlank())
      return "signed.txt";
    name = SAFE_FILENAME.matcher(name).replaceAll("_");
    if (name.length() > 200)
      name = name.substring(0, 200);
    return name.isEmpty() ? "signed.txt" : name;
  }

  private static boolean isPdfUpload(byte[] data, String filename) {
    if (filename != null && filename.toLowerCase(java.util.Locale.ROOT).endsWith(".pdf")) {
      return true;
    }
    return looksLikePdfHeader(data);
  }

  /** True when bytes start with a PDF file header ({@code %PDF-}). */
  private static boolean looksLikePdfHeader(byte[] data) {
    return data != null
        && data.length >= 5
        && data[0] == '%'
        && data[1] == 'P'
        && data[2] == 'D'
        && data[3] == 'F'
        && data[4] == '-';
  }

  /**
   * For auto-sign PDF routes: the next signature is chained from the previous numbered output when present
   * ({@code stem-signed.pdf} → {@code stem-signed1.pdf} → …) so earlier signatures stay valid.
   * Multipart {@code signFromUpload} true/1/yes/y forces signing the uploaded file only (no chain).
   */
  private static byte[] resolveAutoSignIncrementalInput(byte[] uploadedPdf, File targetSignedFile, Multipart.Data mp)
      throws IOException {
    if (parseBooleanLoose(readMultipartString(mp, "signFromUpload", true))) {
      return uploadedPdf;
    }
    File chainSource = predecessorAutoSignPdfOutput(targetSignedFile);
    if (chainSource == null || !chainSource.isFile() || chainSource.length() == 0) {
      return uploadedPdf;
    }
    byte[] existing = Files.readAllBytes(chainSource.toPath());
    if (looksLikePdfHeader(existing)) {
      return existing;
    }
    return uploadedPdf;
  }

  private static String stripPdfExtension(String sanitizedName) {
    int dot = sanitizedName.lastIndexOf('.');
    if (dot <= 0) {
      return sanitizedName;
    }
    if (sanitizedName.substring(dot).equalsIgnoreCase(".pdf")) {
      return sanitizedName.substring(0, dot);
    }
    return sanitizedName.substring(0, dot);
  }

  /**
   * Base name for auto-sign PDF outputs: strips {@code .pdf} and repeated trailing {@code -signed} / {@code -signedN}
   * so an upload {@code test-signed.pdf} still maps to stem {@code test} (avoids {@code test-signed-signed.pdf}).
   */
  private static String pdfStemForAutoSignOutput(String uploadFilename) {
    String safe = sanitizeFilename(uploadFilename);
    String base = stripPdfExtension(safe);
    while (base.matches("(?i).+-signed\\d*")) {
      base = base.replaceFirst("(?i)-signed\\d*$", "");
    }
    return base.isBlank() ? "document" : base;
  }

  private static final Pattern AUTO_SIGN_PDF_NUMBERED = Pattern.compile("(?i)^(.+)-signed(\\d+)$");

  /**
   * Previous file in the numbered sequence: {@code stem-signedN.pdf} → {@code stem-signed(N-1).pdf},
   * {@code stem-signed1.pdf} → {@code stem-signed.pdf}. Unnumbered target has no predecessor.
   */
  private static File predecessorAutoSignPdfOutput(File targetOutFile) {
    String name = targetOutFile.getName();
    if (name.length() < 5 || !name.substring(name.length() - 4).equalsIgnoreCase(".pdf")) {
      return null;
    }
    String base = name.substring(0, name.length() - 4);
    Matcher m = AUTO_SIGN_PDF_NUMBERED.matcher(base);
    if (!m.matches()) {
      return null;
    }
    String stem = m.group(1);
    int n = Integer.parseInt(m.group(2));
    File dir = targetOutFile.getParentFile();
    if (n <= 1) {
      return new File(dir, stem + "-signed.pdf");
    }
    return new File(dir, stem + "-signed" + (n - 1) + ".pdf");
  }

  /**
   * First free output path: {@code stem-signed.pdf}, then {@code stem-signed1.pdf}, {@code stem-signed2.pdf}, …
   */
  private static File resolveNextAutoSignPdfOutput(File outDir, String uploadFilename) {
    String stem = pdfStemForAutoSignOutput(uploadFilename);
    File first = new File(outDir, stem + "-signed.pdf");
    if (!first.exists()) {
      return first;
    }
    for (int n = 1; ; n++) {
      if (n > 99_999) {
        throw new IllegalStateException("Too many signed PDF variants for stem: " + stem);
      }
      File fn = new File(outDir, stem + "-signed" + n + ".pdf");
      if (!fn.exists()) {
        return fn;
      }
    }
  }

  /** Suggested download name for streaming sign endpoints (single file, not numbered). */
  private static String buildSignedPdfFilename(String filename) {
    String safe = sanitizeFilename(filename);
    String base = stripPdfExtension(safe);
    while (base.matches("(?i).+-signed\\d*")) {
      base = base.replaceFirst("(?i)-signed\\d*$", "");
    }
    if (base.isBlank()) {
      base = "document";
    }
    return base + "-signed.pdf";
  }

  private static boolean parseBooleanLoose(String v) {
    if (v == null) return false;
    String t = v.trim().toLowerCase(java.util.Locale.ROOT);
    return t.equals("true") || t.equals("1") || t.equals("yes") || t.equals("y");
  }

  /** Multipart field or file part {@code finalVersion} (true/1/yes/y). */
  private static boolean parseFinalVersionMultipart(Multipart.Data mp) {
    String v = mp.field("finalVersion");
    if (v == null) {
      byte[] b = mp.file("finalVersion");
      if (b != null && b.length > 0) {
        v = new String(b, StandardCharsets.UTF_8).trim();
      }
    }
    return parseBooleanLoose(v);
  }

  private static Integer parsePositiveInt(String v) {
    if (v == null) return null;
    String t = v.trim();
    if (t.isEmpty()) return null;
    try {
      int n = Integer.parseInt(t);
      return n > 0 ? n : null;
    } catch (Exception ignore) {
      return null;
    }
  }

  /**
   * Reads a text multipart field or a same-named file part (Postman-style). For PEM bodies, use {@code trimBody=false}.
   */
  private static String readMultipartString(Multipart.Data mp, String name, boolean trimBody) {
    String v = mp.field(name);
    if (v != null && !v.isEmpty()) {
      v = trimBody ? v.trim() : v;
    } else {
      byte[] b = mp.file(name);
      if (b != null && b.length > 0) {
        v = new String(b, StandardCharsets.UTF_8);
        v = trimBody ? v.trim() : v;
      } else {
        v = null;
      }
    }
    if (v == null || v.isEmpty()) {
      return null;
    }
    if (v.charAt(0) == '\uFEFF') {
      v = v.substring(1).trim();
    }
    return v.isEmpty() ? null : v;
  }

  /**
   * HSM signer certificate: prefers raw file part {@code cer} (PEM or DER), else form field text as UTF-8.
   */
  private static byte[] readMultipartCerPayload(Multipart.Data mp) {
    byte[] filePart = mp.file("cer");
    if (filePart != null && filePart.length > 0) {
      return filePart;
    }
    String field = mp.field("cer");
    if (field != null && !field.isEmpty()) {
      return field.getBytes(StandardCharsets.UTF_8);
    }
    return null;
  }

  /**
   * Parses comma-separated 1-based page numbers (e.g. "1,3,5") into 0-based indices.
   */
  private static java.util.List<Integer> parsePagesCsv1Based(String pagesCsv) {
    if (pagesCsv == null || pagesCsv.isBlank()) {
      return java.util.List.of();
    }
    java.util.List<Integer> out = new java.util.ArrayList<>();
    for (String part : pagesCsv.split(",")) {
      Integer p1 = parsePositiveInt(part);
      if (p1 != null) {
        out.add(p1 - 1);
      }
    }
    return out;
  }

  /**
   * Resolves which PDF pages should get the visible stamp.
   * - {@code allPages}: if true, stamps all pages (evaluated before {@code pages} so a default hidden {@code pages=1}
   *   does not cancel {@code allPages=true})
   * - {@code pages}: comma-separated 1-based page numbers (e.g. {@code 1,3,5})
   * - {@code page} or {@code startPage}: single 1-based page (field or file part, like other multipart text)
   * - default: page 1 only (no config; use {@code allPages}, {@code pages}, {@code page}, or {@code startPage} to change)
   */
  private static java.util.List<Integer> resolvePdfStampPages(Multipart.Data mp) {
    String allPagesStr = readMultipartString(mp, "allPages", true);
    if (parseBooleanLoose(allPagesStr)) {
      return java.util.List.of(-1);
    }

    String pagesCsv = readMultipartString(mp, "pages", true);
    if (pagesCsv != null && !pagesCsv.isBlank()) {
      java.util.List<Integer> pages = parsePagesCsv1Based(pagesCsv);
      return pages.isEmpty() ? java.util.List.of(0) : pages;
    }

    Integer page1 = parsePositiveInt(readMultipartString(mp, "page", true));
    if (page1 == null) {
      page1 = parsePositiveInt(readMultipartString(mp, "startPage", true));
    }
    if (page1 != null) {
      return java.util.List.of(page1 - 1);
    }

    return java.util.List.of(0);
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    if (!isClientIpAllowed(req)) {
      writeJson(resp, 403, Map.of("error", "IP not allowed", "ip", req.getRemoteAddr()));
      return;
    }
    LicenceEnforcer.Result licence = licenceEnforcer.check();
    if (!licence.allowed()) {
      writeJson(resp, 403, Map.of("error", "Licence", "message", licence.message()));
      return;
    }
    String path = normPath(req.getPathInfo());

    try {
      switch (path) {
        case "/health" -> {
          Map<String, Object> health = new LinkedHashMap<>();
          health.put("status", "ok");
          health.put("ts", Instant.now().toString());
          if (signingGate.isLimited()) {
            health.put("signingSlotsAvailable", signingGate.availablePermits());
            health.put("signingSlotsTotal", signingGate.totalPermits());
          }
          writeJson(resp, 200, health);
          return;
        }
        case "/pkcs11/candidates" -> {
          requireSession(req);
          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;
          List<String> libs = OsPkcs11Resolver.candidates(cfg);
          List<Map<String, Object>> list = libs.stream()
              .map(p -> Map.<String, Object>of(
                  "path", p,
                  "exists", Files.isRegularFile(Paths.get(p))))
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
          if (cfg == null)
            return;
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
                "details", detail));
            return;
          }

          var certs = Pkcs11Token.listCertificates(loaded.keyStore());

          writeJson(resp, 200, Map.of(
              "libraryPath", loaded.libraryPath(),
              "certCount", certs.size(),
              "certificates", certs));
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
    if (!isClientIpAllowed(req)) {
      writeJson(resp, 403, Map.of("error", "IP not allowed", "ip", req.getRemoteAddr()));
      return;
    }
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
          // requireSession(req);
          var mp = Multipart.read(req, multipartTextMaxBytes);
          byte[] data = mp.file("file");

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing text file field: file"));
            return;
          }
          if (isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400, Map.of("error", "PDF is not allowed on /auto-sign-text. Use /sign-pdf or /auto-sign-pdf."));
            return;
          }

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;

          String outputDir = cfg.autoSignOutputDir();
          if (outputDir == null || outputDir.isBlank()) {
            writeJson(resp, 500,
                Map.of("error", "Configuration error", "details", "autoSignOutputDir is not configured"));
            return;
          }

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
                "details", detail));
            return;
          }

          KeyStore ks = loaded.keyStore();

          java.util.List<PublicKey> requestedPublicKeys;
          try {
            requestedPublicKeys = loadConfiguredPublicKeysOrThrow();
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to load configured public key(s)", "details", safeMsg(e)));
            return;
          }

          CertificateSelection selection;
          try {
            selection = selectCertificateForPublicKeys(ks, requestedPublicKeys);
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to select certificate from token", "details", safeMsg(e)));
            return;
          }

          if (selection == null || selection.chain == null || selection.chain.length == 0) {
            writeJson(resp, 400, Map.of("error", "No certificate on token matches any configured public key"));
            return;
          }

          String matchedAlias = selection.alias;
          X509Certificate matchedCert = selection.certificate;
          Certificate[] chain = selection.chain;

          PrivateKey key = (PrivateKey) ks.getKey(matchedAlias, pin);
          if (key == null) {
            writeJson(resp, 400, Map.of("error", "No private key found for matching certificate"));
            return;
          }

          // Normalize line endings to \n so signing is consistent (Windows CRLF vs Unix
          // LF).
          String originalText = new String(data, java.nio.charset.StandardCharsets.UTF_8);
          String normalizedText = originalText.replace("\r\n", "\n").replace("\r", "\n");
          // Sign exactly the bytes that will appear before <START-SIGNATURE> in the
          // output file.
          // If trustsign.signContentWithoutTrailingNewline=true, sign without the
          // trailing newline (for verifiers that strip it).
          byte[] contentToSign;
          if (Boolean.getBoolean("trustsign.signContentWithoutTrailingNewline")) {
            String contentForSigning = normalizedText.endsWith("\n")
                ? normalizedText.substring(0, normalizedText.length() - 1)
                : normalizedText;
            contentToSign = contentForSigning.getBytes(java.nio.charset.StandardCharsets.UTF_8);
          } else {
            byte[] normBytes = normalizedText.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            contentToSign = normalizedText.endsWith("\n") ? normBytes
                : java.util.Arrays.copyOf(normBytes, normBytes.length + 1);
            if (!normalizedText.endsWith("\n"))
              contentToSign[normBytes.length] = '\n';
          }
          // SHA256withRSA only (Bouncy Castle / PKCS#11).
          byte[] sigBytes = TextSignerService.signRawSha256WithRsa(contentToSign, key, loaded.provider());

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
              ? cfg.signerVersion()
              : "TrustSign";

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
              java.nio.charset.StandardCharsets.UTF_8);

          writeJson(resp, 200, Map.of(
              "ok", true,
              "subjectDn", signingCert != null ? signingCert.getSubjectX500Principal().getName() : "",
              "serialNumber", signingCert != null ? signingCert.getSerialNumber().toString(16) : "",
              "outputPath", outFile.getAbsolutePath()));
          return;
        }

        case "/auto-sign-pdf" -> {
          var mp = Multipart.read(req, multipartPdfMaxBytes);
          byte[] data = mp.file("file");
          String reason = mp.field("reason");
          String location = mp.field("location");
          // Some clients send text fields as "file" parts with filename present/empty.
          // Fall back to interpreting them as text when mp.field(...) is null.
          if (reason == null) {
            byte[] rb = mp.file("reason");
            if (rb != null && rb.length > 0) {
              reason = new String(rb, java.nio.charset.StandardCharsets.UTF_8).trim();
            }
          }
          if (location == null) {
            byte[] lb = mp.file("location");
            if (lb != null && lb.length > 0) {
              location = new String(lb, java.nio.charset.StandardCharsets.UTF_8).trim();
            }
          }

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing PDF file field: file"));
            return;
          }
          if (!isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400, Map.of("error", "Uploaded file is not a PDF"));
            return;
          }

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;

          java.util.List<Integer> stampPages = resolvePdfStampPages(mp);
          boolean finalVersion = parseFinalVersionMultipart(mp);
          PdfSigningOptions pdfOpts = new PdfSigningOptions(finalVersion);

          String outputDir = cfg.autoSignOutputDir();
          if (outputDir == null || outputDir.isBlank()) {
            writeJson(resp, 500,
                Map.of("error", "Configuration error", "details", "autoSignOutputDir is not configured"));
            return;
          }

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
                "details", detail));
            return;
          }

          KeyStore ks = loaded.keyStore();

          java.util.List<PublicKey> requestedPublicKeys;
          try {
            requestedPublicKeys = loadConfiguredPublicKeysOrThrow();
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to load configured public key(s)", "details", safeMsg(e)));
            return;
          }

          CertificateSelection selection;
          try {
            selection = selectCertificateForPublicKeys(ks, requestedPublicKeys);
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to select certificate from token", "details", safeMsg(e)));
            return;
          }

          if (selection == null || selection.chain == null || selection.chain.length == 0) {
            writeJson(resp, 400, Map.of("error", "No certificate on token matches any configured public key"));
            return;
          }

          String matchedAlias = selection.alias;
          X509Certificate matchedCert = selection.certificate;
          Certificate[] chain = selection.chain;

          PrivateKey key = (PrivateKey) ks.getKey(matchedAlias, pin);
          if (key == null) {
            writeJson(resp, 400, Map.of("error", "No private key found for matching certificate"));
            return;
          }

          X509Certificate signingCert = matchedCert;
          X509Certificate[] x509Chain = null;
          if (chain[0] instanceof X509Certificate) {
            x509Chain = java.util.Arrays.stream(chain)
                .filter(c -> c instanceof X509Certificate)
                .map(c -> (X509Certificate) c)
                .toArray(X509Certificate[]::new);
          }
          CertificateValidator.validateForSigning(signingCert, x509Chain);

          String inputFilename = mp.filename("file");
          if (inputFilename == null || inputFilename.isBlank()) {
            inputFilename = "document.pdf";
          }
          File outFile = resolveNextAutoSignPdfOutput(outDirFile, inputFilename);
          byte[] pdfToSign = resolveAutoSignIncrementalInput(data, outFile, mp);

          byte[] signedPdf = PdfSignerService.signPdf(
              pdfToSign,
              key,
              chain,
              loaded.provider(),
              signingCert,
              reason,
              location,
              stampPages,
              pdfOpts);

          outDirFile.mkdirs();
          Files.write(outFile.toPath(), signedPdf);

          Map<String, Object> autoPdfBody = new LinkedHashMap<>();
          autoPdfBody.put("ok", true);
          autoPdfBody.put("format", "pdf");
          autoPdfBody.put("subjectDn", signingCert.getSubjectX500Principal().getName());
          autoPdfBody.put("serialNumber", signingCert.getSerialNumber().toString(16));
          autoPdfBody.put("outputPath", outFile.getAbsolutePath());
          autoPdfBody.put("chainedFromExistingOutput", pdfToSign != data);
          autoPdfBody.put("stampedPages", stampPages);
          autoPdfBody.put("finalVersion", finalVersion);
          writeJson(resp, 200, autoPdfBody);
          return;
        }

        case "/auto-sign-text-cms" -> {
          requireSession(req);
          var mp = Multipart.read(req, multipartTextMaxBytes);
          byte[] data = mp.file("file");
          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing text file field: file"));
            return;
          }
          if (isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400, Map.of("error", "PDF is not allowed on /auto-sign-text-cms. Use /sign-pdf or /auto-sign-pdf."));
            return;
          }
          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;

          String outputDir = cfg.autoSignOutputDir();
          if (outputDir == null || outputDir.isBlank()) {
            writeJson(resp, 500,
                Map.of("error", "Configuration error", "details", "autoSignOutputDir is not configured"));
            return;
          }

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
            writeJson(resp, 400, Map.of("error", "Token load failed", "details", detail));
            return;
          }
          KeyStore ks = loaded.keyStore();
          java.util.List<PublicKey> requestedPublicKeys;
          try {
            requestedPublicKeys = loadConfiguredPublicKeysOrThrow();
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to load configured public key(s)", "details", safeMsg(e)));
            return;
          }
          CertificateSelection selection;
          try {
            selection = selectCertificateForPublicKeys(ks, requestedPublicKeys);
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to select certificate from token", "details", safeMsg(e)));
            return;
          }
          if (selection == null || selection.chain == null || selection.chain.length == 0) {
            writeJson(resp, 400, Map.of("error", "No certificate on token matches any configured public key"));
            return;
          }
          String matchedAlias = selection.alias;
          X509Certificate matchedCert = selection.certificate;
          Certificate[] chain = selection.chain;
          PrivateKey key = (PrivateKey) ks.getKey(matchedAlias, pin);
          if (key == null) {
            writeJson(resp, 400, Map.of("error", "No private key found for matching certificate"));
            return;
          }
          String originalText = new String(data, StandardCharsets.UTF_8);
          String normalizedText = originalText.replace("\r\n", "\n").replace("\r", "\n");
          byte[] contentToSign = normalizedText.endsWith("\n")
              ? normalizedText.getBytes(StandardCharsets.UTF_8)
              : java.util.Arrays.copyOf(normalizedText.getBytes(StandardCharsets.UTF_8),
                  normalizedText.getBytes(StandardCharsets.UTF_8).length + 1);
          if (!normalizedText.endsWith("\n"))
            contentToSign[normalizedText.getBytes(StandardCharsets.UTF_8).length] = '\n';
          byte[] cmsBytes = TextSignerService.signDetached(contentToSign, key, chain, loaded.provider());
          String cmsB64 = Base64.getEncoder().encodeToString(cmsBytes);
          X509Certificate signingCert = matchedCert;
          X509Certificate[] x509Chain = chain != null && chain.length > 0 && chain[0] instanceof X509Certificate
              ? java.util.Arrays.stream(chain).filter(c -> c instanceof X509Certificate).map(c -> (X509Certificate) c)
                  .toArray(X509Certificate[]::new)
              : null;
          CertificateValidator.validateForSigning(signingCert, x509Chain);
          StringBuilder sb = new StringBuilder();
          sb.append(normalizedText);
          if (!normalizedText.endsWith("\n"))
            sb.append("\n");
          sb.append("<START-CMS-SIGNATURE>").append(cmsB64).append("</START-CMS-SIGNATURE>\n");
          String inputFilename = mp.filename("file");
          if (inputFilename == null || inputFilename.isBlank())
            inputFilename = "text.txt";
          outDirFile.mkdirs();
          String baseName = inputFilename;
          String ext = "";
          int dot = inputFilename.lastIndexOf('.');
          if (dot > 0 && dot < inputFilename.length() - 1) {
            baseName = inputFilename.substring(0, dot);
            ext = inputFilename.substring(dot);
          }
          File outFile = new File(outDirFile, baseName + "-cms-signed" + ext);
          java.nio.file.Files.writeString(outFile.toPath(), sb.toString(), StandardCharsets.UTF_8);
          writeJson(resp, 200, Map.of(
              "ok", true,
              "subjectDn", signingCert.getSubjectX500Principal().getName(),
              "serialNumber", signingCert.getSerialNumber().toString(16),
              "outputPath", outFile.getAbsolutePath()));
          return;
        }

        case "/sign-pdf" -> {
          // requireSession(req);
          var mp = Multipart.read(req, multipartPdfMaxBytes);
          byte[] data = mp.file("file");
          String reason = mp.field("reason");
          String location = mp.field("location");
          if (reason == null) {
            byte[] rb = mp.file("reason");
            if (rb != null && rb.length > 0) {
              reason = new String(rb, java.nio.charset.StandardCharsets.UTF_8).trim();
            }
          }
          if (location == null) {
            byte[] lb = mp.file("location");
            if (lb != null && lb.length > 0) {
              location = new String(lb, java.nio.charset.StandardCharsets.UTF_8).trim();
            }
          }

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing PDF file field: file"));
            return;
          }
          if (!isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400, Map.of("error", "Uploaded file is not a PDF"));
            return;
          }

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;

          java.util.List<Integer> stampPages = resolvePdfStampPages(mp);
          boolean finalVersion = parseFinalVersionMultipart(mp);
          PdfSigningOptions pdfOpts = new PdfSigningOptions(finalVersion);

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
            writeJson(resp, 400, Map.of("error", "Token load failed", "details", detail));
            return;
          }

          KeyStore ks = loaded.keyStore();
          java.util.List<PublicKey> requestedPublicKeys;
          try {
            requestedPublicKeys = loadConfiguredPublicKeysOrThrow();
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to load configured public key(s)", "details", safeMsg(e)));
            return;
          }
          CertificateSelection selection;
          try {
            selection = selectCertificateForPublicKeys(ks, requestedPublicKeys);
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to select certificate from token", "details", safeMsg(e)));
            return;
          }
          if (selection == null || selection.chain == null || selection.chain.length == 0) {
            writeJson(resp, 400, Map.of("error", "No certificate on token matches any configured public key"));
            return;
          }

          String matchedAlias = selection.alias;
          X509Certificate matchedCert = selection.certificate;
          Certificate[] chain = selection.chain;
          PrivateKey key = (PrivateKey) ks.getKey(matchedAlias, pin);
          if (key == null) {
            writeJson(resp, 400, Map.of("error", "No private key found for matching certificate"));
            return;
          }

          X509Certificate signingCert = matchedCert;
          X509Certificate[] x509Chain = chain != null && chain.length > 0 && chain[0] instanceof X509Certificate
              ? java.util.Arrays.stream(chain).filter(c -> c instanceof X509Certificate).map(c -> (X509Certificate) c)
                  .toArray(X509Certificate[]::new)
              : null;
          CertificateValidator.validateForSigning(signingCert, x509Chain);
          byte[] signedPdf = PdfSignerService.signPdf(
              data,
              key,
              chain,
              loaded.provider(),
              signingCert,
              reason,
              location,
              stampPages,
              pdfOpts);

          resp.setStatus(200);
          resp.setContentType("application/pdf");
          resp.setHeader("X-Stamped-Pages", String.valueOf(stampPages));
          resp.setHeader("Content-Disposition",
              "attachment; filename=\"" + buildSignedPdfFilename(mp.filename("file")) + "\"");
          resp.setHeader("X-Signer-SubjectDN", signingCert.getSubjectX500Principal().getName());
          resp.setHeader("X-Signer-SerialNumber", signingCert.getSerialNumber().toString(16));
          if (finalVersion) {
            resp.setHeader("X-TrustSign-Final-Version", "true");
          }
          resp.getOutputStream().write(signedPdf);
          return;
        }

        case "/hsm/sign-pdf" -> {
          var mp = Multipart.read(req, multipartPdfMaxBytes);
          byte[] data = mp.file("file");
          byte[] cerBytes = readMultipartCerPayload(mp);
          String pinStr = readMultipartString(mp, "pin", true);
          String reason = mp.field("reason");
          String location = mp.field("location");
          if (reason == null) {
            byte[] rb = mp.file("reason");
            if (rb != null && rb.length > 0) {
              reason = new String(rb, StandardCharsets.UTF_8).trim();
            }
          }
          if (location == null) {
            byte[] lb = mp.file("location");
            if (lb != null && lb.length > 0) {
              location = new String(lb, StandardCharsets.UTF_8).trim();
            }
          }

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing PDF file field: file"));
            return;
          }
          if (!isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400, Map.of("error", "Uploaded file is not a PDF"));
            return;
          }
          if (cerBytes == null || cerBytes.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing cer field (signer .cer as file or PEM text)"));
            return;
          }
          if (pinStr == null || pinStr.isBlank()) {
            writeJson(resp, 400, Map.of("error", "Missing pin field (HSM token PIN)"));
            return;
          }

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;

          java.util.List<Integer> stampPages = resolvePdfStampPages(mp);
          boolean finalVersion = parseFinalVersionMultipart(mp);
          PdfSigningOptions pdfOpts = new PdfSigningOptions(finalVersion);

          if (cfg.hsm() == null) {
            writeJson(resp, 500,
                Map.of("error", "Configuration error", "details", "config.hsm is not configured (see config.json)"));
            return;
          }
          List<String> libs = OsPkcs11Resolver.hsmCandidates(cfg.hsm());
          if (libs.isEmpty()) {
            writeJson(resp, 400, Map.of("error", "No PKCS#11 libraries configured under config.hsm for this OS"));
            return;
          }

          char[] pinChars = pinStr.toCharArray();
          HsmPdfSignerService.SignResult hsmResult = null;
          try {
            hsmResult = HsmPdfSignerService.signPdfWithMetadata(
                data,
                pinChars,
                cerBytes,
                libs,
                HsmPkcs11ConfigurationService.normalizeSlotProbeCount(
                    cfg.hsm().slotProbeCount() != null ? cfg.hsm().slotProbeCount() : 0),
                reason,
                location,
                stampPages,
                pdfOpts);
          } catch (RuntimeException e) {
            String detail = buildTokenErrorDetail(e);
            writeJson(resp, 400, Map.of("error", "HSM token load or signing failed", "details", detail));
            return;
          } catch (Exception e) {
            LOG.warning("/hsm/sign-pdf: " + e.getMessage());
            writeJson(resp, 400, Map.of("error", "HSM PDF signing failed", "details", safeMsg(e)));
            return;
          } finally {
            java.util.Arrays.fill(pinChars, '\0');
          }

          X509Certificate signingCert = hsmResult.signingCertificate();
          byte[] signedPdf = hsmResult.signedPdf();
          resp.setStatus(200);
          resp.setContentType("application/pdf");
          resp.setHeader("X-Stamped-Pages", String.valueOf(stampPages));
          resp.setHeader("Content-Disposition",
              "attachment; filename=\"" + buildSignedPdfFilename(mp.filename("file")) + "\"");
          resp.setHeader("X-Signer-SubjectDN", signingCert.getSubjectX500Principal().getName());
          resp.setHeader("X-Signer-SerialNumber", signingCert.getSerialNumber().toString(16));
          if (finalVersion) {
            resp.setHeader("X-TrustSign-Final-Version", "true");
          }
          resp.getOutputStream().write(signedPdf);
          return;
        }

        case "/hsm/auto-sign-pdf" -> {
          var mp = Multipart.read(req, multipartPdfMaxBytes);
          byte[] data = mp.file("file");
          byte[] cerBytes = readMultipartCerPayload(mp);
          String pinStr = readMultipartString(mp, "pin", true);
          String reason = mp.field("reason");
          String location = mp.field("location");
          if (reason == null) {
            byte[] rb = mp.file("reason");
            if (rb != null && rb.length > 0) {
              reason = new String(rb, StandardCharsets.UTF_8).trim();
            }
          }
          if (location == null) {
            byte[] lb = mp.file("location");
            if (lb != null && lb.length > 0) {
              location = new String(lb, StandardCharsets.UTF_8).trim();
            }
          }

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing PDF file field: file"));
            return;
          }
          if (!isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400, Map.of("error", "Uploaded file is not a PDF"));
            return;
          }
          if (cerBytes == null || cerBytes.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing cer field (signer .cer as file or PEM text)"));
            return;
          }
          if (pinStr == null || pinStr.isBlank()) {
            writeJson(resp, 400, Map.of("error", "Missing pin field (HSM token PIN)"));
            return;
          }

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;

          java.util.List<Integer> stampPages = resolvePdfStampPages(mp);
          boolean finalVersion = parseFinalVersionMultipart(mp);
          PdfSigningOptions pdfOpts = new PdfSigningOptions(finalVersion);

          if (cfg.hsm() == null) {
            writeJson(resp, 500,
                Map.of("error", "Configuration error", "details", "config.hsm is not configured (see config.json)"));
            return;
          }
          String outputDir = cfg.autoSignOutputDir();
          if (outputDir == null || outputDir.isBlank()) {
            writeJson(resp, 500,
                Map.of("error", "Configuration error", "details", "autoSignOutputDir is not configured"));
            return;
          }
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
          List<String> libs = OsPkcs11Resolver.hsmCandidates(cfg.hsm());
          if (libs.isEmpty()) {
            writeJson(resp, 400, Map.of("error", "No PKCS#11 libraries configured under config.hsm for this OS"));
            return;
          }

          String inputFilename = mp.filename("file");
          if (inputFilename == null || inputFilename.isBlank()) {
            inputFilename = "document.pdf";
          }
          File outFile = resolveNextAutoSignPdfOutput(outDirFile, inputFilename);
          byte[] pdfToSign = resolveAutoSignIncrementalInput(data, outFile, mp);

          char[] pinChars = pinStr.toCharArray();
          HsmPdfSignerService.SignResult hsmResult = null;
          try {
            hsmResult = HsmPdfSignerService.signPdfWithMetadata(
                pdfToSign,
                pinChars,
                cerBytes,
                libs,
                HsmPkcs11ConfigurationService.normalizeSlotProbeCount(
                    cfg.hsm().slotProbeCount() != null ? cfg.hsm().slotProbeCount() : 0),
                reason,
                location,
                stampPages,
                pdfOpts);
          } catch (RuntimeException e) {
            String detail = buildTokenErrorDetail(e);
            writeJson(resp, 400, Map.of("error", "HSM token load or signing failed", "details", detail));
            return;
          } catch (Exception e) {
            LOG.warning("/hsm/auto-sign-pdf: " + e.getMessage());
            writeJson(resp, 400, Map.of("error", "HSM PDF signing failed", "details", safeMsg(e)));
            return;
          } finally {
            java.util.Arrays.fill(pinChars, '\0');
          }

          byte[] signedPdf = hsmResult.signedPdf();
          X509Certificate signingCert = hsmResult.signingCertificate();

          outDirFile.mkdirs();
          Files.write(outFile.toPath(), signedPdf);

          Map<String, Object> hsmAutoBody = new LinkedHashMap<>();
          hsmAutoBody.put("ok", true);
          hsmAutoBody.put("format", "pdf");
          hsmAutoBody.put("subjectDn", signingCert.getSubjectX500Principal().getName());
          hsmAutoBody.put("serialNumber", signingCert.getSerialNumber().toString(16));
          hsmAutoBody.put("outputPath", outFile.getAbsolutePath());
          hsmAutoBody.put("chainedFromExistingOutput", pdfToSign != data);
          hsmAutoBody.put("stampedPages", stampPages);
          hsmAutoBody.put("finalVersion", finalVersion);
          writeJson(resp, 200, hsmAutoBody);
          return;
        }

        case "/verify-pdf" -> {
          var mp = Multipart.read(req, multipartPdfMaxBytes);
          byte[] data = mp.file("file");
          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("ok", false, "reason", "Missing PDF file field: file"));
            return;
          }
          if (!isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400, Map.of("ok", false, "reason", "Uploaded file is not a PDF"));
            return;
          }
          PdfVerifyService.Result result = PdfVerifyService.verify(data);
          writeJson(resp, result.ok() ? 200 : 422, result);
          return;
        }

        case "/sign-text" -> {
          requireSession(req);

          var mp = Multipart.read(req, multipartTextMaxBytes);
          byte[] data = mp.file("file");
          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing text file field: file"));
            return;
          }
          if (isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400, Map.of("error", "PDF is not allowed on /sign-text. Use /sign-pdf."));
            return;
          }

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;
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
            writeJson(resp, 400, Map.of("error", "Token load failed", "details", detail));
            return;
          }

          KeyStore ks = loaded.keyStore();
          java.util.List<PublicKey> requestedPublicKeys;
          try {
            requestedPublicKeys = loadConfiguredPublicKeysOrThrow();
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to load configured public key(s)", "details", safeMsg(e)));
            return;
          }

          CertificateSelection selection;
          try {
            selection = selectCertificateForPublicKeys(ks, requestedPublicKeys);
          } catch (Exception e) {
            writeJson(resp, 500, Map.of("error", "Failed to select certificate from token", "details", safeMsg(e)));
            return;
          }

          if (selection == null || selection.chain == null || selection.chain.length == 0) {
            writeJson(resp, 400, Map.of("error", "No certificate on token matches any configured public key"));
            return;
          }

          String matchedAlias = selection.alias;
          X509Certificate matchedCert = selection.certificate;
          Certificate[] chain = selection.chain;

          PrivateKey key = (PrivateKey) ks.getKey(matchedAlias, pin);
          if (key == null) {
            writeJson(resp, 400, Map.of("error", "No private key found for matching certificate"));
            return;
          }

          // Same signing logic as /auto-sign-text: normalize line endings, sign content
          // that appears before <START-SIGNATURE>.
          String originalText = new String(data, StandardCharsets.UTF_8);
          String normalizedText = originalText.replace("\r\n", "\n").replace("\r", "\n");
          byte[] contentToSign;
          if (Boolean.getBoolean("trustsign.signContentWithoutTrailingNewline")) {
            String contentForSigning = normalizedText.endsWith("\n")
                ? normalizedText.substring(0, normalizedText.length() - 1)
                : normalizedText;
            contentToSign = contentForSigning.getBytes(StandardCharsets.UTF_8);
          } else {
            byte[] normBytes = normalizedText.getBytes(StandardCharsets.UTF_8);
            contentToSign = normalizedText.endsWith("\n") ? normBytes
                : java.util.Arrays.copyOf(normBytes, normBytes.length + 1);
            if (!normalizedText.endsWith("\n"))
              contentToSign[normBytes.length] = '\n';
          }
          byte[] sigBytes = TextSignerService.signRawSha256WithRsa(contentToSign, key, loaded.provider());
          String sigB64 = Base64.getEncoder().encodeToString(sigBytes);

          X509Certificate signingCert = matchedCert;
          X509Certificate[] x509Chain = chain != null && chain.length > 0 && chain[0] instanceof X509Certificate
              ? java.util.Arrays.stream(chain).filter(c -> c instanceof X509Certificate).map(c -> (X509Certificate) c)
                  .toArray(X509Certificate[]::new)
              : null;
          CertificateValidator.validateForSigning(signingCert, x509Chain);
          String certB64 = Base64.getEncoder().encodeToString(signingCert.getEncoded());

          String signerVersion = (cfg.signerVersion() != null && !cfg.signerVersion().isBlank())
              ? cfg.signerVersion()
              : "TrustSign";

          StringBuilder sb = new StringBuilder();
          sb.append(normalizedText);
          if (!normalizedText.endsWith("\n"))
            sb.append("\n");
          sb.append("<START-SIGNATURE>").append(sigB64).append("</START-SIGNATURE>\n");
          sb.append("<START-CERTIFICATE>").append(certB64).append("</START-CERTIFICATE>\n");
          sb.append("<SIGNER-VERSION>").append(signerVersion).append("</SIGNER-VERSION>\n");

          resp.setStatus(200);
          resp.setContentType("text/plain; charset=UTF-8");
          resp.setHeader("Content-Disposition",
              "attachment; filename=\"" + sanitizeFilename(mp.filename("file")) + "\"");
          resp.setHeader("X-Signer-SubjectDN", signingCert.getSubjectX500Principal().getName());
          resp.setHeader("X-Signer-SerialNumber", signingCert.getSerialNumber().toString(16));
          resp.getOutputStream().write(sb.toString().getBytes(StandardCharsets.UTF_8));
          return;
        }

        // ── /verify-text
        // ──────────────────────────────────────────────────────────
        // Accepts only ONE file: file
        // Returns: ok, reason, and full certificate details
        case "/verify-text" -> {
          var mp = Multipart.read(req, multipartMediumMaxBytes);

          byte[] signedFileBytes = mp.file("file");

          if (signedFileBytes == null || signedFileBytes.length == 0) {
            writeJson(resp, 400, Map.of(
                "ok", false,
                "reason", "Missing file field: file"));
            return;
          }

          TextVerifyService.Result result = TextVerifyService.verify(signedFileBytes);

          // Build response — always include cert details if available
          var body = new java.util.LinkedHashMap<String, Object>();
          body.put("ok", result.ok());
          body.put("reason", result.reason());

          if (result.certificate() != null) {
            var cert = result.certificate();
            var certMap = new java.util.LinkedHashMap<String, Object>();
            certMap.put("subject", cert.subject());
            certMap.put("issuer", cert.issuer());
            certMap.put("serialNumber", cert.serialNumber());
            certMap.put("validFrom", cert.validFrom());
            certMap.put("validTo", cert.validTo());
            certMap.put("algorithm", cert.algorithm());
            if (cert.email() != null) {
              certMap.put("email", cert.email());
            }
            body.put("certificate", certMap);
          }

          writeJson(resp, result.ok() ? 200 : 422, body);
        }

        // ── /debug-bytes — REMOVE BEFORE PRODUCTION
        // ───────────────────────────────────
        case "/debug-bytes" -> {
          var mp = Multipart.read(req, multipartMediumMaxBytes);

          byte[] signedFileBytes = mp.file("signedFile");

          if (signedFileBytes == null || signedFileBytes.length == 0) {
            writeJson(resp, 400, Map.of(
                "ok", false,
                "reason", "Missing file field: signedFile"));
            return;
          }

          writeJson(resp, 200, TextVerifyService.debugBytes(signedFileBytes));
        }

        case "/analyze-signed-file" -> {
          var mp = Multipart.read(req, multipartTextMaxBytes);
          byte[] data = mp.file("file");
          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing file field: file"));
            return;
          }
          String signedText = new String(data, StandardCharsets.UTF_8);
          int cmsStart = signedText.indexOf("<START-CMS-SIGNATURE>");
          int rawStart = signedText.indexOf("<START-SIGNATURE>");
          int contentEnd = cmsStart >= 0 ? cmsStart : (rawStart >= 0 ? rawStart : 0);
          byte[] rawBeforeSig = contentEnd > 0 ? Arrays.copyOf(data, contentEnd) : new byte[0];
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
    if (pathInfo == null || pathInfo.isBlank())
      return "";
    return pathInfo.startsWith("/") ? pathInfo : "/" + pathInfo;
  }

  /**
   * On Windows, searches common locations for PKCS#11 DLLs (pkcs11.dll or
   * *pkcs*.dll / *p11*.dll)
   * so the user can set preferredLibrary if the driver is installed in a
   * non-standard path.
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
      if (rootStr == null || rootStr.isBlank())
        continue;
      Path root = Paths.get(rootStr);
      if (!Files.isDirectory(root))
        continue;

      if (rootStr.contains("System32") || rootStr.contains("SysWOW64")) {
        addDllsInDir(root, seen, out);
        continue;
      }

      int count = 0;
      try (var stream = Files.list(root)) {
        for (Path dir : stream.toList()) {
          if (count >= 100)
            break;
          if (!Files.isDirectory(dir))
            continue;
          count++;
          for (String rel : new String[] { "", "bin/", "x64/", "x86/" }) {
            Path base = rel.isEmpty() ? dir : dir.resolve(rel);
            if (!Files.isDirectory(base) && !rel.isEmpty())
              continue;
            if (rel.isEmpty() && !Files.isDirectory(base))
              continue;
            addDllsInDir(base, seen, out);
          }
        }

      } catch (Exception ignore) {
      }
    }
    return out;
  }

  private static void addDllsInDir(Path dir, java.util.Set<String> seen, List<Map<String, Object>> out) {
    try (var stream = Files.list(dir)) {
      for (Path p : stream.toList()) {
        if (!Files.isRegularFile(p))
          continue;
        String name = p.getFileName().toString().toLowerCase();
        if (!name.endsWith(".dll"))
          continue;
        if (name.contains("pkcs") || name.contains("p11") || name.equals("pkcs11.dll")) {
          String path = p.toAbsolutePath().toString();
          if (seen.add(path)) {
            out.add(Map.of("path", path, "exists", true));
          }
        }
      }

    } catch (Exception ignore) {
    }
  }

  private void writeJson(HttpServletResponse resp, int status, Object body) throws IOException {
    resp.setStatus(status);
    resp.setContentType("application/json");
    Json.MAPPER.writeValue(resp.getOutputStream(), body);
  }

  /**
   * Loads one or more signer public keys from a configured location on disk.
   *
   * Resolution order: trustsign.publicKey.path, config/public-key.pem,
   * ../config/public-key.pem.
   * The target file may contain:
   * - a single PEM encoded public key ("-----BEGIN PUBLIC KEY-----")
   * - one or more PEM encoded X.509 certificates ("-----BEGIN CERTIFICATE-----")
   * - a mix of the above
   * - or a single raw base64-encoded DER SubjectPublicKeyInfo.
   */
  private static java.util.List<PublicKey> loadConfiguredPublicKeysOrThrow() throws Exception {
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

          throw new IOException(
              "No configured public key file found (checked config/public-key.pem and ../config/public-key.pem)");
        }
      }
    }
    String pem = java.nio.file.Files.readString(
        java.nio.file.Paths.get(path), java.nio.charset.StandardCharsets.UTF_8);
    java.util.List<PublicKey> keys = parsePublicKeys(pem);
    if (keys.isEmpty()) {
      throw new IOException("Configured public key file did not contain any usable public keys");
    }
    return keys;
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
      java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf
          .generateCertificate(new java.io.ByteArrayInputStream(certDer));
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
   * Parses one or more public keys from the given input.
   * Supports multiple PEM blocks (certificates and/or public keys) in a single
   * file
   * as well as a single base64-encoded public key without PEM headers.
   */
  private static java.util.List<PublicKey> parsePublicKeys(String pemOrBase64) throws Exception {
    String trimmed = pemOrBase64 == null ? "" : pemOrBase64.trim();
    java.util.List<PublicKey> keys = new java.util.ArrayList<>();
    if (trimmed.isEmpty()) {
      return keys;
    }

    String upper = trimmed.toUpperCase(java.util.Locale.ROOT);
    boolean hasPemMarkers = upper.contains("-----BEGIN CERTIFICATE-----")
        || upper.contains("-----BEGIN PUBLIC KEY-----");

    if (!hasPemMarkers) {
      // Single non-PEM base64-encoded key.
      keys.add(parsePublicKey(trimmed));
      return keys;
    }

    int pos = 0;
    while (pos < trimmed.length()) {
      int nextCert = upper.indexOf("-----BEGIN CERTIFICATE-----", pos);
      int nextPub = upper.indexOf("-----BEGIN PUBLIC KEY-----", pos);
      if (nextCert == -1 && nextPub == -1) {
        break;
      }

      boolean isCert;
      int begin;
      if (nextCert == -1) {
        begin = nextPub;
        isCert = false;
      } else if (nextPub == -1 || nextCert < nextPub) {
        begin = nextCert;
        isCert = true;
      } else {
        begin = nextPub;
        isCert = false;
      }

      String endMarker = isCert ? "-----END CERTIFICATE-----" : "-----END PUBLIC KEY-----";
      int end = upper.indexOf(endMarker, begin);
      if (end == -1) {
        break; // malformed block, stop processing further
      }
      end += endMarker.length();

      String block = trimmed.substring(begin, end);
      try {
        PublicKey pk = parsePublicKey(block);
        if (pk != null) {
          keys.add(pk);
        }
      } catch (Exception ignore) {
        // Ignore malformed block and continue with the next one.
      }

      pos = end;
    }

    return keys;
  }

  /**
   * Represents a selected certificate (and its chain) from the token.
   */
  private static final class CertificateSelection {
    final String alias;
    final X509Certificate certificate;
    final Certificate[] chain;

    CertificateSelection(String alias, X509Certificate certificate, Certificate[] chain) {
      this.alias = alias;
      this.certificate = certificate;
      this.chain = chain;
    }
  }

  /**
   * Selects the first certificate on the token whose public key matches any of
   * the
   * configured public keys. Returns null if no matching certificate is found.
   */
  private static CertificateSelection selectCertificateForPublicKeys(
      KeyStore ks,
      java.util.List<PublicKey> requestedPublicKeys) throws Exception {
    if (requestedPublicKeys == null || requestedPublicKeys.isEmpty()) {
      throw new IllegalArgumentException("No configured public keys");
    }

    for (java.util.Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
      String alias = e.nextElement();
      Certificate cert = ks.getCertificate(alias);
      if (cert instanceof X509Certificate x509) {
        PublicKey certKey = x509.getPublicKey();
        for (PublicKey requested : requestedPublicKeys) {
          if (certKey.equals(requested)) {
            Certificate[] chain = ks.getCertificateChain(alias);
            return new CertificateSelection(alias, x509, chain);
          }
        }
      }
    }

    return null;
  }

  /**
   * Resolves the token PIN from: 1) env TRUSTSIGN_TOKEN_PIN, 2) config
   * pkcs11.pin.
   * Client can set either in config.json ("pkcs11": { "pin": "their-pin" }) or
   * via environment variable.
   */
  private char[] resolvePin(AgentConfig cfg) {
    String envPin = System.getenv("TRUSTSIGN_TOKEN_PIN");
    if (envPin != null && !envPin.isBlank()) {
      return envPin.toCharArray();
    }

    String cfgPin = (cfg.pkcs11() != null && cfg.pkcs11().pin() != null) ? cfg.pkcs11().pin() : null;
    if (cfgPin == null || cfgPin.isBlank()) {
      throw new SecurityException(
          "Token PIN not configured. Set it in config.json (pkcs11.pin) or set environment variable TRUSTSIGN_TOKEN_PIN.");
    }

    String trimmed = cfgPin.trim();
    if (trimmed.isEmpty()) {
      throw new SecurityException(
          "Token PIN is empty. Check config.json (pkcs11.pin) or set environment variable TRUSTSIGN_TOKEN_PIN.");
    }

    return trimmed.toCharArray();
  }

  private File resolveConfigFile() {
    File f1 = new File("config/config.json");
    if (f1.exists())
      return f1;
    File f2 = new File("../config/config.json");
    if (f2.exists())
      return f2;
    return f1;
  }

  private static List<String> resolvePkcs11Libraries(AgentConfig cfg) throws IOException {
    if (cfg.pkcs11() == null)
      return List.of();
    return OsPkcs11Resolver.candidates(cfg);
  }

  private String safeMsg(Exception e) {
    String msg = e.getMessage();
    if (msg == null || msg.isBlank())
      return e.getClass().getSimpleName();
    if (msg.length() > 300)
      return msg.substring(0, 300);
    return msg;
  }

  private static String buildTokenErrorDetail(RuntimeException e) {
    Throwable root = e;

    while (root.getCause() != null)
      root = root.getCause();
    String causeMsg = root.getMessage();
    if (causeMsg != null && !causeMsg.isBlank()) {
      String out = causeMsg.length() > 400 ? causeMsg.substring(0, 400) : causeMsg;
      if (root != e)
        return out + " (from " + root.getClass().getSimpleName() + ")";
      return out;
    }
    String topMsg = e.getMessage();
    if (topMsg != null && !topMsg.isBlank())
      return topMsg;
    return "Connect your PKCS#11 token, check the library path and PIN, and try again.";
  }
}
