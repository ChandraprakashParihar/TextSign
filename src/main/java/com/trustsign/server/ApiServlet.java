package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.AgentConfig.ServerConfig;
import com.trustsign.core.ConfigLoader;
import com.trustsign.core.HsmPdfSignerService;
import com.trustsign.core.PdfSignerService;
import com.trustsign.core.PdfSignerService.PdfSigningOptions;
import com.trustsign.core.PdfSignerService.DocMdpNoChangesLockException;
import com.trustsign.core.PdfSignerService.SignaturePlacement;
import com.trustsign.core.PdfSignerService.CoordinateOverflowMode;
import com.trustsign.core.PdfSignerService.CoordinateOrigin;
import com.trustsign.core.PdfVerifyService;
import com.trustsign.core.Pkcs11Token;
import com.trustsign.core.OsPkcs11Resolver;
import com.trustsign.core.SessionManager;
import com.trustsign.core.SignedPdfOutputPaths;
import com.trustsign.core.SignedFileAnalyzer;
import com.trustsign.core.LtvEnabler;
import com.trustsign.core.PdfLtvInspector;
import com.trustsign.core.TsaClient;
import com.trustsign.core.TextSignerService;
import com.trustsign.core.TextVerifyService;
import com.trustsign.core.CertificateValidator;
import com.trustsign.core.LicenceEnforcer;
import com.trustsign.hsm.HsmPkcs11ConfigurationService;
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
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.regex.Pattern;

public final class ApiServlet {
  private static final Logger LOG = LoggerFactory.getLogger(ApiServlet.class);
  private static final Pattern SAFE_FILENAME = Pattern.compile("[^a-zA-Z0-9._-]");

  private final SessionManager sessions;
  private final LicenceEnforcer licenceEnforcer;
  private final SigningConcurrencyGate signingGate;
  private final int multipartPdfMaxBytes;
  private final int multipartTextMaxBytes;
  /** Former 5 MiB cap for verify-text / debug; bounded by PDF limit. */
  private final int multipartMediumMaxBytes;
  private final boolean debugEndpointsEnabled;
  private final boolean exposeErrorDetails;
  private final int sessionIssueRateLimitPerMinute;
  private final ConcurrentHashMap<String, SessionIssueWindow> sessionIssueWindows = new ConcurrentHashMap<>();

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
    this.debugEndpointsEnabled = ServerConfig.enableDebugEndpointsOrDefault(serverLimits);
    this.exposeErrorDetails = this.debugEndpointsEnabled || Boolean.getBoolean("trustsign.exposeErrorDetails");
    this.sessionIssueRateLimitPerMinute = ServerConfig.sessionIssueRateLimitPerMinuteOrDefault(serverLimits);
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
        LOG.warn("Config file not found for IP check: {}", cfgFile.getAbsolutePath());
        return false;
      }
      AgentConfig cfg = ConfigLoader.load(cfgFile);
      List<String> allowed = cfg.allowedClientIps();
      if (allowed == null || allowed.isEmpty()) {
        return true;
      }
      boolean ok = allowed.contains(remoteIp);
      if (!ok) {
        LOG.warn("Rejecting request from disallowed IP: {}", remoteIp);
      }
      return ok;
    } catch (Exception e) {
      LOG.warn("Failed to evaluate client IP allowlist: {}", safeMsg(e));
      return false;
    }
  }

  private static String requestId(HttpServletRequest req) {
    String h = req != null ? req.getHeader("X-Request-Id") : null;
    if (h != null && !h.isBlank()) {
      return h.trim();
    }
    // Short id keeps logs readable; uniqueness is per-process/time and sufficient
    // for correlation.
    return UUID.randomUUID().toString().substring(0, 12);
  }

  private static String logCtx(HttpServletRequest req, String requestId) {
    String method = req != null ? req.getMethod() : "";
    String path = req != null ? req.getPathInfo() : "";
    String ip = req != null ? req.getRemoteAddr() : "";
    return "[rid=" + requestId + " " + method + " " + path + " ip=" + ip + "]";
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
      LOG.warn("Config load failed: {}", safeMsg(e));
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

  private static Path resolveConfiguredLogDirectory(AgentConfig cfg, File configFile) {
    String path = firstNonBlank(
        cfg != null && cfg.logging() != null ? cfg.logging().filePath() : null,
        cfg != null ? cfg.logFilePath() : null);
    if (path != null && !path.isBlank()) {
      String trimmed = path.trim();
      Path resolved = resolveAgainstConfigDir(trimmed, configFile);
      if (trimmed.endsWith("/") || trimmed.endsWith("\\") || (Files.exists(resolved) && Files.isDirectory(resolved))) {
        return resolved.toAbsolutePath().normalize();
      }
      Path parent = resolved.getParent();
      return (parent != null ? parent : resolveAgainstConfigDir("logs", configFile)).toAbsolutePath().normalize();
    }

    String logDir = cfg != null && cfg.logging() != null ? cfg.logging().directory() : null;
    if (logDir != null && !logDir.isBlank()) {
      return resolveAgainstConfigDir(logDir.trim(), configFile).toAbsolutePath().normalize();
    }
    return resolveAgainstConfigDir("logs", configFile).toAbsolutePath().normalize();
  }

  private static Path resolveSafeLogFile(Path allowedLogDir, String fileName) {
    Path base = allowedLogDir.toAbsolutePath().normalize();
    Path resolved = base.resolve(fileName).normalize().toAbsolutePath();
    if (!resolved.startsWith(base)) {
      throw new SecurityException("Invalid log file path");
    }
    return resolved;
  }

  private static Path resolveAgainstConfigDir(String path, File configFile) {
    Path p = Paths.get(path);
    if (p.isAbsolute()) {
      return p.normalize();
    }
    Path base = (configFile != null && configFile.getParentFile() != null)
        ? configFile.getParentFile().toPath()
        : Paths.get(System.getProperty("user.dir", "."));
    return base.resolve(p).normalize();
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) {
      return a.trim();
    }
    if (b != null && !b.isBlank()) {
      return b.trim();
    }
    return null;
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
   * For auto-sign PDF routes: by default signs the uploaded bytes only
   * ({@code chainedFromExistingOutput}
   * stays false), so re-signing an already-signed PDF adds a new signature and
   * visible stamp on top of the
   * prior one when the same stamp pages are used.
   * <p>
   * Set multipart {@code signFromUpload} to false/0/no to opt into chaining from
   * the previous numbered
   * output on disk when present ({@code stem-signed.pdf} ←
   * {@code stem-signed1.pdf} ← …) so earlier
   * signatures stay valid across incremental saves.
   */
  private static byte[] resolveAutoSignIncrementalInput(byte[] uploadedPdf, File targetSignedFile, Multipart.Data mp)
      throws IOException {
    String signFromUpload = readMultipartString(mp, "signFromUpload", true);
    boolean useUploadedPdfOnly = signFromUpload == null || signFromUpload.isBlank()
        || parseBooleanLoose(signFromUpload);
    if (useUploadedPdfOnly) {
      return uploadedPdf;
    }
    File chainSource = SignedPdfOutputPaths.predecessorForIncrementalChain(targetSignedFile);
    if (chainSource == null || !chainSource.isFile() || chainSource.length() == 0) {
      return uploadedPdf;
    }
    byte[] existing = Files.readAllBytes(chainSource.toPath());
    if (looksLikePdfHeader(existing)) {
      return existing;
    }
    return uploadedPdf;
  }

  /**
   * Suggested download name for streaming sign endpoints (single file, not
   * numbered).
   */
  private static String buildSignedPdfFilename(String filename) {
    String safe = sanitizeFilename(filename);
    String stem = SignedPdfOutputPaths.stemForSignedOutput(safe);
    return stem + "-signed.pdf";
  }

  private static boolean parseBooleanLoose(String v) {
    if (v == null)
      return false;
    String t = v.trim().toLowerCase(java.util.Locale.ROOT);
    return t.equals("true") || t.equals("1") || t.equals("yes") || t.equals("y");
  }

  /**
   * Builds PDF signing options from multipart: {@code finalVersion} and optional
   * {@code allowResignFinalVersion}
   * (true/1/yes/y) to sign a PDF that already has ISO 32000 DocMDP P=1 (no
   * changes permitted).
   */
  private static PdfSigningOptions pdfSigningOptionsFromMultipart(
      Multipart.Data mp, boolean finalVersion, AgentConfig cfg) {
    boolean allowResign = parseBooleanLoose(readMultipartString(mp, "allowResignFinalVersion", true));
    SignaturePlacement placement = parseSignaturePlacementFromMultipart(mp);
    return new PdfSigningOptions(
        finalVersion,
        allowResign,
        tsaConfigFromAgentConfig(cfg),
        ltvConfigFromAgentConfig(cfg),
        placement);
  }

  private static SignaturePlacement parseSignaturePlacementFromMultipart(Multipart.Data mp) {
    Float x = parseOptionalFloat(readMultipartString(mp, "x", true), "x");
    Float y = parseOptionalFloat(readMultipartString(mp, "y", true), "y");
    if ((x == null) != (y == null)) {
      throw new IllegalArgumentException("Both x and y coordinates are required together");
    }
    if (x != null && x < 0) {
      throw new IllegalArgumentException("x must be greater than or equal to 0");
    }
    if (y != null && y < 0) {
      throw new IllegalArgumentException("y must be greater than or equal to 0");
    }
    Float width = parseOptionalFloat(readMultipartString(mp, "width", true), "width");
    Float height = parseOptionalFloat(readMultipartString(mp, "height", true), "height");
    if (width != null && width <= 0) {
      throw new IllegalArgumentException("width must be positive");
    }
    if (height != null && height <= 0) {
      throw new IllegalArgumentException("height must be positive");
    }
    String overflowRaw = readMultipartString(mp, "coordinateOverflowMode", true);
    CoordinateOverflowMode overflowMode = CoordinateOverflowMode.ADJUST;
    if (overflowRaw != null && !overflowRaw.isBlank()) {
      String o = overflowRaw.trim().toLowerCase(java.util.Locale.ROOT);
      if ("adjust".equals(o)) {
        overflowMode = CoordinateOverflowMode.ADJUST;
      } else if ("error".equals(o)) {
        overflowMode = CoordinateOverflowMode.ERROR;
      } else {
        throw new IllegalArgumentException("Invalid coordinateOverflowMode. Supported values: adjust, error");
      }
    }
    String originRaw = readMultipartString(mp, "coordinateOrigin", true);
    CoordinateOrigin origin = CoordinateOrigin.BOTTOM_LEFT;
    if (originRaw != null && !originRaw.isBlank()) {
      String o = originRaw.trim().toLowerCase(java.util.Locale.ROOT);
      if ("bottom-left".equals(o) || "bottom_left".equals(o) || "bottomleft".equals(o)) {
        origin = CoordinateOrigin.BOTTOM_LEFT;
      } else if ("top-left".equals(o) || "top_left".equals(o) || "topleft".equals(o)) {
        origin = CoordinateOrigin.TOP_LEFT;
      } else {
        throw new IllegalArgumentException("Invalid coordinateOrigin. Supported values: bottom-left, top-left");
      }
    }
    return new SignaturePlacement(x, y, width, height, overflowMode, origin);
  }

  private static Float parseOptionalFloat(String raw, String fieldName) {
    if (raw == null || raw.isBlank()) {
      return null;
    }
    try {
      return Float.parseFloat(raw.trim());
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(fieldName + " must be a valid number");
    }
  }

  private static TsaClient.Config tsaConfigFromAgentConfig(AgentConfig cfg) {
    AgentConfig.TsaConfig t = cfg != null ? cfg.tsa() : null;
    if (t == null || t.url() == null || t.url().isBlank()) {
      return TsaClient.Config.DISABLED;
    }
    String hashAlg = (t.hashAlgorithm() == null || t.hashAlgorithm().isBlank()) ? "SHA-256" : t.hashAlgorithm();
    boolean failOnError = t.failOnError() != null && t.failOnError();
    int connectTimeout = t.connectTimeoutMs() == null ? 10_000 : t.connectTimeoutMs();
    int readTimeout = t.readTimeoutMs() == null ? 15_000 : t.readTimeoutMs();
    return new TsaClient.Config(t.url().trim(), hashAlg, failOnError, connectTimeout, readTimeout);
  }

  private static LtvEnabler.Config ltvConfigFromAgentConfig(AgentConfig cfg) {
    AgentConfig.LtvConfig l = cfg != null ? cfg.ltv() : null;
    if (l == null || l.enabled() == null || !l.enabled()) {
      return LtvEnabler.Config.DISABLED;
    }
    boolean fail = l.failOnMissingRevocationData() != null && l.failOnMissingRevocationData();
    int ocspCt = l.ocspConnectTimeoutMs() == null ? 10_000 : l.ocspConnectTimeoutMs();
    int ocspRt = l.ocspReadTimeoutMs() == null ? 15_000 : l.ocspReadTimeoutMs();
    int crlCt = l.crlConnectTimeoutMs() == null ? 10_000 : l.crlConnectTimeoutMs();
    int crlRt = l.crlReadTimeoutMs() == null ? 15_000 : l.crlReadTimeoutMs();
    return new LtvEnabler.Config(true, fail, ocspCt, ocspRt, crlCt, crlRt);
  }

  private Map<String, Object> probeTsaHealth(AgentConfig cfg) {
    TsaClient.Config tsa = tsaConfigFromAgentConfig(cfg);
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("configured", tsa.enabled());
    out.put("url", tsa.url());
    if (!tsa.enabled()) {
      out.put("status", "disabled");
      return out;
    }
    long startNs = System.nanoTime();
    try {
      byte[] dummySignatureValue = new byte[64];
      new java.security.SecureRandom().nextBytes(dummySignatureValue);
      byte[] token = new TsaClient(tsa).requestTimestampToken(dummySignatureValue);
      long ms = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
      out.put("status", "ok");
      out.put("latencyMs", ms);
      out.put("tokenBytes", token.length);
      out.put("hashAlgorithm", tsa.normalizedHashAlgorithm());
    } catch (Exception e) {
      long ms = Math.max(0L, (System.nanoTime() - startNs) / 1_000_000L);
      out.put("status", "error");
      out.put("latencyMs", ms);
      out.put("error", safeMsg(e));
    }
    return out;
  }

  /**
   * OCSP/CRL reachability for the configured signer (PKCS#11 cert matching
   * public-key.pem) and issuer
   * (token chain or trust store). Same timeouts as {@code ltv} in config.
   */
  private Map<String, Object> probeLtvHealth(AgentConfig cfg) {
    LtvEnabler.Config ltv = ltvConfigFromAgentConfig(cfg);
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("ts", Instant.now().toString());
    if (!ltv.enabled()) {
      out.put("status", "disabled");
      out.put("configured", false);
      return out;
    }
    out.put("configured", true);
    out.put("failOnMissingRevocationData", ltv.failOnMissingRevocationData());

    List<String> libs = OsPkcs11Resolver.candidates(cfg);
    if (libs.isEmpty()) {
      out.put("status", "error");
      out.put("error", "No PKCS#11 libraries configured for this OS");
      return out;
    }

    char[] pin;
    try {
      pin = resolvePin(cfg);
    } catch (SecurityException e) {
      out.put("status", "error");
      out.put("error", safeMsg(e));
      return out;
    }

    Pkcs11Token.Loaded loaded;
    try {
      loaded = Pkcs11Token.load(pin, libs);
    } catch (RuntimeException e) {
      out.put("status", "error");
      out.put("error", "Token load failed");
      out.put("details", buildTokenErrorDetail(e));
      return out;
    }

    java.util.List<PublicKey> pks;
    try {
      pks = loadConfiguredPublicKeysOrThrow();
    } catch (Exception e) {
      out.put("status", "error");
      out.put("error", "Failed to load configured public key(s)");
      out.put("details", safeMsg(e));
      return out;
    }

    CertificateSelection sel;
    try {
      sel = selectCertificateForPublicKeys(loaded.keyStore(), pks);
    } catch (Exception e) {
      out.put("status", "error");
      out.put("error", "Failed to select certificate from token");
      out.put("details", safeMsg(e));
      return out;
    }
    if (sel == null) {
      out.put("status", "error");
      out.put("error", "No token certificate matches configured public keys");
      return out;
    }

    out.put("alias", sel.alias);
    out.put("signerSubject", sel.certificate.getSubjectX500Principal().getName());

    X509Certificate issuer = null;
    if (sel.chain != null && sel.chain.length > 1 && sel.chain[1] instanceof X509Certificate x) {
      issuer = x;
    }
    if (issuer == null) {
      try {
        issuer = CertificateValidator.findIssuerInConfiguredTruststore(sel.certificate);
      } catch (Exception e) {
        out.put("status", "error");
        out.put("error", "Trust store read failed while resolving issuer");
        out.put("details", safeMsg(e));
        return out;
      }
    }

    if (issuer == null) {
      out.put("status", "error");
      out.put(
          "error",
          "Issuer certificate not found (no chain[1] on token and no matching entry in trust store)");
      return out;
    }
    out.put("issuerSubject", issuer.getSubjectX500Principal().getName());

    LtvEnabler.RevocationProbeResult probe = LtvEnabler.probeRevocation(sel.certificate, issuer, ltv);
    out.put("ocspOk", probe.ocspOk());
    if (probe.ocspLatencyMs() != null) {
      out.put("ocspLatencyMs", probe.ocspLatencyMs());
    }
    if (probe.ocspError() != null) {
      out.put("ocspError", probe.ocspError());
    }
    out.put("crlAttempted", probe.crlAttempted());
    out.put("crlOk", probe.crlOk());
    if (probe.crlLatencyMs() != null) {
      out.put("crlLatencyMs", probe.crlLatencyMs());
    }
    if (probe.crlError() != null) {
      out.put("crlError", probe.crlError());
    }
    if (probe.source() != null) {
      out.put("revocationSource", probe.source());
    }

    if (probe.ok()) {
      out.put("status", "ok");
    } else {
      out.put("status", "error");
      out.put("error", "OCSP and CRL both failed for signer certificate");
    }
    return out;
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
    if (v == null)
      return null;
    String t = v.trim();
    if (t.isEmpty())
      return null;
    try {
      int n = Integer.parseInt(t);
      return n > 0 ? n : null;
    } catch (Exception ignore) {
      return null;
    }
  }

  private enum OutputMode {
    RAW,
    FILE,
    BOTH
  }

  private enum RawOutputFormat {
    BASE64,
    HEX,
    BINARY
  }

  private record OutputPreference(OutputMode mode, RawOutputFormat rawFormat) {
    boolean includesRaw() {
      return mode == OutputMode.RAW || mode == OutputMode.BOTH;
    }

    boolean includesFile() {
      return mode == OutputMode.FILE || mode == OutputMode.BOTH;
    }
  }

  private static OutputPreference parseOutputPreference(Multipart.Data mp) {
    String outputRaw = readMultipartString(mp, "output", true);
    if (outputRaw == null || outputRaw.isBlank()) {
      throw new IllegalArgumentException("output is required. Supported values: raw, file, both");
    }
    OutputMode mode = switch (outputRaw.trim().toLowerCase(java.util.Locale.ROOT)) {
      case "raw" -> OutputMode.RAW;
      case "file" -> OutputMode.FILE;
      case "both" -> OutputMode.BOTH;
      default -> throw new IllegalArgumentException("Invalid output value. Supported values: raw, file, both");
    };

    RawOutputFormat format = RawOutputFormat.BASE64;
    if (mode == OutputMode.RAW) {
      String outputFormatRaw = readMultipartString(mp, "outputFormat", true);
      if (outputFormatRaw != null && !outputFormatRaw.isBlank()) {
        format = switch (outputFormatRaw.trim().toLowerCase(java.util.Locale.ROOT)) {
          case "base64" -> RawOutputFormat.BASE64;
          case "hex" -> RawOutputFormat.HEX;
          case "binary" -> RawOutputFormat.BINARY;
          default -> throw new IllegalArgumentException(
              "Invalid outputFormat value. Supported values: base64, hex, binary");
        };
      }
    }
    return new OutputPreference(mode, format);
  }

  private static String encodeForRawOutput(byte[] content, RawOutputFormat format) {
    RawOutputFormat safeFormat = format == null ? RawOutputFormat.BASE64 : format;
    return switch (safeFormat) {
      case BASE64 -> Base64.getEncoder().encodeToString(content);
      case HEX -> toHex(content);
      case BINARY -> toBinary(content);
    };
  }

  private static String toHex(byte[] content) {
    StringBuilder out = new StringBuilder(content.length * 2);
    for (byte b : content) {
      out.append(String.format("%02x", b));
    }
    return out.toString();
  }

  private static String toBinary(byte[] content) {
    StringBuilder out = new StringBuilder(content.length * 8);
    for (byte b : content) {
      out.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
    }
    return out.toString();
  }

  private static String requireAutoSignOutputDirForFileOutput(AgentConfig cfg) {
    String outputDir = cfg.autoSignOutputDir();
    if (outputDir == null || outputDir.isBlank()) {
      throw new IllegalArgumentException(
          "Output directory is not configured. Please provide autoSignOutputDir in config.");
    }
    return outputDir;
  }

  /**
   * Reads a text multipart field or a same-named file part (Postman-style). For
   * PEM bodies, use {@code trimBody=false}.
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
   * HSM signer certificate: prefers raw file part {@code cer} (PEM or DER), else
   * form field text as UTF-8.
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
   * Parses comma-separated 1-based page numbers (e.g. "1,3,5") into 0-based
   * indices.
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
   * - {@code allPages}: if true, stamps all pages (evaluated before {@code pages}
   * so a default hidden {@code pages=1}
   * does not cancel {@code allPages=true})
   * - {@code lastPage}: if true, stamps only the final page
   * - {@code pages}: comma-separated 1-based page numbers (e.g. {@code 1,3,5})
   * - {@code startPage}: 1-based page; stamps from this page through the final page
   * - {@code page}: single 1-based page (field or file part, like other multipart text)
   * - default: page 1 only (no config; use {@code allPages}, {@code pages},
   * {@code page}, or {@code startPage} to change)
   */
  private static java.util.List<Integer> resolvePdfStampPages(Multipart.Data mp) {
    String allPagesStr = readMultipartString(mp, "allPages", true);
    if (parseBooleanLoose(allPagesStr)) {
      return java.util.List.of(-1);
    }

    String lastPageStr = readMultipartString(mp, "lastPage", true);
    if (parseBooleanLoose(lastPageStr)) {
      // Marker resolved in PdfSignerService.resolveStampPages(...)
      return java.util.List.of(-2);
    }

    String pagesCsv = readMultipartString(mp, "pages", true);
    if (pagesCsv != null && !pagesCsv.isBlank()) {
      java.util.List<Integer> pages = parsePagesCsv1Based(pagesCsv);
      return pages.isEmpty() ? java.util.List.of(0) : pages;
    }

    Integer startPage1 = parsePositiveInt(readMultipartString(mp, "startPage", true));
    if (startPage1 != null) {
      // Negative range marker resolved in PdfSignerService.resolveStampPages(...):
      // -1000 - startPage1 means [startPage1..lastPage].
      return java.util.List.of(-1000 - startPage1);
    }

    Integer page1 = parsePositiveInt(readMultipartString(mp, "page", true));
    if (page1 != null) {
      return java.util.List.of(page1 - 1);
    }

    return java.util.List.of(0);
  }

  public void handleGet(HttpServletRequest req, HttpServletResponse resp, String forcedPath) throws IOException {
    final String rid = requestId(req);
    final String ctx = logCtx(req, rid);
    final long startMs = System.currentTimeMillis();
    if (!isClientIpAllowed(req)) {
      writeJson(resp, 403, Map.of("error", "IP not allowed", "ip", req.getRemoteAddr()));
      return;
    }
    LicenceEnforcer.Result licence = licenceEnforcer.check();
    if (!licence.allowed()) {
      writeJson(resp, 403, Map.of("error", "Licence", "message", licence.message()));
      return;
    }
    String path = forcedPath != null ? normPath(forcedPath) : normPath(req.getPathInfo());

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
        case "/health/tsa" -> {
          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;
          Map<String, Object> tsaHealth = probeTsaHealth(cfg);
          int status = "error".equals(String.valueOf(tsaHealth.get("status"))) ? 503 : 200;
          writeJson(resp, status, tsaHealth);
          return;
        }
        case "/health/ltv" -> {
          AgentConfig cfgLtv = loadConfig(resp);
          if (cfgLtv == null)
            return;
          Map<String, Object> ltvHealth = probeLtvHealth(cfgLtv);
          int ltvStatus = "error".equals(String.valueOf(ltvHealth.get("status"))) ? 503 : 200;
          writeJson(resp, ltvStatus, ltvHealth);
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
            LOG.warn("{} Token load failed (certificates). tookMs={} details={}",
                ctx, System.currentTimeMillis() - startMs, detail);
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
        case "/logs" -> {
          // requireSession(req);
          AgentConfig cfg = loadConfig(resp);
          if (cfg == null) {
            return;
          }
          String dateParam = req.getParameter("date");
          if (dateParam == null || dateParam.isBlank()) {
            writeJson(resp, 400, Map.of("error", "Missing required query parameter: date (YYYY-MM-DD)"));
            return;
          }
          LocalDate date;
          try {
            date = LocalDate.parse(dateParam.trim());
          } catch (DateTimeParseException e) {
            writeJson(resp, 400, Map.of("error", "Invalid date format. Use YYYY-MM-DD"));
            return;
          }
          File cfgFile = resolveConfigFile();
          Path logDir = resolveConfiguredLogDirectory(cfg, cfgFile);
          String fileName = "application-" + date + ".log";
          Path logFile = resolveSafeLogFile(logDir, fileName);
          if (!Files.isRegularFile(logFile)) {
            writeJson(resp, 404, Map.of("error", "Log file not found", "file", fileName));
            return;
          }

          resp.setStatus(200);
          resp.setContentType("application/octet-stream");
          resp.setHeader("Content-Disposition", "attachment; filename=\"" + sanitizeFilename(fileName) + "\"");
          resp.setContentLengthLong(Files.size(logFile));
          Files.copy(logFile, resp.getOutputStream());
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
      LOG.warn("{} GET error after {} ms: {}", ctx, System.currentTimeMillis() - startMs, safeMsg(e), e);
      writeJson(resp, 500, Map.of("error", "Internal error", "details", safeMsg(e)));
    }
  }

  public void handlePost(HttpServletRequest req, HttpServletResponse resp, String forcedPath) throws IOException {
    final String rid = requestId(req);
    final String ctx = logCtx(req, rid);
    final long startMs = System.currentTimeMillis();
    if (!isClientIpAllowed(req)) {
      writeJson(resp, 403, Map.of("error", "IP not allowed", "ip", req.getRemoteAddr()));
      return;
    }
    LicenceEnforcer.Result licence = licenceEnforcer.check();
    if (!licence.allowed()) {
      writeJson(resp, 403, Map.of("error", "Licence", "message", licence.message()));
      return;
    }
    String path = forcedPath != null ? normPath(forcedPath) : normPath(req.getPathInfo());

    try {
      switch (path) {
        case "/session" -> {
          if (!allowSessionIssue(req)) {
            writeJson(resp, 429, Map.of("error", "Too many session requests"));
            return;
          }
          SessionManager.Session s = sessions.createSessionMinutes(10);
          writeJson(resp, 200, Map.of("token", s.token(), "expiresAt", s.expiresAt().toString()));
          return;
        }

        case "/auto-sign-text" -> {
          requireSession(req);
          var mp = Multipart.read(req, multipartTextMaxBytes);
          OutputPreference outputPreference;
          try {
            outputPreference = parseOutputPreference(mp);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }
          byte[] data = mp.file("file");

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing text file field: file"));
            return;
          }
          if (isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400,
                Map.of("error", "PDF is not allowed on /auto-sign-text. Use /sign-pdf or /auto-sign-pdf."));
            return;
          }

          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;

          File outDirFile = null;
          if (outputPreference.includesFile()) {
            String outputDir;
            try {
              outputDir = requireAutoSignOutputDirForFileOutput(cfg);
            } catch (IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", e.getMessage()));
              return;
            }
            Path outputBase = null;
            if (cfg.outputBaseDir() != null && !cfg.outputBaseDir().isBlank()) {
              outputBase = Paths.get(cfg.outputBaseDir());
              if (!outputBase.isAbsolute()) {
                outputBase = Paths.get(System.getProperty("user.dir", ".")).resolve(outputBase).normalize();
              }
            }
            try {
              outDirFile = resolveSafeOutputDir(outputDir, outputBase);
            } catch (SecurityException | IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", "Invalid outputDir", "details", e.getMessage()));
              return;
            }
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
            LOG.warn("{} Token load failed (auto-sign-text). tookMs={} details={}",
                ctx, System.currentTimeMillis() - startMs, detail);
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

          String signedText = sb.toString();
          byte[] signedTextBytes = signedText.getBytes(StandardCharsets.UTF_8);
          String outputPath = null;
          if (outputPreference.includesFile()) {
            final Path reservedOutPath;
            try {
              reservedOutPath = SignedPdfOutputPaths.reserveNextSignedTextPath(
                  Objects.requireNonNull(outDirFile, "outDirFile").toPath(), inputFilename,
                  ApiServlet::sanitizeFilename);
            } catch (IOException e) {
              LOG.warn("/auto-sign-text: failed to reserve output path: {}", safeMsg(e));
              writeJson(resp, 500, Map.of("error", "Could not reserve output file", "details", safeMsg(e)));
              return;
            }
            boolean outputWritten = false;
            try {
              Files.writeString(
                  reservedOutPath,
                  signedText,
                  StandardCharsets.UTF_8,
                  StandardOpenOption.TRUNCATE_EXISTING);
              outputWritten = true;
              outputPath = reservedOutPath.toAbsolutePath().toString();
            } finally {
              if (!outputWritten) {
                try {
                  Files.deleteIfExists(reservedOutPath);
                } catch (IOException e) {
                  LOG.warn("/auto-sign-text: failed to delete reserved output: {}", safeMsg(e));
                }
              }
            }
          }
          Map<String, Object> responseBody = new LinkedHashMap<>();
          responseBody.put("ok", true);
          responseBody.put("subjectDn", signingCert != null ? signingCert.getSubjectX500Principal().getName() : "");
          responseBody.put("serialNumber", signingCert != null ? signingCert.getSerialNumber().toString(16) : "");
          if (outputPreference.includesRaw()) {
            responseBody.put("signedData", encodeForRawOutput(signedTextBytes, outputPreference.rawFormat()));
            responseBody.put("outputFormat", outputPreference.rawFormat().name().toLowerCase(java.util.Locale.ROOT));
          }
          if (outputPreference.includesFile()) {
            responseBody.put("outputPath", outputPath);
          }
          writeJson(resp, 200, responseBody);
          return;
        }

        case "/auto-sign-pdf" -> {
          LOG.info("{} Auto-signing PDF request received", ctx);
          var mp = Multipart.read(req, multipartPdfMaxBytes);
          OutputPreference outputPreference;
          try {
            outputPreference = parseOutputPreference(mp);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }
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
          PdfSigningOptions pdfOpts;
          try {
            pdfOpts = pdfSigningOptionsFromMultipart(mp, finalVersion, cfg);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }

          File outDirFile = null;
          if (outputPreference.includesFile()) {
            String outputDir;
            try {
              outputDir = requireAutoSignOutputDirForFileOutput(cfg);
            } catch (IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", e.getMessage()));
              return;
            }
            Path outputBase = null;
            if (cfg.outputBaseDir() != null && !cfg.outputBaseDir().isBlank()) {
              outputBase = Paths.get(cfg.outputBaseDir());
              if (!outputBase.isAbsolute()) {
                outputBase = Paths.get(System.getProperty("user.dir", ".")).resolve(outputBase).normalize();
              }
            }
            try {
              outDirFile = resolveSafeOutputDir(outputDir, outputBase);
            } catch (SecurityException | IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", "Invalid outputDir", "details", e.getMessage()));
              return;
            }
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
            LOG.warn("{} Token load failed (auto-sign-pdf). tookMs={} details={}",
                ctx, System.currentTimeMillis() - startMs, detail);
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

          Path reservedOutPath = null;
          if (outputPreference.includesFile()) {
            try {
              reservedOutPath = SignedPdfOutputPaths.reserveNextSignedPdfPath(
                  Objects.requireNonNull(outDirFile, "outDirFile").toPath(), inputFilename,
                  ApiServlet::sanitizeFilename);
            } catch (IOException e) {
              LOG.warn("/auto-sign-pdf: failed to reserve output path: {}", safeMsg(e));
              writeJson(resp, 500, Map.of("error", "Could not reserve output file", "details", safeMsg(e)));
              return;
            }
          }

          boolean outputWritten = false;
          try {
            File outFile = reservedOutPath != null ? reservedOutPath.toFile() : null;
            byte[] pdfToSign = outFile != null ? resolveAutoSignIncrementalInput(data, outFile, mp) : data;

            PdfSignerService.PdfSigningResult signResult;
            try {
              long signStartMs = System.currentTimeMillis();
              signResult = PdfSignerService.signPdf(
                  pdfToSign,
                  key,
                  chain,
                  loaded.provider(),
                  signingCert,
                  reason,
                  location,
                  stampPages,
                  pdfOpts);
              LOG.info("{} PDF signed. alias={} pages={} timestamped={} tookMs={}",
                  ctx, matchedAlias, stampPages != null ? stampPages.size() : 0, signResult.isTimestamped(),
                  System.currentTimeMillis() - signStartMs);
            } catch (DocMdpNoChangesLockException e) {
              writeJson(resp, 409, Map.of("error", "DocMDP P=1 (document locked)", "details", e.getMessage()));
              return;
            } catch (PdfSignerService.PdfSigningException e) {
              LOG.warn("{} PDF signing failed. alias={} tookMs={} err={}",
                  ctx, matchedAlias, System.currentTimeMillis() - startMs, safeMsg(e), e);
              writeJson(resp, 500, Map.of("error", "PDF signing failed", "details", safeMsg(e)));
              return;
            } catch (IOException e) {
              LOG.warn("{} Invalid PDF structure. alias={} tookMs={} err={}",
                  ctx, matchedAlias, System.currentTimeMillis() - startMs, safeMsg(e));
              writeJson(resp, 400, Map.of("error", "Invalid PDF structure", "details", safeMsg(e)));
              return;
            }
            byte[] signedPdf = signResult.signedPdf();
            String outputPath = null;
            if (reservedOutPath != null) {
              Files.write(reservedOutPath, signedPdf, StandardOpenOption.TRUNCATE_EXISTING);
              outputWritten = true;
              outputPath = Objects.requireNonNull(outFile, "outFile").getAbsolutePath();
            }

            Map<String, Object> autoPdfBody = new LinkedHashMap<>();
            autoPdfBody.put("ok", true);
            autoPdfBody.put("format", "pdf");
            autoPdfBody.put("subjectDn", signingCert.getSubjectX500Principal().getName());
            autoPdfBody.put("serialNumber", signingCert.getSerialNumber().toString(16));
            if (outputPreference.includesRaw()) {
              autoPdfBody.put("signedData", encodeForRawOutput(signedPdf, outputPreference.rawFormat()));
              autoPdfBody.put("outputFormat", outputPreference.rawFormat().name().toLowerCase(java.util.Locale.ROOT));
            }
            if (outputPreference.includesFile()) {
              autoPdfBody.put("outputPath", outputPath);
            }
            autoPdfBody.put("chainedFromExistingOutput", outFile != null && pdfToSign != data);
            autoPdfBody.put("stampedPages", stampPages);
            autoPdfBody.put("finalVersion", finalVersion);
            autoPdfBody.put("timestamped", signResult.isTimestamped());
            if (signResult.tsaWarning() != null) {
              autoPdfBody.put("tsaWarning", signResult.tsaWarning().getMessage());
            }
            // writeJson(resp, 200, autoPdfBody);
            resp.getOutputStream().write(signedPdf);
          } finally {
            if (reservedOutPath != null && !outputWritten) {
              try {
                Files.deleteIfExists(reservedOutPath);
              } catch (IOException e) {
                LOG.warn("/auto-sign-pdf: failed to delete reserved output: {}", safeMsg(e));
              }
            }
          }
          return;
        }

        case "/auto-sign-text-cms" -> {
          requireSession(req);
          var mp = Multipart.read(req, multipartTextMaxBytes);
          OutputPreference outputPreference;
          try {
            outputPreference = parseOutputPreference(mp);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }
          byte[] data = mp.file("file");
          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing text file field: file"));
            return;
          }
          if (isPdfUpload(data, mp.filename("file"))) {
            writeJson(resp, 400,
                Map.of("error", "PDF is not allowed on /auto-sign-text-cms. Use /sign-pdf or /auto-sign-pdf."));
            return;
          }
          AgentConfig cfg = loadConfig(resp);
          if (cfg == null)
            return;

          File outDirFile = null;
          if (outputPreference.includesFile()) {
            String outputDir;
            try {
              outputDir = requireAutoSignOutputDirForFileOutput(cfg);
            } catch (IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", e.getMessage()));
              return;
            }
            Path outputBase = null;
            if (cfg.outputBaseDir() != null && !cfg.outputBaseDir().isBlank()) {
              outputBase = Paths.get(cfg.outputBaseDir());
              if (!outputBase.isAbsolute()) {
                outputBase = Paths.get(System.getProperty("user.dir", ".")).resolve(outputBase).normalize();
              }
            }
            try {
              outDirFile = resolveSafeOutputDir(outputDir, outputBase);
            } catch (SecurityException | IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", "Invalid outputDir", "details", e.getMessage()));
              return;
            }
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
            LOG.warn("{} Token load failed (auto-sign-text-cms). tookMs={} details={}",
                ctx, System.currentTimeMillis() - startMs, detail);
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
          if (inputFilename == null || inputFilename.isBlank()) {
            inputFilename = "text.txt";
          }

          String signedText = sb.toString();
          byte[] signedTextBytes = signedText.getBytes(StandardCharsets.UTF_8);
          String outputPath = null;
          if (outputPreference.includesFile()) {
            final Path reservedOutPath;
            try {
              reservedOutPath = SignedPdfOutputPaths.reserveNextCmsSignedTextPath(
                  Objects.requireNonNull(outDirFile, "outDirFile").toPath(), inputFilename,
                  ApiServlet::sanitizeFilename);
            } catch (IOException e) {
              LOG.warn("/auto-sign-text-cms: failed to reserve output path: {}", safeMsg(e));
              writeJson(resp, 500, Map.of("error", "Could not reserve output file", "details", safeMsg(e)));
              return;
            }
            boolean outputWritten = false;
            try {
              Files.writeString(
                  reservedOutPath, signedText, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
              outputWritten = true;
              outputPath = reservedOutPath.toAbsolutePath().toString();
            } finally {
              if (!outputWritten) {
                try {
                  Files.deleteIfExists(reservedOutPath);
                } catch (IOException e) {
                  LOG.warn("/auto-sign-text-cms: failed to delete reserved output: {}", safeMsg(e));
                }
              }
            }
          }
          Map<String, Object> responseBody = new LinkedHashMap<>();
          responseBody.put("ok", true);
          responseBody.put("subjectDn", signingCert.getSubjectX500Principal().getName());
          responseBody.put("serialNumber", signingCert.getSerialNumber().toString(16));
          if (outputPreference.includesRaw()) {
            responseBody.put("signedData", encodeForRawOutput(signedTextBytes, outputPreference.rawFormat()));
            responseBody.put("outputFormat", outputPreference.rawFormat().name().toLowerCase(java.util.Locale.ROOT));
          }
          if (outputPreference.includesFile()) {
            responseBody.put("outputPath", outputPath);
          }
          writeJson(resp, 200, responseBody);
          return;
        }

        case "/sign-pdf" -> {
          requireSession(req);
          var mp = Multipart.read(req, multipartPdfMaxBytes);
          OutputPreference outputPreference;
          try {
            outputPreference = parseOutputPreference(mp);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }
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
          PdfSigningOptions pdfOpts;
          try {
            pdfOpts = pdfSigningOptionsFromMultipart(mp, finalVersion, cfg);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
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

          X509Certificate signingCert = matchedCert;
          X509Certificate[] x509Chain = chain != null && chain.length > 0 && chain[0] instanceof X509Certificate
              ? java.util.Arrays.stream(chain).filter(c -> c instanceof X509Certificate).map(c -> (X509Certificate) c)
                  .toArray(X509Certificate[]::new)
              : null;
          CertificateValidator.validateForSigning(signingCert, x509Chain);
          PdfSignerService.PdfSigningResult signResult;
          try {
            long signStartMs = System.currentTimeMillis();
            signResult = PdfSignerService.signPdf(
                data,
                key,
                chain,
                loaded.provider(),
                signingCert,
                reason,
                location,
                stampPages,
                pdfOpts);
            LOG.info("{} PDF signed. alias={} pages={} timestamped={} tookMs={}",
                ctx, matchedAlias, stampPages != null ? stampPages.size() : 0, signResult.isTimestamped(),
                System.currentTimeMillis() - signStartMs);
          } catch (DocMdpNoChangesLockException e) {
            writeJson(resp, 409, Map.of("error", "DocMDP P=1 (document locked)", "details", e.getMessage()));
            return;
          } catch (PdfSignerService.PdfSigningException e) {
            LOG.warn("{} PDF signing failed. alias={} tookMs={} err={}",
                ctx, matchedAlias, System.currentTimeMillis() - startMs, safeMsg(e), e);
            writeJson(resp, 500, Map.of("error", "PDF signing failed", "details", safeMsg(e)));
            return;
          } catch (IOException e) {
            LOG.warn("{} Invalid PDF structure. alias={} tookMs={} err={}",
                ctx, matchedAlias, System.currentTimeMillis() - startMs, safeMsg(e));
            writeJson(resp, 400, Map.of("error", "Invalid PDF structure", "details", safeMsg(e)));
            return;
          }
          byte[] signedPdf = signResult.signedPdf();
          String outputPath = null;
          if (outputPreference.includesFile()) {
            String outputDir;
            try {
              outputDir = requireAutoSignOutputDirForFileOutput(cfg);
            } catch (IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", e.getMessage()));
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
            String inputFilename = mp.filename("file");
            if (inputFilename == null || inputFilename.isBlank()) {
              inputFilename = "document.pdf";
            }
            final Path reservedOutPath;
            try {
              reservedOutPath = SignedPdfOutputPaths.reserveNextSignedPdfPath(
                  outDirFile.toPath(), inputFilename, ApiServlet::sanitizeFilename);
            } catch (IOException e) {
              LOG.warn("/sign-pdf: failed to reserve output path: {}", safeMsg(e));
              writeJson(resp, 500, Map.of("error", "Could not reserve output file", "details", safeMsg(e)));
              return;
            }
            boolean outputWritten = false;
            try {
              Files.write(reservedOutPath, signedPdf, StandardOpenOption.TRUNCATE_EXISTING);
              outputWritten = true;
              outputPath = reservedOutPath.toAbsolutePath().toString();
            } finally {
              if (!outputWritten) {
                try {
                  Files.deleteIfExists(reservedOutPath);
                } catch (IOException e) {
                  LOG.warn("/sign-pdf: failed to delete reserved output: {}", safeMsg(e));
                }
              }
            }
          }
          Map<String, Object> signPdfBody = new LinkedHashMap<>();
          signPdfBody.put("ok", true);
          signPdfBody.put("format", "pdf");
          signPdfBody.put("subjectDn", signingCert.getSubjectX500Principal().getName());
          signPdfBody.put("serialNumber", signingCert.getSerialNumber().toString(16));
          signPdfBody.put("stampedPages", stampPages);
          signPdfBody.put("finalVersion", finalVersion);
          signPdfBody.put("timestamped", signResult.isTimestamped());
          if (signResult.tsaWarning() != null) {
            signPdfBody.put("tsaWarning", signResult.tsaWarning().getMessage());
          }
          if (outputPreference.includesRaw()) {
            signPdfBody.put("signedData", encodeForRawOutput(signedPdf, outputPreference.rawFormat()));
            signPdfBody.put("outputFormat", outputPreference.rawFormat().name().toLowerCase(java.util.Locale.ROOT));
          }
          if (outputPreference.includesFile()) {
            signPdfBody.put("outputPath", outputPath);
          }
          writeJson(resp, 200, signPdfBody);
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
          PdfSigningOptions pdfOpts;
          try {
            pdfOpts = pdfSigningOptionsFromMultipart(mp, finalVersion, cfg);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }

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
            long signStartMs = System.currentTimeMillis();
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
            LOG.info("{} HSM PDF signed. pages={} tookMs={}",
                ctx, stampPages != null ? stampPages.size() : 0, System.currentTimeMillis() - signStartMs);
          } catch (DocMdpNoChangesLockException e) {
            writeJson(resp, 409, Map.of("error", "DocMDP P=1 (document locked)", "details", e.getMessage()));
            return;
          } catch (IOException e) {
            LOG.warn("{} HSM invalid PDF structure. tookMs={} err={}",
                ctx, System.currentTimeMillis() - startMs, safeMsg(e));
            writeJson(resp, 400, Map.of("error", "Invalid PDF structure", "details", safeMsg(e)));
            return;
          } catch (RuntimeException e) {
            String detail = buildTokenErrorDetail(e);
            LOG.warn("{} HSM token load or signing failed. tookMs={} details={}",
                ctx, System.currentTimeMillis() - startMs, detail, e);
            writeJson(resp, 400, Map.of("error", "HSM token load or signing failed", "details", detail));
            return;
          } catch (Exception e) {
            LOG.warn("{} /hsm/sign-pdf failed. tookMs={} err={}", ctx, System.currentTimeMillis() - startMs, safeMsg(e),
                e);
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
          OutputPreference outputPreference;
          try {
            outputPreference = parseOutputPreference(mp);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }
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
          PdfSigningOptions pdfOpts;
          try {
            pdfOpts = pdfSigningOptionsFromMultipart(mp, finalVersion, cfg);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }

          if (cfg.hsm() == null) {
            writeJson(resp, 500,
                Map.of("error", "Configuration error", "details", "config.hsm is not configured (see config.json)"));
            return;
          }
          File outDirFile = null;
          if (outputPreference.includesFile()) {
            String outputDir;
            try {
              outputDir = requireAutoSignOutputDirForFileOutput(cfg);
            } catch (IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", e.getMessage()));
              return;
            }
            Path outputBase = null;
            if (cfg.outputBaseDir() != null && !cfg.outputBaseDir().isBlank()) {
              outputBase = Paths.get(cfg.outputBaseDir());
              if (!outputBase.isAbsolute()) {
                outputBase = Paths.get(System.getProperty("user.dir", ".")).resolve(outputBase).normalize();
              }
            }
            try {
              outDirFile = resolveSafeOutputDir(outputDir, outputBase);
            } catch (SecurityException | IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", "Invalid outputDir", "details", e.getMessage()));
              return;
            }
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

          Path reservedOutPath = null;
          if (outputPreference.includesFile()) {
            try {
              reservedOutPath = SignedPdfOutputPaths.reserveNextSignedPdfPath(
                  Objects.requireNonNull(outDirFile, "outDirFile").toPath(), inputFilename,
                  ApiServlet::sanitizeFilename);
            } catch (IOException e) {
              LOG.warn("/hsm/auto-sign-pdf: failed to reserve output path: {}", safeMsg(e));
              writeJson(resp, 500, Map.of("error", "Could not reserve output file", "details", safeMsg(e)));
              return;
            }
          }

          boolean outputWritten = false;
          try {
            File outFile = reservedOutPath != null ? reservedOutPath.toFile() : null;
            byte[] pdfToSign = outFile != null ? resolveAutoSignIncrementalInput(data, outFile, mp) : data;

            char[] pinChars = pinStr.toCharArray();
            HsmPdfSignerService.SignResult hsmResult = null;
            try {
              long signStartMs = System.currentTimeMillis();
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
              LOG.info("{} HSM auto-sign PDF signed. pages={} tookMs={}",
                  ctx, stampPages != null ? stampPages.size() : 0, System.currentTimeMillis() - signStartMs);
            } catch (DocMdpNoChangesLockException e) {
              writeJson(resp, 409, Map.of("error", "DocMDP P=1 (document locked)", "details", e.getMessage()));
              return;
            } catch (IOException e) {
              LOG.warn("{} HSM auto-sign invalid PDF structure. tookMs={} err={}",
                  ctx, System.currentTimeMillis() - startMs, safeMsg(e));
              writeJson(resp, 400, Map.of("error", "Invalid PDF structure", "details", safeMsg(e)));
              return;
            } catch (RuntimeException e) {
              String detail = buildTokenErrorDetail(e);
              LOG.warn("{} HSM auto-sign token load or signing failed. tookMs={} details={}",
                  ctx, System.currentTimeMillis() - startMs, detail, e);
              writeJson(resp, 400, Map.of("error", "HSM token load or signing failed", "details", detail));
              return;
            } catch (Exception e) {
              LOG.warn("{} /hsm/auto-sign-pdf failed. tookMs={} err={}",
                  ctx, System.currentTimeMillis() - startMs, safeMsg(e), e);
              writeJson(resp, 400, Map.of("error", "HSM PDF signing failed", "details", safeMsg(e)));
              return;
            } finally {
              java.util.Arrays.fill(pinChars, '\0');
            }

            byte[] signedPdf = hsmResult.signedPdf();
            X509Certificate signingCert = hsmResult.signingCertificate();
            String outputPath = null;
            if (reservedOutPath != null) {
              Files.write(reservedOutPath, signedPdf, StandardOpenOption.TRUNCATE_EXISTING);
              outputWritten = true;
              outputPath = Objects.requireNonNull(outFile, "outFile").getAbsolutePath();
            }

            Map<String, Object> hsmAutoBody = new LinkedHashMap<>();
            hsmAutoBody.put("ok", true);
            hsmAutoBody.put("format", "pdf");
            hsmAutoBody.put("subjectDn", signingCert.getSubjectX500Principal().getName());
            hsmAutoBody.put("serialNumber", signingCert.getSerialNumber().toString(16));
            if (outputPreference.includesRaw()) {
              hsmAutoBody.put("signedData", encodeForRawOutput(signedPdf, outputPreference.rawFormat()));
              hsmAutoBody.put("outputFormat", outputPreference.rawFormat().name().toLowerCase(java.util.Locale.ROOT));
            }
            if (outputPreference.includesFile()) {
              hsmAutoBody.put("outputPath", outputPath);
            }
            hsmAutoBody.put("chainedFromExistingOutput", outFile != null && pdfToSign != data);
            hsmAutoBody.put("stampedPages", stampPages);
            hsmAutoBody.put("finalVersion", finalVersion);
            writeJson(resp, 200, hsmAutoBody);
          } finally {
            if (reservedOutPath != null && !outputWritten) {
              try {
                Files.deleteIfExists(reservedOutPath);
              } catch (IOException e) {
                LOG.warn("/hsm/auto-sign-pdf: failed to delete reserved output: {}", safeMsg(e));
              }
            }
          }
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

        case "/debug/pdf-ltv" -> {
          if (!debugEndpointsEnabled) {
            writeJson(resp, 404, Map.of("error", "Not found"));
            return;
          }
          requireSession(req);
          LOG.info("{} LTV debug request received", ctx);
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
          PdfLtvInspector.Result result = PdfLtvInspector.inspect(data);
          writeJson(resp, result.ok() ? 200 : 422, result);
          return;
        }

        case "/sign-text" -> {
          requireSession(req);

          var mp = Multipart.read(req, multipartTextMaxBytes);
          OutputPreference outputPreference;
          try {
            outputPreference = parseOutputPreference(mp);
          } catch (IllegalArgumentException e) {
            writeJson(resp, 400, Map.of("error", e.getMessage()));
            return;
          }
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
            LOG.warn("{} Token load failed (sign-text). tookMs={} details={}",
                ctx, System.currentTimeMillis() - startMs, detail);
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
          String signedText = sb.toString();
          byte[] signedTextBytes = signedText.getBytes(StandardCharsets.UTF_8);
          String outputPath = null;
          if (outputPreference.includesFile()) {
            String outputDir;
            try {
              outputDir = requireAutoSignOutputDirForFileOutput(cfg);
            } catch (IllegalArgumentException e) {
              writeJson(resp, 400, Map.of("error", e.getMessage()));
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
            String inputFilename = mp.filename("file");
            if (inputFilename == null || inputFilename.isBlank()) {
              inputFilename = "text.txt";
            }
            final Path reservedOutPath;
            try {
              reservedOutPath = SignedPdfOutputPaths.reserveNextSignedTextPath(
                  outDirFile.toPath(), inputFilename, ApiServlet::sanitizeFilename);
            } catch (IOException e) {
              LOG.warn("/sign-text: failed to reserve output path: {}", safeMsg(e));
              writeJson(resp, 500, Map.of("error", "Could not reserve output file", "details", safeMsg(e)));
              return;
            }
            boolean outputWritten = false;
            try {
              Files.writeString(
                  reservedOutPath,
                  signedText,
                  StandardCharsets.UTF_8,
                  StandardOpenOption.TRUNCATE_EXISTING);
              outputWritten = true;
              outputPath = reservedOutPath.toAbsolutePath().toString();
            } finally {
              if (!outputWritten) {
                try {
                  Files.deleteIfExists(reservedOutPath);
                } catch (IOException e) {
                  LOG.warn("/sign-text: failed to delete reserved output: {}", safeMsg(e));
                }
              }
            }
          }
          Map<String, Object> signTextBody = new LinkedHashMap<>();
          signTextBody.put("ok", true);
          signTextBody.put("subjectDn", signingCert.getSubjectX500Principal().getName());
          signTextBody.put("serialNumber", signingCert.getSerialNumber().toString(16));
          if (outputPreference.includesRaw()) {
            signTextBody.put("signedData", encodeForRawOutput(signedTextBytes, outputPreference.rawFormat()));
            signTextBody.put("outputFormat", outputPreference.rawFormat().name().toLowerCase(java.util.Locale.ROOT));
          }
          if (outputPreference.includesFile()) {
            signTextBody.put("outputPath", outputPath);
          }
          writeJson(resp, 200, signTextBody);
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
          if (!debugEndpointsEnabled) {
            writeJson(resp, 404, Map.of("error", "Not found"));
            return;
          }
          requireSession(req);
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
      LOG.warn("{} POST error after {} ms: {}", ctx, System.currentTimeMillis() - startMs, safeMsg(e), e);
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
    Object normalized = normalizeErrorShape(status, body);
    Json.MAPPER.writeValue(resp.getOutputStream(), redactErrorDetails(normalized));
  }

  private Object normalizeErrorShape(int status, Object body) {
    if (!(body instanceof Map<?, ?> original) || !original.containsKey("error") || original.containsKey("code")) {
      return body;
    }
    Map<String, Object> normalized = new LinkedHashMap<>();
    normalized.put("code", codeForStatus(status));
    for (Map.Entry<?, ?> e : original.entrySet()) {
      if (e.getKey() == null) {
        continue;
      }
      normalized.put(String.valueOf(e.getKey()), e.getValue());
    }
    return normalized;
  }

  private static String codeForStatus(int status) {
    return switch (status) {
      case 400 -> "TS_BAD_REQUEST";
      case 401 -> "TS_UNAUTHORIZED";
      case 403 -> "TS_FORBIDDEN";
      case 404 -> "TS_NOT_FOUND";
      case 409 -> "TS_CONFLICT";
      case 422 -> "TS_UNPROCESSABLE";
      case 429 -> "TS_RATE_LIMITED";
      default -> "TS_INTERNAL";
    };
  }

  private Object redactErrorDetails(Object body) {
    if (exposeErrorDetails || !(body instanceof Map<?, ?> original) || !original.containsKey("details")) {
      return body;
    }
    Map<String, Object> sanitized = new LinkedHashMap<>();
    for (Map.Entry<?, ?> e : original.entrySet()) {
      if (e.getKey() == null) {
        continue;
      }
      String key = String.valueOf(e.getKey());
      if ("details".equals(key)) {
        continue;
      }
      sanitized.put(key, e.getValue());
    }
    return sanitized;
  }

  private boolean allowSessionIssue(HttpServletRequest req) {
    String ip = req.getRemoteAddr();
    long nowMinute = System.currentTimeMillis() / 60_000L;
    SessionIssueWindow window = sessionIssueWindows.compute(ip, (k, curr) -> {
      if (curr == null || curr.minute != nowMinute) {
        return new SessionIssueWindow(nowMinute, 1);
      }
      return new SessionIssueWindow(curr.minute, curr.count + 1);
    });
    return window != null && window.count <= sessionIssueRateLimitPerMinute;
  }

  private static final class SessionIssueWindow {
    final long minute;
    final int count;

    SessionIssueWindow(long minute, int count) {
      this.minute = minute;
      this.count = count;
    }
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

    String dotEnvPin = readDotEnvValue("TRUSTSIGN_TOKEN_PIN");
    if (dotEnvPin != null && !dotEnvPin.isBlank()) {
      return dotEnvPin.toCharArray();
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

  private static String readDotEnvValue(String key) {
    Path[] candidates = new Path[] { Paths.get(".env"), Paths.get("..", ".env") };
    for (Path p : candidates) {
      try {
        if (!Files.isRegularFile(p)) {
          continue;
        }
        for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
          if (line == null) {
            continue;
          }
          String trimmed = line.trim();
          if (trimmed.isEmpty() || trimmed.startsWith("#")) {
            continue;
          }
          int idx = trimmed.indexOf('=');
          if (idx <= 0) {
            continue;
          }
          String k = trimmed.substring(0, idx).trim();
          if (!key.equals(k)) {
            continue;
          }
          String v = trimmed.substring(idx + 1).trim();
          if ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'"))) {
            v = v.substring(1, v.length() - 1).trim();
          }
          return v;
        }
      } catch (Exception ignore) {
      }
    }
    return null;
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
