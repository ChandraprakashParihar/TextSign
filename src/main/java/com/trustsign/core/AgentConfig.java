package com.trustsign.core;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record AgentConfig(
    List<String> allowedOrigins,
    Integer port,
    Pkcs11Config pkcs11,
    /** Optional. Shortcut for logging.filePath. Absolute or relative to config dir. */
    @JsonProperty(required = false) String logFilePath,
    /** Optional. Logging configuration (file/console, levels, strictness). */
    @JsonProperty(required = false) LoggingConfig logging,
    /**
     * Optional. PKCS#11 settings used only by {@code /hsm/sign-pdf} and {@code /hsm/auto-sign-pdf}.
     * Keeps HSM driver paths separate from the main {@code pkcs11} block; token PIN and signer .cer are supplied per request.
     */
    @JsonProperty(required = false) HsmConfig hsm,
    /** Optional. When set, outputDir for /auto-sign-text must be under this path (absolute or relative to working dir). */
    @JsonProperty(required = false) String outputBaseDir,
    /** Optional. When set, signing certificates are validated against this trust store (chain validation). */
    @JsonProperty(required = false) TruststoreConfig truststore,
    /** Optional. When set, enables CCA ROOT SKI and/or class (certificate policy) validation. */
    @JsonProperty(required = false) CertificateValidationConfig certificateValidation,
    /** Optional. Emitted as &lt;SIGNER-VERSION&gt; in signed output. Use e.g. "V-NCODE_01.05.2013" for Icegate verification. */
    @JsonProperty(required = false) String signerVersion,
    /** Optional. File path to an image rendered inside visible PDF signatures. */
    @JsonProperty(required = false) String signatureImagePath,
    /** Optional. RFC 3161 timestamping settings for PDF signatures. */
    @JsonProperty(required = false) TsaConfig tsa,
    /** Optional. Long-Term Validation (DSS: certs, OCSP, CRLs) settings for PDF signatures. */
    @JsonProperty(required = false) LtvConfig ltv,
    /** Optional default output mode for auto-sign APIs: raw, file, or both. */
    @JsonProperty(required = false) String output,
    /** Optional default raw output format for auto-sign APIs: base64, hex, or binary. */
    @JsonProperty(required = false) String outputFormat,
    /**
     * Optional. When set, /auto-sign-text and /auto-sign-text-cms will always write signed
     * files to this directory instead of taking outputDir from the HTTP request.
     * May be absolute or relative to the working directory.
     */
    @JsonProperty(required = false) String autoSignOutputDir,
    /**
     * Optional. When non-empty, only these client IP addresses are allowed to call the HTTP API.
     * Values should be plain IP string matches of HttpServletRequest.getRemoteAddr()
     * (for example: "127.0.0.1", "10.0.0.5").
     * When null or empty, all client IPs are allowed.
     */
    @JsonProperty(required = false) List<String> allowedClientIps,
    /**
     * Optional. Server threading, TCP limits, multipart sizes, and signing concurrency.
     * Very large concurrent user counts require many JVM instances behind a load balancer; tune {@code maxConcurrentSigningOperations}
     * per HSM throughput and set {@code maxTcpConnections} to protect each instance.
     */
    @JsonProperty(required = false) ServerConfig server
) {

  public record TruststoreConfig(
      String path,
      @JsonProperty(required = false) String password,
      @JsonProperty(required = false) String type,
      @JsonProperty(required = false) Boolean enablePathValidation
  ) {}

  /** Config for CCA ROOT SKI and class (certificate policy OID) validation. */
  public record CertificateValidationConfig(
      @JsonProperty(required = false) Boolean enableCcaRootSkiCheck,
      /** Comma-separated hex Subject Key Identifiers of allowed root CAs (e.g. CCA India root SKI). */
      @JsonProperty(required = false) String allowedRootSkis,
      @JsonProperty(required = false) Boolean enableClassValidation,
      /** Comma-separated certificate policy OIDs (e.g. India PKI Class 2/3 policy OIDs). */
      @JsonProperty(required = false) String allowedCertificatePolicyOids
  ) {}

  public record Pkcs11Config(
      String preferredLibrary,
      List<String> windowsCandidates,
      List<String> macCandidates,
      List<String> linuxCandidates,
      String pin
  ) {}

  /**
   * HSM / PKCS#11 library discovery for the dedicated HSM PDF endpoints. No PIN here — use the {@code pin} multipart field on the API.
   */
  public record HsmConfig(
      @JsonProperty(required = false) String preferredLibrary,
      @JsonProperty(required = false) List<String> windowsCandidates,
      @JsonProperty(required = false) List<String> macCandidates,
      @JsonProperty(required = false) List<String> linuxCandidates,
      /**
       * Optional. For each library, PKCS#11 {@code slotListIndex} values {@code 0 .. slotProbeCount-1} are tried until the uploaded .cer matches.
       * When omitted or non-positive, the server uses default probing (see {@code com.trustsign.hsm.HsmPkcs11ConfigurationService}).
       */
      @JsonProperty(required = false) Integer slotProbeCount
  ) {}

  /**
   * RFC 3161 Time Stamping Authority settings.
   * When {@code url} is blank or missing, TSA is disabled.
   */
  public record TsaConfig(
      @JsonProperty(required = false) String url,
      @JsonProperty(required = false) String hashAlgorithm,
      @JsonProperty(required = false) Boolean failOnError,
      @JsonProperty(required = false) Integer connectTimeoutMs,
      @JsonProperty(required = false) Integer readTimeoutMs
  ) {}

  /**
   * Application logging settings. File logging is appended (never overwritten).
   */
  public record LoggingConfig(
      /**
       * Log directory (absolute or relative to the config file directory).
       * When set, the log file is {@code <directory>/application.log} (parent dirs created at runtime).
       * Ignored when {@link #filePath} is set or top-level {@code logFilePath} is set.
       */
      @JsonProperty(required = false) String directory,
      /** Absolute or relative to config directory. */
      @JsonProperty(required = false) String filePath,
      /** When true, errors initializing file logging will fail startup. */
      @JsonProperty(required = false) Boolean failOnError,
      /** Default INFO. Values: SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST. */
      @JsonProperty(required = false) String level,
      /** Default true. */
      @JsonProperty(required = false) Boolean consoleEnabled
  ) {}

  /**
   * LTV embedding settings for PDF signatures.
   */
  public record LtvConfig(
      @JsonProperty(required = false) Boolean enabled,
      /** If true, signing fails when OCSP and CRL are both unavailable for any signer cert. */
      @JsonProperty(required = false) Boolean failOnMissingRevocationData,
      /** If true, require revocation evidence for each non-root certificate in the embedded DSS chain. */
      @JsonProperty(required = false) Boolean strictPerCertEvidence,
      @JsonProperty(required = false) Integer ocspConnectTimeoutMs,
      @JsonProperty(required = false) Integer ocspReadTimeoutMs,
      @JsonProperty(required = false) Integer crlConnectTimeoutMs,
      @JsonProperty(required = false) Integer crlReadTimeoutMs
  ) {}

  public int portOrDefault() {
    return (port == null || port <= 0) ? 31927 : port;
  }

  /**
   * Production server limits. All fields optional; static {@code *OrDefault} helpers apply safe bounds.
   */
  public record ServerConfig(
      @JsonProperty(required = false) Integer maxThreads,
      @JsonProperty(required = false) Integer minSpareThreads,
      @JsonProperty(required = false) Integer threadIdleTimeoutMs,
      @JsonProperty(required = false) Boolean enableDebugEndpoints,
      @JsonProperty(required = false) Integer acceptQueueSize,
      @JsonProperty(required = false) Integer connectorIdleTimeoutMs,
      /** When set and positive, server connector max connections are capped. Zero or omitted = no global TCP cap. */
      @JsonProperty(required = false) Integer maxTcpConnections,
      /** Max concurrent PKCS#11 / signing requests. Omitted defaults to 16; {@code 0} means unlimited (use only with external throttling). */
      @JsonProperty(required = false) Integer maxConcurrentSigningOperations,
      @JsonProperty(required = false) Long signingAcquireTimeoutMs,
      @JsonProperty(required = false) Integer requestHeaderSizeBytes,
      @JsonProperty(required = false) Integer responseHeaderSizeBytes,
      @JsonProperty(required = false) Integer multipartPdfMaxFileMb,
      @JsonProperty(required = false) Integer multipartTextMaxFileMb,
      /** Max /session token issuances per IP per minute. */
      @JsonProperty(required = false) Integer sessionIssueRateLimitPerMinute,
      @JsonProperty(required = false) Long gracefulStopTimeoutMs
  ) {

    public static int maxThreadsOrDefault(ServerConfig c) {
      Integer configured = c == null ? null : c.maxThreads();
      int v = configured == null ? 250 : configured;
      return Math.min(Math.max(v, 8), 20_000);
    }

    public static int minSpareThreadsOrDefault(ServerConfig c) {
      int max = maxThreadsOrDefault(c);
      Integer configured = c == null ? null : c.minSpareThreads();
      int v = configured == null ? Math.min(10, max) : configured;
      return Math.min(Math.max(v, 1), max);
    }

    public static int threadIdleTimeoutMsOrDefault(ServerConfig c) {
      Integer configured = c == null ? null : c.threadIdleTimeoutMs();
      int v = configured == null ? 60_000 : configured;
      return Math.min(Math.max(v, 1000), 600_000);
    }

    public static int acceptQueueSizeOrDefault(ServerConfig c) {
      int v = c == null || c.acceptQueueSize() == null ? 4096 : c.acceptQueueSize();
      return Math.min(Math.max(v, 50), 1_000_000);
    }

    public static boolean enableDebugEndpointsOrDefault(ServerConfig c) {
      return c != null && Boolean.TRUE.equals(c.enableDebugEndpoints());
    }

    public static int connectorIdleTimeoutMsOrDefault(ServerConfig c) {
      int v = c == null || c.connectorIdleTimeoutMs() == null ? 120_000 : c.connectorIdleTimeoutMs();
      return Math.min(Math.max(v, 1000), 600_000);
    }

    public static int maxTcpConnectionsOrDefault(ServerConfig c) {
      if (c == null || c.maxTcpConnections() == null) {
        return 0;
      }
      return Math.min(Math.max(c.maxTcpConnections(), 0), 10_000_000);
    }

    /**
     * @return 0 means unlimited signing concurrency (not recommended without external throttling).
     */
    public static int maxConcurrentSigningOrDefault(ServerConfig c) {
      if (c == null || c.maxConcurrentSigningOperations() == null) {
        return 16;
      }
      return Math.min(Math.max(c.maxConcurrentSigningOperations(), 0), 50_000);
    }

    public static long signingAcquireTimeoutMsOrDefault(ServerConfig c) {
      long v = c == null || c.signingAcquireTimeoutMs() == null ? 300_000L : c.signingAcquireTimeoutMs();
      return Math.min(Math.max(v, 0L), 3_600_000L);
    }

    public static int requestHeaderSizeBytesOrDefault(ServerConfig c) {
      int v = c == null || c.requestHeaderSizeBytes() == null ? 8192 : c.requestHeaderSizeBytes();
      return Math.min(Math.max(v, 4096), 1_048_576);
    }

    public static int responseHeaderSizeBytesOrDefault(ServerConfig c) {
      int v = c == null || c.responseHeaderSizeBytes() == null ? 8192 : c.responseHeaderSizeBytes();
      return Math.min(Math.max(v, 4096), 1_048_576);
    }

    public static int multipartPdfMaxFileMbOrDefault(ServerConfig c) {
      int v = c == null || c.multipartPdfMaxFileMb() == null ? 25 : c.multipartPdfMaxFileMb();
      return Math.min(Math.max(v, 1), 500);
    }

    public static int multipartTextMaxFileMbOrDefault(ServerConfig c) {
      int v = c == null || c.multipartTextMaxFileMb() == null ? 4 : c.multipartTextMaxFileMb();
      return Math.min(Math.max(v, 1), 100);
    }

    public static int sessionIssueRateLimitPerMinuteOrDefault(ServerConfig c) {
      Integer fromProp = Integer.getInteger("trustsign.sessionRateLimitPerMinute");
      int v = c == null || c.sessionIssueRateLimitPerMinute() == null
          ? (fromProp == null ? 30 : fromProp)
          : c.sessionIssueRateLimitPerMinute();
      return Math.min(Math.max(v, 1), 10_000);
    }

    public static long gracefulStopTimeoutMsOrDefault(ServerConfig c) {
      long v = c == null || c.gracefulStopTimeoutMs() == null ? 30_000L : c.gracefulStopTimeoutMs();
      return Math.min(Math.max(v, 1000L), 300_000L);
    }
  }
}

