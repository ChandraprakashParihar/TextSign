package com.trustsign.core;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record AgentConfig(
    List<String> allowedOrigins,
    Integer port,
    Pkcs11Config pkcs11,
    /** Optional. When set, outputDir for /auto-sign-text must be under this path (absolute or relative to working dir). */
    @JsonProperty(required = false) String outputBaseDir,
    /** Optional. When set, signing certificates are validated against this trust store (chain validation). */
    @JsonProperty(required = false) TruststoreConfig truststore,
    /** Optional. When set, enables CCA ROOT SKI and/or class (certificate policy) validation. */
    @JsonProperty(required = false) CertificateValidationConfig certificateValidation,
    /** Optional. Emitted as &lt;SIGNER-VERSION&gt; in signed output. Use e.g. "V-NCODE_01.05.2013" for Icegate verification. */
    @JsonProperty(required = false) String signerVersion,
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
    @JsonProperty(required = false) List<String> allowedClientIps
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

  public int portOrDefault() {
    return (port == null || port <= 0) ? 31927 : port;
  }
}

