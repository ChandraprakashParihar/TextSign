package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.ConfigLoader;
import com.trustsign.core.LicenceEnforcer;
import org.eclipse.jetty.server.Server;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class Main {
  private static final Logger LOG = Logger.getLogger(Main.class.getName());
  private static final String BUILD_TIME_RESOURCE = "/com/trustsign/build-time.txt";
  private static final String LICENCE_PUBLIC_KEY_RESOURCE = "/com/trustsign/licence-public-key.pem";

  public static void main(String[] args) throws Exception {
    File configFile = resolveConfigFileOrFail(args);

    if (!configFile.exists()) {
      System.err.println("Config file not found: " + configFile.getAbsolutePath());
      System.err.println("Specify with --config=/path/to/config.json or place config/config.json in the working directory.");
      System.exit(1);
    }

    LOG.info("Using config: " + configFile.getAbsolutePath());

    AgentConfig cfg = ConfigLoader.load(configFile);
    applyTruststoreConfig(configFile, cfg);
    applyCertificateValidationConfig(cfg);

    LicenceEnforcer licenceEnforcer = createLicenceEnforcer(configFile);
    LicenceEnforcer.Result licenceResult = licenceEnforcer.check();
    if (!licenceResult.allowed()) {
      System.err.println("Licence check failed: " + licenceResult.message());
      System.exit(1);
    }

    Server server = ServerBootstrap.buildServer(cfg, licenceEnforcer);
    server.setStopTimeout(AgentConfig.ServerConfig.gracefulStopTimeoutMsOrDefault(cfg.server()));
    server.start();

    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      LOG.info("Shutting down TrustSign server...");
      try {
        server.stop();
      } catch (Exception e) {
        LOG.log(Level.WARNING, "Error stopping server", e);
      }
    }));

    LOG.info("TrustSign API at http://0.0.0.0:" + cfg.portOrDefault() + "/v1 — for very high load run many instances behind a load balancer; each JVM is bounded by signing hardware throughput.");
    server.join();
  }

  /**
   * Resolves config file from args or default locations. Caller must check exists() before loading.
   */
  static File resolveConfigFile(String[] args) {
    if (args != null) {
      for (String a : args) {
        if (a != null && a.startsWith("--config=")) {
          String path = a.substring("--config=".length()).trim();
          if (!path.isEmpty()) {
            File f = new File(path);
            if (f.exists()) return f;
            return f; // return so caller can report missing path
          }
        }
      }
    }

    File f1 = Path.of("config", "config.json").toFile();
    if (f1.exists()) return f1;

    File f2 = Path.of("..", "config", "config.json").normalize().toFile();
    if (f2.exists()) return f2;

    return f1;
  }

  private static File resolveConfigFileOrFail(String[] args) {
    return resolveConfigFile(args);
  }

  /**
   * Applies truststore and path-validation settings from config to system properties
   * so CertificateValidator uses them when validating signing certificates.
   */
  private static void applyTruststoreConfig(File configFile, AgentConfig cfg) {
    if (cfg.truststore() == null || cfg.truststore().path() == null || cfg.truststore().path().isBlank()) {
      return;
    }
    String path = cfg.truststore().path();
    if (!new File(path).isAbsolute()) {
      path = new File(path).getAbsolutePath();
    }
    System.setProperty("trustsign.truststore.path", path);
    if (cfg.truststore().password() != null) {
      System.setProperty("trustsign.truststore.password", cfg.truststore().password());
    }
    if (cfg.truststore().type() != null && !cfg.truststore().type().isBlank()) {
      System.setProperty("trustsign.truststore.type", cfg.truststore().type());
    }
    if (cfg.truststore().enablePathValidation() != null && cfg.truststore().enablePathValidation()) {
      System.setProperty("trustsign.enablePathValidation", "true");
    }
  }

  /**
   * Applies certificate validation settings (CCA ROOT SKI, class validation) from config
   * to system properties so CertificateValidator uses them.
   */
  private static void applyCertificateValidationConfig(AgentConfig cfg) {
    if (cfg.certificateValidation() == null) {
      return;
    }
    AgentConfig.CertificateValidationConfig v = cfg.certificateValidation();
    if (Boolean.TRUE.equals(v.enableCcaRootSkiCheck())) {
      System.setProperty("trustsign.enableCcaRootSkiCheck", "true");
      if (v.allowedRootSkis() != null && !v.allowedRootSkis().isBlank()) {
        System.setProperty("trustsign.allowedRootSkis", v.allowedRootSkis().trim());
      }
    }
    if (Boolean.TRUE.equals(v.enableClassValidation())) {
      System.setProperty("trustsign.enableClassValidation", "true");
      if (v.allowedCertificatePolicyOids() != null && !v.allowedCertificatePolicyOids().isBlank()) {
        System.setProperty("trustsign.allowedCertificatePolicyOids", v.allowedCertificatePolicyOids().trim());
      }
    }
  }

  private static LicenceEnforcer createLicenceEnforcer(File configFile) throws Exception {
    Path configDir = configFile.getParentFile() != null ? configFile.getParentFile().toPath() : Path.of(".");
    Path licencePath = configDir.resolve("licence.json");
    Path statePath = configDir.resolve(".licence-state");

    if (!licencePath.toFile().exists()) {
      throw new IllegalStateException(
          "Licence file not found: " + licencePath.toAbsolutePath() +
              ". The vendor must provide a signed licence.json in the config directory.");
    }

    long buildTimestampMs = 0;
    try (InputStream in = Main.class.getResourceAsStream(BUILD_TIME_RESOURCE)) {
      if (in != null) {
        String s = new String(in.readAllBytes()).trim();
        if (!s.isEmpty()) {
          // Accept integer seconds or decimal (e.g. 1773463432 or 1773463432.051)
          int dot = s.indexOf('.');
          String secs = dot >= 0 ? s.substring(0, dot) : s;
          if (!secs.isEmpty()) {
            buildTimestampMs = Long.parseLong(secs) * 1000L;
          }
        }
      }
    }

    PublicKey publicKey;
    try (InputStream in = Main.class.getResourceAsStream(LICENCE_PUBLIC_KEY_RESOURCE)) {
      if (in == null) {
        throw new IllegalStateException("Licence public key resource not found. Rebuild with licence-public-key.pem in resources.");
      }
      publicKey = LicenceEnforcer.loadPublicKeyFromPem(in);
    }

    return new LicenceEnforcer(licencePath, statePath, buildTimestampMs, publicKey);
  }
}

