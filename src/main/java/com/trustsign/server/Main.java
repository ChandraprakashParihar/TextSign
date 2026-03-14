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

    LicenceEnforcer licenceEnforcer = createLicenceEnforcer(configFile);
    LicenceEnforcer.Result licenceResult = licenceEnforcer.check();
    if (!licenceResult.allowed()) {
      System.err.println("Licence check failed: " + licenceResult.message());
      System.exit(1);
    }

    Server server = ServerBootstrap.buildServer(cfg, licenceEnforcer);
    server.start();

    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      LOG.info("Shutting down TrustSign server...");
      try {
        server.stop();
      } catch (Exception e) {
        LOG.log(Level.WARNING, "Error stopping server", e);
      }
    }));

    LOG.info("TrustSign text server listening on http://127.0.0.1:" + cfg.portOrDefault() + "/v1");
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

