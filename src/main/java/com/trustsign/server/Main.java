package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.ConfigLoader;
import org.eclipse.jetty.server.Server;

import java.io.File;
import java.nio.file.Path;

public final class Main {
  public static void main(String[] args) throws Exception {
    File configFile = resolveConfigFile(args);

    System.out.println("Using config: " + configFile.getAbsolutePath());

    AgentConfig cfg = ConfigLoader.load(configFile);

    Server server = ServerBootstrap.buildServer(cfg);
    server.start();
    System.out.println("TrustSign text server listening on http://127.0.0.1:" + cfg.portOrDefault() + "/v1");
    server.join();
  }

  private static File resolveConfigFile(String[] args) {
    if (args != null) {
      for (String a : args) {
        if (a != null && a.startsWith("--config=")) {
          File f = new File(a.substring("--config=".length()));
          if (f.exists()) return f;
        }
      }
    }

    File f1 = Path.of("config", "config.json").toFile();
    if (f1.exists()) return f1;

    File f2 = Path.of("..", "config", "config.json").normalize().toFile();
    if (f2.exists()) return f2;

    return f1;
  }
}

