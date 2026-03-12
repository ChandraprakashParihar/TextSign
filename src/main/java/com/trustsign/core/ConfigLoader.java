package com.trustsign.core;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.nio.file.Files;

public final class ConfigLoader {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static AgentConfig load(File file) {
    try {
      if (!file.exists()) {
        throw new IllegalStateException("Missing config: " + file.getAbsolutePath());
      }
      String json = Files.readString(file.toPath());
      AgentConfig cfg = MAPPER.readValue(json, AgentConfig.class);

      if (cfg.allowedOrigins() == null || cfg.allowedOrigins().isEmpty()) {
        throw new IllegalStateException("allowedOrigins is required");
      }
      if (cfg.pkcs11() == null) {
        throw new IllegalStateException("pkcs11 is required");
      }
      return cfg;
    } catch (Exception e) {
      throw new RuntimeException("Failed to load config.json", e);
    }
  }

  private ConfigLoader() {}
}

