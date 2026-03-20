package com.trustsign.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.File;
import java.nio.file.Files;

public final class ConfigLoader {
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final int MIN_PORT = 1;
  private static final int MAX_PORT = 65535;

  public static AgentConfig load(File file) {
    if (file == null) {
      throw new IllegalArgumentException("Config file is null");
    }
    if (!file.exists()) {
      throw new IllegalStateException("Missing config: " + file.getAbsolutePath());
    }
    if (!file.isFile()) {
      throw new IllegalStateException("Config path is not a file: " + file.getAbsolutePath());
    }
    try {
      String json = Files.readString(file.toPath());
      if (json == null || json.isBlank()) {
        throw new IllegalStateException("Config file is empty: " + file.getAbsolutePath());
      }

      // Validate pkcs11.pin shape before mapping into records so users get a
      // clear error (e.g. they must use quotes in JSON).
      JsonNode root = MAPPER.readTree(json);
      JsonNode pinNode = root.path("pkcs11").path("pin");
      if (pinNode.isMissingNode() || pinNode.isNull()) {
        throw new IllegalStateException("Missing config field: pkcs11.pin (use a quoted string PIN, e.g. \"12345678\")");
      }
      if (!pinNode.isTextual()) {
        throw new IllegalStateException(
            "Invalid config field: pkcs11.pin must be a quoted JSON string (e.g. \"12345678\").");
      }
      String pinText = pinNode.asText();
      String pinTrim = pinText == null ? "" : pinText.trim();
      if (pinTrim.isEmpty()) {
        throw new IllegalStateException("Invalid config field: pkcs11.pin must not be empty.");
      }

      AgentConfig cfg = MAPPER.readValue(json, AgentConfig.class);

      if (cfg.allowedOrigins() == null || cfg.allowedOrigins().isEmpty()) {
        throw new IllegalStateException("allowedOrigins is required and must be non-empty");
      }
      if (cfg.pkcs11() == null) {
        throw new IllegalStateException("pkcs11 is required");
      }
      int port = cfg.portOrDefault();
      if (port < MIN_PORT || port > MAX_PORT) {
        throw new IllegalStateException("port must be between " + MIN_PORT + " and " + MAX_PORT + ", got: " + port);
      }
      return cfg;
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException("Failed to load config: " + file.getAbsolutePath() + " — " + e.getMessage(), e);
    }
  }

  private ConfigLoader() {}
}

