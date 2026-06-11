package com.trustsign.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.nio.file.Files;
import java.util.regex.Pattern;

public final class ConfigLoader {
  private static final ObjectMapper MAPPER = new ObjectMapper();
  /** Matches a config value like {@code ${MY_ENV_VAR}} and captures the var name. */
  private static final Pattern ENV_PLACEHOLDER = Pattern.compile("^\\$\\{([^}]+)}$");
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

      // Resolve ${ENV_VAR} placeholders in all string values, then validate pin.
      JsonNode root = MAPPER.readTree(json);
      if (root instanceof ObjectNode rootObj) {
        resolveEnvPlaceholders(rootObj);
      }
      JsonNode pinNode = root.path("pkcs11").path("pin");
      if (!pinNode.isMissingNode() && !pinNode.isNull() && !pinNode.isTextual()) {
        throw new IllegalStateException(
            "Invalid config field: pkcs11.pin must be a quoted JSON string (e.g. \"12345678\").");
      }
      if (!pinNode.isMissingNode() && !pinNode.isNull()) {
        String pinText = pinNode.asText();
        String pinTrim = pinText == null ? "" : pinText.trim();
        if (pinTrim.isEmpty()) {
          throw new IllegalStateException("Invalid config field: pkcs11.pin must not be empty when provided.");
        }
      }

      AgentConfig cfg = MAPPER.treeToValue(root, AgentConfig.class);

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
      if (cfg.tsa() != null && cfg.tsa().hashAlgorithm() != null && !cfg.tsa().hashAlgorithm().isBlank()) {
        String alg = cfg.tsa().hashAlgorithm().trim().toUpperCase(java.util.Locale.ROOT);
        if (!alg.equals("SHA-256") && !alg.equals("SHA256")) {
          throw new IllegalStateException("tsa.hashAlgorithm must be SHA-256");
        }
      }
      return cfg;
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException("Failed to load config: " + file.getAbsolutePath() + " — " + e.getMessage(), e);
    }
  }

  /**
   * Recursively replaces {@code "${ENV_VAR_NAME}"} string values with the
   * corresponding environment variable.  Throws if the variable is not set so
   * the operator gets a clear startup error instead of a cryptic wrong-password
   * failure later.  Plain literal passwords are left untouched.
   */
  private static void resolveEnvPlaceholders(ObjectNode node) {
    node.fields().forEachRemaining(entry -> {
      JsonNode value = entry.getValue();
      if (value.isTextual()) {
        java.util.regex.Matcher m = ENV_PLACEHOLDER.matcher(value.asText());
        if (m.matches()) {
          String varName = m.group(1).trim();
          String resolved = System.getenv(varName);
          if (resolved == null) {
            resolved = System.getProperty(varName);
          }
          if (resolved == null) {
            throw new IllegalStateException(
                "Config references environment variable '" + varName + "' which is not set. "
                    + "Export the variable or replace the placeholder with a literal value.");
          }
          node.put(entry.getKey(), resolved);
        }
      } else if (value.isObject()) {
        resolveEnvPlaceholders((ObjectNode) value);
      }
    });
  }

  private ConfigLoader() {}
}

