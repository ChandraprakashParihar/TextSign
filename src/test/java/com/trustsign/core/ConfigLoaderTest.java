package com.trustsign.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ConfigLoaderTest {

  @TempDir
  Path tempDir;

  @Test
  void loadThrowsWhenFileIsNull() {
    assertThrows(IllegalArgumentException.class, () -> ConfigLoader.load(null));
  }

  @Test
  void loadThrowsWhenFileDoesNotExist() {
    File missing = tempDir.resolve("missing.json").toFile();
    assertThrows(IllegalStateException.class, () -> ConfigLoader.load(missing));
    assertTrue(
        assertThrows(IllegalStateException.class, () -> ConfigLoader.load(missing))
            .getMessage()
            .contains("Missing config")
    );
  }

  @Test
  void loadThrowsWhenFileIsEmpty() throws Exception {
    Path empty = tempDir.resolve("empty.json");
    Files.writeString(empty, "");
    IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConfigLoader.load(empty.toFile()));
    assertTrue(e.getMessage().contains("empty"));
  }

  @Test
  void loadThrowsWhenAllowedOriginsMissing() throws Exception {
    String json = """
        {"port": 31927, "pkcs11": {"pin": "1234"}}
        """;
    Path f = tempDir.resolve("cfg.json");
    Files.writeString(f, json);
    IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConfigLoader.load(f.toFile()));
    assertTrue(e.getMessage().toLowerCase().contains("allowedorigins"));
  }

  @Test
  void loadThrowsWhenPkcs11Missing() throws Exception {
    String json = """
        {"port": 31927, "allowedOrigins": ["http://localhost:3000"]}
        """;
    Path f = tempDir.resolve("cfg.json");
    Files.writeString(f, json);
    IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConfigLoader.load(f.toFile()));
    assertTrue(e.getMessage().toLowerCase().contains("pkcs11"));
  }

  @Test
  void loadThrowsWhenPortOutOfRange() throws Exception {
    String json = """
        {"port": 70000, "allowedOrigins": ["http://localhost:3000"], "pkcs11": {"pin": "1234"}}
        """;
    Path f = tempDir.resolve("cfg.json");
    Files.writeString(f, json);
    IllegalStateException e = assertThrows(IllegalStateException.class, () -> ConfigLoader.load(f.toFile()));
    assertTrue(e.getMessage().toLowerCase().contains("port"));
  }

  @Test
  void loadSucceedsWithValidConfig() throws Exception {
    String json = """
        {"port": 31927, "allowedOrigins": ["http://localhost:3000"], "pkcs11": {"pin": "1234"}}
        """;
    Path f = tempDir.resolve("cfg.json");
    Files.writeString(f, json);
    AgentConfig cfg = ConfigLoader.load(f.toFile());
    assertNotNull(cfg);
    assertEquals(31927, cfg.portOrDefault());
    assertEquals(1, cfg.allowedOrigins().size());
    assertNotNull(cfg.pkcs11());
  }

  @Test
  void portOrDefaultWhenPortZeroUsesDefault() throws Exception {
    String json = """
        {"port": 0, "allowedOrigins": ["http://localhost:3000"], "pkcs11": {}}
        """;
    Path f = tempDir.resolve("cfg.json");
    Files.writeString(f, json);
    AgentConfig cfg = ConfigLoader.load(f.toFile());
    assertEquals(31927, cfg.portOrDefault());
  }
}
