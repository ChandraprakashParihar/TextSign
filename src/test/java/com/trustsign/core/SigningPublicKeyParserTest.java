package com.trustsign.core;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SigningPublicKeyParserTest {

  @Test
  void parsesPemPublicKeyFile() throws Exception {
    Path pem = Path.of("config/public-key.pem");
    if (!Files.isRegularFile(pem)) {
      pem = Path.of("../config/public-key.pem");
    }
    if (!Files.isRegularFile(pem)) {
      // Repo may not ship the file in all environments
      return;
    }
    String text = Files.readString(pem);
    List<PublicKey> keys = SigningPublicKeyParser.parsePublicKeys(text);
    assertFalse(keys.isEmpty());
    assertEquals("RSA", keys.get(0).getAlgorithm());
  }
}
