package com.trustsign.core;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SigningCertificateParserTest {

  @Test
  void parseFromUploadEmpty() throws Exception {
    assertTrue(SigningCertificateParser.parseFromUpload(null).isEmpty());
    assertTrue(SigningCertificateParser.parseFromUpload(new byte[0]).isEmpty());
  }

  @Test
  void parsesPemCertificateFile() throws Exception {
    Path pem = Path.of("config/public-key.pem");
    if (!Files.isRegularFile(pem)) {
      pem = Path.of("../config/public-key.pem");
    }
    if (!Files.isRegularFile(pem)) {
      return;
    }
    byte[] raw = Files.readAllBytes(pem);
    String text = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
    if (!text.contains("BEGIN CERTIFICATE")) {
      return;
    }
    List<X509Certificate> certs = SigningCertificateParser.parseFromUpload(raw);
    assertFalse(certs.isEmpty());
    assertNotNull(certs.get(0).getSerialNumber());
  }
}
