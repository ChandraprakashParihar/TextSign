package com.trustsign.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustsign.core.SignedFileAnalyzer;
import com.trustsign.tools.DiscoverSignedContentFormat;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class TextVerifyServiceTest {

  @Test
  void verifyReturnsFalseForNull() {
    TextVerifyService.Result r = TextVerifyService.verify(null);
    assertFalse(r.ok());
    assertNotNull(r.reason());
  }

  @Test
  void verifyReturnsFalseForEmptyString() {
    TextVerifyService.Result r = TextVerifyService.verify("");
    assertFalse(r.ok());
    assertTrue(r.reason().toLowerCase().contains("empty"));
  }

  @Test
  void verifyReturnsFalseWhenSignatureMarkersMissing() {
    TextVerifyService.Result r = TextVerifyService.verify("just some text\nno signature here");
    assertFalse(r.ok());
    assertTrue(r.reason().toLowerCase().contains("marker") || r.reason().toLowerCase().contains("signature"));
  }

  @Test
  void verifyReturnsFalseWhenSignatureBlockEmpty() {
    String text = "hello\n<START-SIGNATURE></START-SIGNATURE>\n<START-CERTIFICATE>invalid</START-CERTIFICATE>\n";
    TextVerifyService.Result r = TextVerifyService.verify(text);
    assertFalse(r.ok());
  }

  /** Run with -Ddiscover.signed.file=path to see which content Icegate signed. Or uses g:/pki/testncodeSigned.txt if it exists. */
  @Test
  void discoverIcegateFormat() throws Exception {
    String path = System.getProperty("discover.signed.file");
    if (path == null || path.isBlank()) {
      path = "g:/pki/testncodeSigned.txt";
      if (!Files.exists(Paths.get(path))) return;
    }
    System.setProperty("discover.report.path", "build/icegate-discovery.txt");
    byte[] raw = Files.readAllBytes(Paths.get(path));
    String content = new String(raw, StandardCharsets.UTF_8);
    int sigStart = content.indexOf("<START-SIGNATURE>");
    if (sigStart < 0) return;
    byte[] rawBeforeSig = java.util.Arrays.copyOf(raw, sigStart);
    DiscoverSignedContentFormat.discover(content, rawBeforeSig);
  }

  /** Analyzes Icegate signed file via SignedFileAnalyzer and writes JSON to build/icegate-analysis.json. */
  @Test
  void analyzeIcegateSignedFile() throws Exception {
    String path = "g:/pki/testncodeSigned.txt";
    if (!Files.exists(Paths.get(path))) return;
    byte[] raw = Files.readAllBytes(Paths.get(path));
    String signedText = new String(raw, StandardCharsets.UTF_8);
    int sigStart = signedText.indexOf("<START-SIGNATURE>");
    byte[] rawBeforeSig = sigStart > 0 ? java.util.Arrays.copyOf(raw, sigStart) : new byte[0];
    SignedFileAnalyzer.Result result = SignedFileAnalyzer.analyze(signedText, rawBeforeSig);
    String json = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(result);
    Files.createDirectories(Paths.get("build"));
    Files.writeString(Paths.get("build/icegate-analysis.json"), json, StandardCharsets.UTF_8);
  }
}
