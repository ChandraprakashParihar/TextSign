package com.trustsign.core;

import org.junit.jupiter.api.Test;

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
}
