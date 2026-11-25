package com.trustsign.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RequestTraceTest {

  @Test
  void keepsOrdinaryIdsUnchanged() {
    assertEquals("order-123_A.b:9", RequestTrace.normalizeTxnId("  order-123_A.b:9 "));
    assertEquals("abc", RequestTrace.normalizeTxnId("\"abc\""));
  }

  @Test
  void stripsLineBreaksAndControlCharacters() {
    String cleaned = RequestTrace.normalizeTxnId("abc\r\nINFO forged log line\u0000");
    assertFalse(cleaned.contains("\n"));
    assertFalse(cleaned.contains("\r"));
    assertFalse(cleaned.contains(" "));
    assertTrue(cleaned.startsWith("abc"));
  }

  @Test
  void capsLengthAndFallsBackToGeneratedId() {
    assertEquals(128, RequestTrace.normalizeTxnId("a".repeat(5000)).length());
    assertEquals(32, RequestTrace.normalizeTxnId("\r\n\t").length());
  }
}
