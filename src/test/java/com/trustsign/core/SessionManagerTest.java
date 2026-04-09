package com.trustsign.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SessionManagerTest {

  @Test
  void createSessionReturnsTokenAndExpiry() {
    SessionManager mgr = new SessionManager();
    SessionManager.Session s = mgr.createSessionMinutes(10);
    assertNotNull(s.token());
    assertFalse(s.token().isBlank());
    assertNotNull(s.expiresAt());
  }

  @Test
  void requireValidThrowsWhenTokenNull() {
    SessionManager mgr = new SessionManager();
    assertThrows(SecurityException.class, () -> mgr.requireValid(null));
  }

  @Test
  void requireValidThrowsWhenTokenBlank() {
    SessionManager mgr = new SessionManager();
    assertThrows(SecurityException.class, () -> mgr.requireValid("   "));
  }

  @Test
  void requireValidThrowsWhenTokenUnknown() {
    SessionManager mgr = new SessionManager();
    assertThrows(SecurityException.class, () -> mgr.requireValid("unknown-token"));
  }

  @Test
  void requireValidSucceedsForValidToken() {
    SessionManager mgr = new SessionManager();
    SessionManager.Session s = mgr.createSessionMinutes(10);
    assertDoesNotThrow(() -> mgr.requireValid(s.token()));
  }

  @Test
  void createSessionFailsWhenCapacityReached() {
    System.setProperty("trustsign.maxSessions", "1");
    try {
      SessionManager mgr = new SessionManager();
      mgr.createSessionMinutes(10);
      assertThrows(SecurityException.class, () -> mgr.createSessionMinutes(10));
    } finally {
      System.clearProperty("trustsign.maxSessions");
    }
  }
}
