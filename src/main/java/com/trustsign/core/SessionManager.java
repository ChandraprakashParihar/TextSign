package com.trustsign.core;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class SessionManager {
  private static final SecureRandom RNG = new SecureRandom();
  private final Map<String, Instant> sessions = new ConcurrentHashMap<>();

  public record Session(String token, Instant expiresAt) {}

  public Session createSessionMinutes(int minutes) {
    purgeExpired();
    if (sessions.size() >= maxSessions()) {
      throw new SecurityException("Session capacity reached");
    }
    String token = randomToken(32);
    Instant exp = Instant.now().plusSeconds(minutes * 60L);
    sessions.put(token, exp);
    return new Session(token, exp);
  }

  public void requireValid(String token) {
    if (token == null || token.isBlank()) throw new SecurityException("Missing X-Session-Token");
    Instant exp = sessions.get(token);
    if (exp == null) throw new SecurityException("Invalid session token");
    if (Instant.now().isAfter(exp)) {
      sessions.remove(token);
      throw new SecurityException("Session expired");
    }
  }

  private void purgeExpired() {
    Instant now = Instant.now();
    sessions.entrySet().removeIf(e -> now.isAfter(e.getValue()));
  }

  private static int maxSessions() {
    int configured = Integer.getInteger("trustsign.maxSessions", 10_000);
    return Math.max(configured, 1);
  }

  private static String randomToken(int bytes) {
    byte[] b = new byte[bytes];
    RNG.nextBytes(b);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }
}

