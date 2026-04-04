package com.trustsign.server;

import com.trustsign.core.AgentConfig;

import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Limits how many expensive PKCS#11 / signing operations run at once so Jetty worker threads are not all blocked on hardware.
 */
public final class SigningConcurrencyGate {

  private final Semaphore semaphore;
  private final int totalPermits;

  private SigningConcurrencyGate(Semaphore semaphore, int totalPermits) {
    this.semaphore = semaphore;
    this.totalPermits = totalPermits;
  }

  public static SigningConcurrencyGate create(AgentConfig.ServerConfig cfg) {
    int max = AgentConfig.ServerConfig.maxConcurrentSigningOrDefault(cfg);
    if (max <= 0) {
      return unlimited();
    }
    return new SigningConcurrencyGate(new Semaphore(max, true), max);
  }

  public static SigningConcurrencyGate unlimited() {
    return new SigningConcurrencyGate(null, 0);
  }

  public boolean isLimited() {
    return semaphore != null;
  }

  public int totalPermits() {
    return totalPermits;
  }

  public int availablePermits() {
    return semaphore == null ? Integer.MAX_VALUE : semaphore.availablePermits();
  }

  /**
   * @param waitMs max time to wait for a permit; non-positive means no waiting (fail immediately if busy)
   */
  public AutoCloseable enter(long waitMs) throws InterruptedException {
    if (semaphore == null) {
      return NOOP_CLOSEABLE;
    }
    long ms = waitMs <= 0 ? 0 : waitMs;
    boolean ok = ms == 0 ? semaphore.tryAcquire() : semaphore.tryAcquire(ms, TimeUnit.MILLISECONDS);
    if (!ok) {
      throw new SigningOverloadException("Too many concurrent signing or token operations. Retry shortly.");
    }
    return () -> semaphore.release();
  }

  private static final AutoCloseable NOOP_CLOSEABLE = () -> {};
}
