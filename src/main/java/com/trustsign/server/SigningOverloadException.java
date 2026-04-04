package com.trustsign.server;

/** Thrown when the signing concurrency gate cannot grant a permit within the configured wait time. */
public final class SigningOverloadException extends RuntimeException {

  public SigningOverloadException(String message) {
    super(message);
  }
}
