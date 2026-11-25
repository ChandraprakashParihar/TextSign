package com.trustsign.core;

import java.io.IOException;
import java.io.InputStream;

/**
 * Size-capped reads for responses from remote servers (OCSP, CRL, TSA).
 * Those endpoints are named by certificate extensions or config and are
 * reached over plain HTTP, so an unbounded {@code readAllBytes()} lets a
 * misbehaving or spoofed responder exhaust the heap.
 */
final class BoundedIo {

  static byte[] readAtMost(InputStream in, int maxBytes, String what) throws IOException {
    byte[] body = in.readNBytes(maxBytes + 1);
    if (body.length > maxBytes) {
      throw new IOException(what + " response exceeds " + maxBytes + " bytes");
    }
    return body;
  }

  private BoundedIo() {}
}
