package com.trustsign.server;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;

import java.net.InetAddress;
import java.util.UUID;

/**
 * Shared request trace keys and helpers (txnId + client IP).
 */
public final class RequestTrace {
  public static final String TXN_ID_HEADER = "X-Txn-Id";
  public static final String TXN_ID_MDC_KEY = "txnId";
  public static final String CLIENT_IP_MDC_KEY = "clientIp";
  public static final String TXN_ID_REQUEST_ATTR = "trustsign.txnId";
  public static final String CLIENT_IP_REQUEST_ATTR = "trustsign.clientIp";

  public static String resolveTxnId(HttpServletRequest req) {
    if (req != null) {
      String header = req.getHeader(TXN_ID_HEADER);
      if (header != null && !header.isBlank()) {
        return normalizeTxnId(header);
      }
      String param = req.getParameter("txnId");
      if (param != null && !param.isBlank()) {
        return normalizeTxnId(param);
      }
    }
    return UUID.randomUUID().toString().replace("-", "");
  }

  private static final int MAX_TXN_ID_LENGTH = 128;

  /**
   * Client-supplied txnIds are echoed into a response header, the JSON body and every log line,
   * so they are restricted to a conservative character set and length. Anything else (CR/LF,
   * control characters, quotes) is dropped to prevent log forging / header injection.
   */
  static String normalizeTxnId(String raw) {
    String v = raw == null ? "" : raw.trim();
    if (v.length() >= 2) {
      if ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.substring(1, v.length() - 1).trim();
      }
    }
    StringBuilder sb = new StringBuilder(Math.min(v.length(), MAX_TXN_ID_LENGTH));
    for (int i = 0; i < v.length() && sb.length() < MAX_TXN_ID_LENGTH; i++) {
      char c = v.charAt(i);
      boolean safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
          || c == '-' || c == '_' || c == '.' || c == ':';
      if (safe) {
        sb.append(c);
      }
    }
    return sb.length() == 0 ? UUID.randomUUID().toString().replace("-", "") : sb.toString();
  }

  public static String resolveClientIp(HttpServletRequest req) {
    if (req == null) {
      return "";
    }
    String remote = req.getRemoteAddr();
    // Only trust X-Forwarded-For when the direct TCP connection comes from a
    // loopback or RFC-1918 private address (i.e. a trusted reverse proxy).
    // Accepting it from arbitrary remotes lets any client spoof their IP and
    // bypass per-IP rate limits.
    if (isPrivateOrLoopback(remote)) {
      String xff = req.getHeader("X-Forwarded-For");
      if (xff != null && !xff.isBlank()) {
        int comma = xff.indexOf(',');
        String first = (comma >= 0 ? xff.substring(0, comma) : xff).trim();
        if (!first.isBlank()) {
          return first;
        }
      }
    }
    return remote == null ? "" : remote;
  }

  private static boolean isPrivateOrLoopback(String addr) {
    if (addr == null || addr.isBlank()) {
      return false;
    }
    try {
      InetAddress ia = InetAddress.getByName(addr);
      return ia.isLoopbackAddress() || ia.isSiteLocalAddress();
    } catch (Exception e) {
      return false;
    }
  }

  public static String currentTxnId() {
    return MDC.get(TXN_ID_MDC_KEY);
  }

  private RequestTrace() {
  }
}
