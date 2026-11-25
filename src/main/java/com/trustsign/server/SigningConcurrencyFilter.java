package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Set;

/**
 * Serialises expensive token/signing work behind {@link SigningConcurrencyGate}. Health checks pass through.
 */
public final class SigningConcurrencyFilter extends HttpFilter {

  private static final Set<String> POST_SIGNING_PATHS = Set.of(
      "/sign-pdf",
      "/auto-sign-pdf",
      "/auto-sign-pdf-at-field",
      "/auto-sign-text",
      "/auto-sign-text-cms",
      "/hsm/sign-pdf",
      "/hsm/auto-sign-pdf",
      "/sign-text",
      "/auto-sign-csv",
      "/sign-csv",
      "/auto-sign-xml",
      "/sign-xml",
      "/auto-sign-excel",
      "/sign-excel",
      "/auto-sign-word",
      "/sign-word",
      "/auto-sign-ppt",
      "/sign-ppt",
      "/validate-token");   // also opens PKCS#11 — must be throttled like signing ops

  private static final Set<String> GET_TOKEN_PATHS = Set.of(
      "/certificates",
      "/pkcs11/candidates");

  private final SigningConcurrencyGate gate;
  private final long acquireTimeoutMs;

  public SigningConcurrencyFilter(SigningConcurrencyGate gate, AgentConfig.ServerConfig serverCfg) {
    this.gate = gate;
    this.acquireTimeoutMs = AgentConfig.ServerConfig.signingAcquireTimeoutMsOrDefault(serverCfg);
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    if (!gate.isLimited() || !requiresSlot(req.getMethod(), pathInfo(req))) {
      chain.doFilter(req, res);
      return;
    }
    AutoCloseable permit = null;
    try {
      permit = gate.enter(acquireTimeoutMs);
      chain.doFilter(req, res);
    } catch (SigningOverloadException e) {
      writeBusy(res, e.getMessage());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      writeBusy(res, "Interrupted while waiting for signing capacity");
    } finally {
      if (permit != null) {
        try {
          permit.close();
        } catch (Exception ignore) {
        }
      }
    }
  }

  private static final String API_PREFIX = "/pki";

  /**
   * Path of the request relative to the {@code /pki} API root (e.g. {@code /sign-pdf}).
   *
   * <p>Must be derived from the request URI, not {@code getPathInfo()}: under Spring Boot the
   * DispatcherServlet is mapped to {@code /}, so {@code getPathInfo()} is always {@code null}
   * and every request would silently bypass the gate.
   */
  static String pathInfo(HttpServletRequest req) {
    String uri = req.getRequestURI();
    if (uri == null || uri.isBlank()) {
      return "";
    }
    String ctx = req.getContextPath();
    if (ctx != null && !ctx.isEmpty() && uri.startsWith(ctx)) {
      uri = uri.substring(ctx.length());
    }
    int semi = uri.indexOf(';'); // strip path parameters such as ;jsessionid=...
    if (semi >= 0) {
      uri = uri.substring(0, semi);
    }
    if (uri.equals(API_PREFIX) || uri.startsWith(API_PREFIX + "/")) {
      uri = uri.substring(API_PREFIX.length());
    }
    while (uri.length() > 1 && uri.endsWith("/")) {
      uri = uri.substring(0, uri.length() - 1);
    }
    return uri;
  }

  static boolean requiresSlot(String method, String pathInfo) {
    if (pathInfo == null) {
      return false;
    }
    String m = method == null ? "" : method.toUpperCase();
    if ("POST".equals(m) && POST_SIGNING_PATHS.contains(pathInfo)) {
      return true;
    }
    return "GET".equals(m) && GET_TOKEN_PATHS.contains(pathInfo);
  }

  /** Same response shape as ApiServlet errors ({@code status}/{@code message}/{@code code}), plus Retry-After. */
  private static void writeBusy(HttpServletResponse res, String message) throws IOException {
    if (res.isCommitted()) {
      return;
    }
    res.setStatus(503);
    res.setHeader("Retry-After", "5");
    res.setContentType("application/json");
    res.setCharacterEncoding("UTF-8");
    res.getWriter().write("{\"status\":false,\"message\":\"" + escapeJson(message)
        + "\",\"code\":\"TS_BUSY\"}");
  }

  private static String escapeJson(String s) {
    if (s == null) {
      return "";
    }
    StringBuilder sb = new StringBuilder(s.length() + 8);
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '"' || c == '\\') {
        sb.append('\\').append(c);
      } else if (c < 0x20) {
        sb.append(' ');
      } else {
        sb.append(c);
      }
    }
    return sb.toString();
  }
}
