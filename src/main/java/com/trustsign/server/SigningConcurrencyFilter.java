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
      "/auto-sign-text",
      "/auto-sign-text-cms",
      "/hsm/sign-pdf",
      "/hsm/auto-sign-pdf",
      "/sign-text");

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
      res.setStatus(503);
      res.setContentType("application/json");
      res.getWriter().write("{\"error\":\"Service busy\",\"message\":\"" + escapeJson(e.getMessage()) + "\"}");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      res.setStatus(503);
      res.setContentType("application/json");
      res.getWriter().write("{\"error\":\"Service busy\",\"message\":\"Interrupted while waiting for signing capacity\"}");
    } finally {
      if (permit != null) {
        try {
          permit.close();
        } catch (Exception ignore) {
        }
      }
    }
  }

  private static String pathInfo(HttpServletRequest req) {
    String p = req.getPathInfo();
    if (p == null || p.isBlank()) {
      return "";
    }
    return p.startsWith("/") ? p : "/" + p;
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

  private static String escapeJson(String s) {
    if (s == null) {
      return "";
    }
    return s.replace("\\", "\\\\").replace("\"", "\\\"");
  }
}
