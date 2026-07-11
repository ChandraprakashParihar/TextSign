package com.trustsign.server;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Answers Chrome's Private Network Access preflight so pages served from a
 * public HTTPS origin (e.g. a website with an embedded signing form) can call
 * this loopback service. Access-Control-Request-Private-Network /
 * Access-Control-Allow-Private-Network is a Chrome-only extension to the
 * Fetch spec, not part of standard CORS, so Spring's built-in CORS support
 * (configured in SpringServerConfig) has no notion of it — without this
 * filter, the preflight is rejected before Spring's own CORS handling runs,
 * even when allowedOrigins already lists the caller's origin.
 */
public final class PrivateNetworkAccessFilter extends OncePerRequestFilter {
  private static final String REQUEST_HEADER = "Access-Control-Request-Private-Network";
  private static final String RESPONSE_HEADER = "Access-Control-Allow-Private-Network";

  private final List<String> allowedOrigins;

  public PrivateNetworkAccessFilter(List<String> allowedOrigins) {
    this.allowedOrigins = allowedOrigins == null ? List.of() : allowedOrigins;
  }

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {
    if ("OPTIONS".equalsIgnoreCase(request.getMethod())
        && "true".equalsIgnoreCase(request.getHeader(REQUEST_HEADER))) {
      String origin = request.getHeader("Origin");
      if (origin != null && allowedOrigins.contains(origin)) {
        response.setHeader(RESPONSE_HEADER, "true");
      }
    }
    filterChain.doFilter(request, response);
  }
}
