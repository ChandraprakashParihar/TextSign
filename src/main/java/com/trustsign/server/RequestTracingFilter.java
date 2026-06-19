package com.trustsign.server;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Resolves txnId/client IP once per request and stores them in MDC.
 */
public final class RequestTracingFilter extends OncePerRequestFilter {
  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {
    String txnId = RequestTrace.resolveTxnId(request);
    String clientIp = RequestTrace.resolveClientIp(request);
    request.setAttribute(RequestTrace.TXN_ID_REQUEST_ATTR, txnId);
    request.setAttribute(RequestTrace.CLIENT_IP_REQUEST_ATTR, clientIp);
    response.setHeader(RequestTrace.TXN_ID_HEADER, txnId);
    MDC.put(RequestTrace.TXN_ID_MDC_KEY, txnId);
    MDC.put(RequestTrace.CLIENT_IP_MDC_KEY, clientIp);
    try {
      filterChain.doFilter(request, response);
    } finally {
      MDC.remove(RequestTrace.TXN_ID_MDC_KEY);
      MDC.remove(RequestTrace.CLIENT_IP_MDC_KEY);
    }
  }
}
