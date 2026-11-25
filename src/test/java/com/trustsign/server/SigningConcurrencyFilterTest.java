package com.trustsign.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.trustsign.core.AgentConfig;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class SigningConcurrencyFilterTest {

  private static AgentConfig.ServerConfig serverConfig(int maxConcurrent, long acquireTimeoutMs) {
    return new AgentConfig.ServerConfig(
        null, null, null, null, null, null, null, maxConcurrent, acquireTimeoutMs,
        null, null, null, null, null, null, null, null, null);
  }

  /** Mirrors what Tomcat reports under Spring Boot: DispatcherServlet on "/", so pathInfo is null. */
  private static MockHttpServletRequest springStyleRequest(String method, String uri) {
    MockHttpServletRequest req = new MockHttpServletRequest(method, uri);
    req.setServletPath(uri);
    req.setPathInfo(null);
    return req;
  }

  @Test
  void resolvesApiPathFromRequestUriWhenPathInfoIsNull() {
    assertEquals("/sign-pdf", SigningConcurrencyFilter.pathInfo(springStyleRequest("POST", "/pki/sign-pdf")));
    assertEquals("/hsm/sign-pdf", SigningConcurrencyFilter.pathInfo(springStyleRequest("POST", "/pki/hsm/sign-pdf")));
    assertEquals("/sign-pdf", SigningConcurrencyFilter.pathInfo(springStyleRequest("POST", "/pki/sign-pdf/")));
    assertEquals("/sign-pdf", SigningConcurrencyFilter.pathInfo(springStyleRequest("POST", "/pki/sign-pdf;x=1")));

    MockHttpServletRequest withContext = springStyleRequest("POST", "/app/pki/sign-pdf");
    withContext.setContextPath("/app");
    assertEquals("/sign-pdf", SigningConcurrencyFilter.pathInfo(withContext));
  }

  @Test
  void signingRequestHoldsPermitWhileHandlerRuns() throws Exception {
    AgentConfig.ServerConfig cfg = serverConfig(1, 0);
    SigningConcurrencyGate gate = SigningConcurrencyGate.create(cfg);
    SigningConcurrencyFilter filter = new SigningConcurrencyFilter(gate, cfg);
    AtomicInteger availableInsideHandler = new AtomicInteger(-1);

    filter.doFilter(
        springStyleRequest("POST", "/pki/sign-pdf"),
        new MockHttpServletResponse(),
        (req, res) -> availableInsideHandler.set(gate.availablePermits()));

    assertEquals(0, availableInsideHandler.get(), "permit must be held during the handler");
    assertEquals(1, gate.availablePermits(), "permit must be released afterwards");
  }

  @Test
  void rejectsWith503WhenNoCapacity() throws Exception {
    AgentConfig.ServerConfig cfg = serverConfig(1, 0);
    SigningConcurrencyGate gate = SigningConcurrencyGate.create(cfg);
    SigningConcurrencyFilter filter = new SigningConcurrencyFilter(gate, cfg);
    AtomicBoolean handlerRan = new AtomicBoolean();

    try (AutoCloseable held = gate.enter(0)) {
      MockHttpServletResponse res = new MockHttpServletResponse();
      filter.doFilter(springStyleRequest("POST", "/pki/auto-sign-pdf"), res, (rq, rs) -> handlerRan.set(true));

      assertEquals(503, res.getStatus());
      assertFalse(handlerRan.get());
      assertTrue(res.getContentAsString().contains("\"status\":false"));
      assertEquals("5", res.getHeader("Retry-After"));
    }
    assertEquals(1, gate.availablePermits());
  }

  @Test
  void nonSigningRequestsBypassTheGate() throws Exception {
    AgentConfig.ServerConfig cfg = serverConfig(1, 0);
    SigningConcurrencyGate gate = SigningConcurrencyGate.create(cfg);
    SigningConcurrencyFilter filter = new SigningConcurrencyFilter(gate, cfg);

    try (AutoCloseable held = gate.enter(0)) {
      MockHttpServletResponse res = new MockHttpServletResponse();
      MockFilterChain chain = new MockFilterChain();
      filter.doFilter(springStyleRequest("GET", "/pki/health"), res, chain);
      assertEquals(200, res.getStatus());
      assertTrue(chain.getRequest() != null, "health check must pass through even when saturated");
    }
  }
}
