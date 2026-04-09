package com.trustsign.server;

import com.trustsign.core.LicenceEnforcer;
import com.trustsign.core.SessionManager;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ApiServletSecurityTest {

  @Test
  void signPdfRequiresSessionToken() throws Exception {
    ApiServlet api = newApiServletWithValidLicence();
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/v1/sign-pdf");
    req.setRemoteAddr("127.0.0.1");
    MockHttpServletResponse resp = new MockHttpServletResponse();

    api.handlePost(req, resp, "/sign-pdf");

    assertEquals(403, resp.getStatus());
    assertTrue(resp.getContentAsString().contains("\"code\":\"TS_FORBIDDEN\""));
  }

  @Test
  void debugBytesIsDisabledByDefault() throws Exception {
    ApiServlet api = newApiServletWithValidLicence();
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/v1/debug-bytes");
    req.setRemoteAddr("127.0.0.1");
    MockHttpServletResponse resp = new MockHttpServletResponse();

    api.handlePost(req, resp, "/debug-bytes");

    assertEquals(404, resp.getStatus());
    assertTrue(resp.getContentAsString().contains("\"code\":\"TS_NOT_FOUND\""));
  }

  @Test
  void sessionEndpointIsRateLimitedPerIp() throws Exception {
    System.setProperty("trustsign.sessionRateLimitPerMinute", "1");
    try {
      ApiServlet api = newApiServletWithValidLicence();
      MockHttpServletRequest req1 = new MockHttpServletRequest("POST", "/v1/session");
      req1.setRemoteAddr("127.0.0.1");
      MockHttpServletResponse resp1 = new MockHttpServletResponse();
      api.handlePost(req1, resp1, "/session");
      assertEquals(200, resp1.getStatus());

      MockHttpServletRequest req2 = new MockHttpServletRequest("POST", "/v1/session");
      req2.setRemoteAddr("127.0.0.1");
      MockHttpServletResponse resp2 = new MockHttpServletResponse();
      api.handlePost(req2, resp2, "/session");
      assertEquals(429, resp2.getStatus());
      assertTrue(resp2.getContentAsString().contains("\"code\":\"TS_RATE_LIMITED\""));
    } finally {
      System.clearProperty("trustsign.sessionRateLimitPerMinute");
    }
  }

  private static ApiServlet newApiServletWithValidLicence() {
    LicenceEnforcer licenceEnforcer = mock(LicenceEnforcer.class);
    when(licenceEnforcer.check()).thenReturn(LicenceEnforcer.Result.allow());
    return new ApiServlet(new SessionManager(), licenceEnforcer, SigningConcurrencyGate.unlimited(), null);
  }
}
