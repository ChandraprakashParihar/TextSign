package com.trustsign.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.trustsign.core.AgentConfig;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Runs the real filter inside real embedded Tomcat with the same registration as
 * {@link SpringServerConfig}. Guards against the filter resolving the request path in a way that
 * only works in mocks (the original bug: {@code getPathInfo()} is null behind DispatcherServlet,
 * so the signing concurrency limit was never applied).
 */
@SpringBootTest(
    classes = SigningConcurrencyFilterTomcatTest.TestApp.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SigningConcurrencyFilterTomcatTest {

  @Configuration
  @EnableAutoConfiguration
  static class TestApp {
    private static final AgentConfig.ServerConfig CFG = new AgentConfig.ServerConfig(
        null, null, null, null, null, null, null, 1, 0L,
        null, null, null, null, null, null, null, null, null);

    @Bean
    SigningConcurrencyGate gate() {
      return SigningConcurrencyGate.create(CFG);
    }

    @Bean
    FilterRegistrationBean<SigningConcurrencyFilter> signingFilter(SigningConcurrencyGate gate) {
      FilterRegistrationBean<SigningConcurrencyFilter> bean =
          new FilterRegistrationBean<>(new SigningConcurrencyFilter(gate, CFG));
      bean.addUrlPatterns("/pki/*");
      return bean;
    }

    @Bean
    StubController stubController() {
      return new StubController();
    }
  }

  @RestController
  @RequestMapping("/pki")
  static class StubController {
    @PostMapping("/sign-pdf")
    String signPdf() {
      return "signed";
    }

    @PostMapping("/verify-pdf")
    String verifyPdf() {
      return "verified";
    }
  }

  @LocalServerPort
  int port;

  @Autowired
  SigningConcurrencyGate gate;

  private int post(String path) throws Exception {
    HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
        .POST(HttpRequest.BodyPublishers.noBody())
        .build();
    return HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString()).statusCode();
  }

  @Test
  void signingEndpointIsGatedOverRealHttp() throws Exception {
    assertEquals(200, post("/pki/sign-pdf"));

    try (AutoCloseable held = gate.enter(0)) {
      assertEquals(503, post("/pki/sign-pdf"), "saturated gate must reject signing requests");
      assertEquals(200, post("/pki/verify-pdf"), "non-signing endpoints are never gated");
    }

    assertEquals(200, post("/pki/sign-pdf"));
  }
}
