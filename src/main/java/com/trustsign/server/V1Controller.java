package com.trustsign.server;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/v1")
public class V1Controller {
  private final ApiServlet api;

  public V1Controller(ApiServlet api) {
    this.api = api;
  }

  @GetMapping("/health")
  public void health(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/health");
  }

  @GetMapping("/health/tsa")
  public void healthTsa(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/health/tsa");
  }

  @GetMapping("/health/ltv")
  public void healthLtv(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/health/ltv");
  }

  @GetMapping("/pkcs11/candidates")
  public void pkcs11Candidates(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/pkcs11/candidates");
  }

  @GetMapping("/certificates")
  public void certificates(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/certificates");
  }

  @PostMapping("/session")
  public void session(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/session");
  }

  @PostMapping("/auto-sign-text")
  public void autoSignText(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-text");
  }

  @PostMapping("/auto-sign-pdf")
  public void autoSignPdf(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-pdf");
  }

  @PostMapping("/auto-sign-text-cms")
  public void autoSignTextCms(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-text-cms");
  }

  @PostMapping("/sign-pdf")
  public void signPdf(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/sign-pdf");
  }

  @PostMapping("/hsm/sign-pdf")
  public void hsmSignPdf(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/hsm/sign-pdf");
  }

  @PostMapping("/hsm/auto-sign-pdf")
  public void hsmAutoSignPdf(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/hsm/auto-sign-pdf");
  }

  @PostMapping("/verify-pdf")
  public void verifyPdf(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/verify-pdf");
  }

  @PostMapping("/debug/pdf-ltv")
  public void debugPdfLtv(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/debug/pdf-ltv");
  }

  @PostMapping("/sign-text")
  public void signText(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/sign-text");
  }

  @PostMapping("/verify-text")
  public void verifyText(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/verify-text");
  }

  @PostMapping("/debug-bytes")
  public void debugBytes(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/debug-bytes");
  }

  @PostMapping("/analyze-signed-file")
  public void analyzeSignedFile(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/analyze-signed-file");
  }
}

