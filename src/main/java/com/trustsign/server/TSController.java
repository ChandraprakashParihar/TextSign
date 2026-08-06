package com.trustsign.server;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/pki")
public class TSController {
  private final ApiServlet api;

  public TSController(ApiServlet api) {
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

  @GetMapping("/health/licence")
  public void healthLicence(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/health/licence");
  }

  @GetMapping("/pkcs11/candidates")
  public void pkcs11Candidates(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/pkcs11/candidates");
  }

  @GetMapping("/certificates")
  public void certificates(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/certificates");
  }

  @GetMapping("/logs")
  public void logs(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/logs");
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

  @PostMapping("/auto-sign-pdf-blob")
  public void autoSignPdfBlob(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-pdf-blob");
  }

  @PostMapping("/auto-sign-pdf-at-field")
  public void autoSignPdfAtField(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-pdf-at-field");
  }

  @PostMapping("/auto-sign-pdf-bulk")
  public void autoSignPdfBulk(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-pdf-bulk");
  }

  @PostMapping("/auto-sign-pdf-bulk-pfx")
  public void autoSignPdfBulkPfx(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-pdf-bulk-pfx");
  }

  @GetMapping("/auto-sign-pdf-bulk-status")
  public void autoSignPdfBulkStatus(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handleGet(req, resp, "/auto-sign-pdf-bulk-status");
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

  @PostMapping("/verify-text-cms")
  public void verifyTextCms(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/verify-text-cms");
  }

  @PostMapping("/auto-sign-csv")
  public void autoSignCsv(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-csv");
  }

  @PostMapping("/sign-csv")
  public void signCsv(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/sign-csv");
  }

  @PostMapping("/verify-csv")
  public void verifyCsv(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/verify-csv");
  }

  @PostMapping("/auto-sign-xml")
  public void autoSignXml(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-xml");
  }

  @PostMapping("/sign-xml")
  public void signXml(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/sign-xml");
  }

  @PostMapping("/verify-xml")
  public void verifyXml(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/verify-xml");
  }

  @PostMapping("/auto-sign-excel")
  public void autoSignExcel(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-excel");
  }

  @PostMapping("/sign-excel")
  public void signExcel(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/sign-excel");
  }

  @PostMapping("/verify-excel")
  public void verifyExcel(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/verify-excel");
  }

  @PostMapping("/auto-sign-word")
  public void autoSignWord(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-word");
  }

  @PostMapping("/sign-word")
  public void signWord(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/sign-word");
  }

  @PostMapping("/verify-word")
  public void verifyWord(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/verify-word");
  }

  @PostMapping("/auto-sign-ppt")
  public void autoSignPpt(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/auto-sign-ppt");
  }

  @PostMapping("/sign-ppt")
  public void signPpt(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/sign-ppt");
  }

  @PostMapping("/verify-ppt")
  public void verifyPpt(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/verify-ppt");
  }

  @PostMapping("/validate-token")
  public void validateToken(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/validate-token");
  }

  @PostMapping("/map-certificate")
  public void mapCertificate(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    api.handlePost(req, resp, "/map-certificate");
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
