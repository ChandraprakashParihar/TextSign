package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.ConfigLoader;
import com.trustsign.core.Pkcs11Token;
import com.trustsign.core.OsPkcs11Resolver;
import com.trustsign.core.SessionManager;
import com.trustsign.core.TextSignerService;
import com.trustsign.core.TextVerifyService;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.swing.JPasswordField;
import javax.swing.JOptionPane;
import com.fasterxml.jackson.databind.JsonNode;

import java.awt.GraphicsEnvironment;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public final class ApiServlet extends HttpServlet {
  private final SessionManager sessions;

  public ApiServlet(SessionManager sessions) {
    this.sessions = sessions;
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String path = normPath(req.getPathInfo());

    try {
      switch (path) {
        case "/health" -> {
          writeJson(resp, 200, Map.of("status", "ok", "ts", Instant.now().toString()));
          return;
        }
           case "/certificates" -> {
          requireSession(req);

          AgentConfig cfg = ConfigLoader.load(resolveConfigFile());
          List<String> libs = OsPkcs11Resolver.candidates(cfg);
          if (libs.isEmpty()) {
            writeJson(resp, 400, Map.of("error", "No PKCS#11 libraries configured for this OS"));
            return;
          }

          char[] pin = promptPin();
          Pkcs11Token.Loaded loaded;
          try {
            loaded = Pkcs11Token.load(pin, libs);
          } catch (RuntimeException e) {
            String detail = buildTokenErrorDetail(e);
            writeJson(resp, 400, Map.of(
                "error", "Token load failed",
                "details", detail
            ));
            return;
          }

          var certs = Pkcs11Token.listCertificates(loaded.keyStore());

          writeJson(resp, 200, Map.of(
              "libraryPath", loaded.libraryPath(),
              "certCount", certs.size(),
              "certificates", certs
          ));
          return;
        }
        default -> {
          writeJson(resp, 404, Map.of("error", "Not found"));
          return;
        }
      }
    } catch (SecurityException se) {
      writeJson(resp, 403, Map.of("error", se.getMessage()));
    } catch (Exception e) {
      writeJson(resp, 500, Map.of("error", "Internal error", "details", safeMsg(e)));
    }
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String path = normPath(req.getPathInfo());

    try {
      switch (path) {
        case "/session" -> {
          SessionManager.Session s = sessions.createSessionMinutes(10);
          writeJson(resp, 200, Map.of("token", s.token(), "expiresAt", s.expiresAt().toString()));
          return;
        }

        case "/sign-text" -> {
          requireSession(req);

          var mp = Multipart.read(req, 2 * 1024 * 1024); // 2 MB text payload max
          byte[] data = mp.file("file");
          String alias = mp.field("alias");

          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("error", "Missing text file field: file"));
            return;
          }
          if (alias == null || alias.isBlank()) {
            writeJson(resp, 400, Map.of("error", "Missing alias field: alias"));
            return;
          }

          char[] pin = promptPin();

          AgentConfig cfg = ConfigLoader.load(resolveConfigFile());
          List<String> libs = resolvePkcs11Libraries(cfg);
          if (libs.isEmpty()) {
            writeJson(resp, 400, Map.of("error", "No PKCS#11 libraries configured for this OS"));
            return;
          }

          Pkcs11Token.Loaded loaded;
          try {
            loaded = Pkcs11Token.load(pin, libs);
          } catch (RuntimeException e) {
            String detail = buildTokenErrorDetail(e);
            writeJson(resp, 400, Map.of(
                "error", "Token load failed",
                "details", detail
            ));
            return;
          }

          KeyStore ks = loaded.keyStore();
          PrivateKey key = (PrivateKey) ks.getKey(alias, pin);
          Certificate[] chain = ks.getCertificateChain(alias);

          if (key == null || chain == null || chain.length == 0) {
            writeJson(resp, 400, Map.of("error", "No key/certificate chain found for alias: " + alias));
            return;
          }

          byte[] signature = TextSignerService.signDetached(data, key, chain, loaded.provider());

          String originalText = new String(data, java.nio.charset.StandardCharsets.UTF_8);
          String sigB64 = Base64.getEncoder().encodeToString(signature);

          X509Certificate signingCert = null;
          if (chain[0] instanceof X509Certificate x509) {
            signingCert = x509;
          }
          String certB64 = signingCert != null
              ? Base64.getEncoder().encodeToString(signingCert.getEncoded())
              : "";

          StringBuilder sb = new StringBuilder();
          sb.append(originalText);
          if (!originalText.endsWith("\n")) {
            sb.append("\n");
          }
          sb.append("<START-SIGNATURE>").append(sigB64).append("</START-SIGNATURE>\n");
          sb.append("<START-CERTIFICATE>").append(certB64).append("</START-CERTIFICATE>\n");
          sb.append("<SIGNER-VERSION>V-NCODE_01.05.2013</SIGNER-VERSION>\n");

          resp.setStatus(200);
          resp.setContentType("text/plain; charset=UTF-8");
          String filename = mp.filename("file");
          if (filename == null || filename.isBlank()) filename = "text";
          resp.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
          resp.getOutputStream().write(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
          return;
        }

        case "/verify-text" -> {
          var mp = Multipart.read(req, 2 * 1024 * 1024);
          byte[] data = mp.file("file");
          if (data == null || data.length == 0) {
            writeJson(resp, 400, Map.of("ok", false, "reason", "Missing text file field: file"));
            return;
          }
          String signed = new String(data, java.nio.charset.StandardCharsets.UTF_8);
          TextVerifyService.Result result = TextVerifyService.verify(signed);
          writeJson(resp, 200, Map.of("ok", result.ok(), "reason", result.reason()));
          return;
        }

        default -> {
          writeJson(resp, 404, Map.of("error", "Not found"));
          return;
        }
      }
    } catch (SecurityException se) {
      writeJson(resp, 403, Map.of("error", se.getMessage()));
    } catch (Exception e) {
      writeJson(resp, 500, Map.of("error", "Internal error", "details", safeMsg(e)));
    }
  }

  private void requireSession(HttpServletRequest req) {
    String token = req.getHeader("X-Session-Token");
    sessions.requireValid(token);
  }

  private static String normPath(String pathInfo) {
    if (pathInfo == null || pathInfo.isBlank()) return "";
    return pathInfo.startsWith("/") ? pathInfo : "/" + pathInfo;
  }

  private void writeJson(HttpServletResponse resp, int status, Object body) throws IOException {
    resp.setStatus(status);
    resp.setContentType("application/json");
    Json.MAPPER.writeValue(resp.getOutputStream(), body);
  }

  private char[] promptPin() {
    if (GraphicsEnvironment.isHeadless()) {
      Console console = System.console();
      if (console != null) {
        char[] pin = console.readPassword("Enter token PIN: ");
        if (pin == null || pin.length == 0) throw new SecurityException("Empty PIN not allowed");
        return pin;
      }
      System.out.print("Enter token PIN: ");
      System.out.flush();
      try {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = System.in.read()) != '\n' && c != '\r' && c != -1) {
          if (c != '\n' && c != '\r') sb.append((char) c);
        }
        String pinStr = sb.toString().trim();
        if (pinStr.isEmpty()) throw new SecurityException("Empty PIN not allowed");
        return pinStr.toCharArray();
      } catch (IOException e) {
        throw new SecurityException("Failed to read PIN from console", e);
      }
    }

    JPasswordField pf = new JPasswordField();
    int ok = JOptionPane.showConfirmDialog(
        null,
        new Object[]{"Enter token PIN:", pf},
        "TrustSign - Token PIN",
        JOptionPane.OK_CANCEL_OPTION,
        JOptionPane.PLAIN_MESSAGE
    );
    if (ok != JOptionPane.OK_OPTION) throw new SecurityException("PIN entry cancelled");
    char[] pin = pf.getPassword();
    if (pin == null || pin.length == 0) throw new SecurityException("Empty PIN not allowed");
    return pin;
  }

  private File resolveConfigFile() {
    File f1 = new File("config/config.json");
    if (f1.exists()) return f1;
    File f2 = new File("../config/config.json");
    if (f2.exists()) return f2;
    return f1;
  }

  private static List<String> resolvePkcs11Libraries(AgentConfig cfg) throws IOException {
    AgentConfig.Pkcs11Config pkcs = cfg.pkcs11();
    if (pkcs == null) return List.of();

    if (pkcs.preferredLibrary() != null && !pkcs.preferredLibrary().isBlank()) {
      return List.of(pkcs.preferredLibrary());
    }

    String os = System.getProperty("os.name", "").toLowerCase();
    if (os.contains("win")) {
      return pkcs.windowsCandidates() != null ? pkcs.windowsCandidates() : List.of();
    } else if (os.contains("mac")) {
      return pkcs.macCandidates() != null ? pkcs.macCandidates() : List.of();
    } else {
      return pkcs.linuxCandidates() != null ? pkcs.linuxCandidates() : List.of();
    }
  }

  private String safeMsg(Exception e) {
    String msg = e.getMessage();
    if (msg == null || msg.isBlank()) return e.getClass().getSimpleName();
    if (msg.length() > 300) return msg.substring(0, 300);
    return msg;
  }

  private static String buildTokenErrorDetail(RuntimeException e) {
    Throwable t = e;
    String msg = null;
    while (t != null) {
      msg = t.getMessage();
      if (msg != null && !msg.isBlank()) break;
      t = t.getCause();
    }
    if (msg != null && !msg.isBlank()) {
      if (msg.length() > 400) return msg.substring(0, 400);
      return msg;
    }
    return "Connect your PKCS#11 token, check the library path and PIN, and try again.";
  }
}

