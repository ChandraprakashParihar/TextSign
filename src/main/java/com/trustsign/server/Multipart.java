package com.trustsign.server;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Part;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public final class Multipart {

  public record Data(Map<String, byte[]> files, Map<String, String> fields, Map<String, String> fileNames) {
    public byte[] file(String name) { return files.get(name); }
    public String field(String name) { return fields.get(name); }
    public String filename(String name) { return fileNames.get(name); }
  }

  public static Data read(HttpServletRequest req, int maxBytes) throws Exception {
    Map<String, byte[]> files = new HashMap<>();
    Map<String, String> fields = new HashMap<>();
    Map<String, String> fileNames = new HashMap<>();

    for (Part p : req.getParts()) {
      String name = p.getName();
      if (name != null) {
        name = name.trim();
      }
      String submitted = p.getSubmittedFileName();
      // Some clients (e.g. Postman) may send text fields with filename=""
      // which returns non-null submittedFileName. Treat empty filename as a field.
      if (submitted != null && !submitted.isBlank()) {
        files.put(name, readAll(p.getInputStream(), maxBytes));
        fileNames.put(name, submitted);
      } else {
        fields.put(name, new String(readAll(p.getInputStream(), maxBytes), StandardCharsets.UTF_8));
      }
    }
    return new Data(files, fields, fileNames);
  }

  private static byte[] readAll(InputStream in, int maxBytes) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buf = new byte[8192];
    int r;
    int total = 0;
    while ((r = in.read(buf)) != -1) {
      total += r;
      if (total > maxBytes) {
        throw new IllegalStateException("Payload too large (max " + (maxBytes / 1024) + " KB)");
      }
      out.write(buf, 0, r);
    }
    return out.toByteArray();
  }

  private Multipart() {}
}

