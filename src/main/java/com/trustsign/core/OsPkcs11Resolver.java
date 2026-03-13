package com.trustsign.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class OsPkcs11Resolver {

  public enum Os { WINDOWS, MAC, LINUX, OTHER }

  private static final Pattern WINDOWS_ENV_VAR = Pattern.compile("%([^%]+)%");

  public static Os current() {
    String os = System.getProperty("os.name", "").toLowerCase();
    if (os.contains("win")) return Os.WINDOWS;
    if (os.contains("mac")) return Os.MAC;
    if (os.contains("nux") || os.contains("nix")) return Os.LINUX;
    return Os.OTHER;
  }

  /**
   * Expands Windows environment variables in a path (e.g. %ProgramFiles% → C:\Program Files).
   * No-op on non-Windows or when the string contains no %VAR% patterns.
   */
  public static String expandWindowsPath(String path) {
    if (path == null || path.isBlank() || current() != Os.WINDOWS) return path;
    Matcher m = WINDOWS_ENV_VAR.matcher(path);
    StringBuffer sb = new StringBuffer();
    while (m.find()) {
      String varName = m.group(1);
      String value = System.getenv(varName);
      m.appendReplacement(sb, value == null ? m.group(0) : value.replace("\\", "\\\\"));
    }
    m.appendTail(sb);
    return sb.toString();
  }

  public static List<String> candidates(AgentConfig cfg) {
    var out = new ArrayList<String>();
    var p = cfg.pkcs11();

    if (p.preferredLibrary() != null && !p.preferredLibrary().isBlank()) {
      out.add(expandWindowsPath(p.preferredLibrary().trim()));
    }

    switch (current()) {
      case WINDOWS -> nullToEmpty(p.windowsCandidates()).stream()
          .map(String::trim)
          .filter(s -> !s.isBlank())
          .map(OsPkcs11Resolver::expandWindowsPath)
          .forEach(out::add);
      case MAC -> out.addAll(nullToEmpty(p.macCandidates()));
      case LINUX -> out.addAll(nullToEmpty(p.linuxCandidates()));
      default -> {}
    }

    return out.stream()
        .filter(Objects::nonNull)
        .map(String::trim)
        .filter(s -> !s.isBlank())
        .distinct()
        .toList();
  }

  private static List<String> nullToEmpty(List<String> list) {
    return list == null ? List.of() : list;
  }

  private OsPkcs11Resolver() {}
}
