package com.trustsign.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class OsPkcs11Resolver {

  public enum Os { WINDOWS, MAC, LINUX, OTHER }

  public static Os current() {
    String os = System.getProperty("os.name", "").toLowerCase();
    if (os.contains("win")) return Os.WINDOWS;
    if (os.contains("mac")) return Os.MAC;
    if (os.contains("nux") || os.contains("nix")) return Os.LINUX;
    return Os.OTHER;
  }

  public static List<String> candidates(AgentConfig cfg) {
    var out = new ArrayList<String>();
    var p = cfg.pkcs11();

    if (p.preferredLibrary() != null && !p.preferredLibrary().isBlank()) out.add(p.preferredLibrary());

    switch (current()) {
      case WINDOWS -> out.addAll(nullToEmpty(p.windowsCandidates()));
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
