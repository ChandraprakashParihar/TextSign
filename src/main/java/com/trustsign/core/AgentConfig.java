package com.trustsign.core;

import java.util.List;

/**
 * Minimal configuration for the standalone text signing backend.
 *
 * Example config.json:
 * {
 *   "port": 31927,
 *   "allowedOrigins": ["http://localhost:3000"],
 *   "pkcs11": {
 *     "preferredLibrary": "/path/to/pkcs11.so",
 *     "windowsCandidates": ["%ProgramFiles%\\\\HyperPKI\\\\bin\\\\pkcs11.dll"],
 *     "macCandidates": [],
 *     "linuxCandidates": []
 *   }
 * }
 * On Windows, preferredLibrary and paths in windowsCandidates can use env vars (e.g. %ProgramFiles%).
 */
public record AgentConfig(
    List<String> allowedOrigins,
    Integer port,
    Pkcs11Config pkcs11
) {

  public record Pkcs11Config(
      String preferredLibrary,
      List<String> windowsCandidates,
      List<String> macCandidates,
      List<String> linuxCandidates
  ) {}

  public int portOrDefault() {
    return (port == null || port <= 0) ? 31927 : port;
  }
}

