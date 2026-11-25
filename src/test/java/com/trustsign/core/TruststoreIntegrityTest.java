package com.trustsign.core;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.trustsign.testutil.TestKeyMaterial;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The truststore tamper check must fail closed: missing, empty and mismatching integrity files all reject. */
class TruststoreIntegrityTest {

  private static final String PASSWORD = "test-pass";
  private static final String[] PROPS = {
      "trustsign.truststore.path", "trustsign.truststore.password", "trustsign.truststore.type"};

  @TempDir
  Path dir;

  private final String[] saved = new String[PROPS.length];
  private Path truststore;
  private Path integrityFile;
  private X509Certificate root;
  private X509Certificate unrelated;

  @BeforeEach
  void setUp() throws Exception {
    for (int i = 0; i < PROPS.length; i++) {
      saved[i] = System.getProperty(PROPS[i]);
    }
    root = TestKeyMaterial.selfSigned("Integrity Test Root").certificate();
    unrelated = TestKeyMaterial.selfSigned("Unrelated").certificate();

    truststore = dir.resolve("truststore.jks");
    integrityFile = dir.resolve(".truststore-integrity");
    writeTruststore(root);

    System.setProperty("trustsign.truststore.path", truststore.toString());
    System.setProperty("trustsign.truststore.password", PASSWORD);
    System.setProperty("trustsign.truststore.type", "PKCS12");
    CertificateValidator.invalidateTrustStoreCache();
  }

  @AfterEach
  void tearDown() {
    for (int i = 0; i < PROPS.length; i++) {
      if (saved[i] == null) {
        System.clearProperty(PROPS[i]);
      } else {
        System.setProperty(PROPS[i], saved[i]);
      }
    }
    CertificateValidator.invalidateTrustStoreCache();
  }

  private void writeTruststore(X509Certificate cert) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, PASSWORD.toCharArray());
    ks.setCertificateEntry("root", cert);
    try (OutputStream out = Files.newOutputStream(truststore)) {
      ks.store(out, PASSWORD.toCharArray());
    }
  }

  /** Any call that needs the truststore; returns the root for its own (self-issued) certificate. */
  private X509Certificate useTruststore() throws Exception {
    return CertificateValidator.findIssuerInConfiguredTruststore(root);
  }

  @Test
  void loadsWhenIntegrityFileMatches() throws Exception {
    CertificateValidator.writeTruststoreHmac(truststore.toFile());
    assertEquals(root, assertDoesNotThrow(this::useTruststore));
  }

  @Test
  void rejectsWhenIntegrityFileIsMissing() {
    SecurityException e = assertThrows(SecurityException.class, this::useTruststore);
    assertTrue(e.getMessage().contains("missing"), e.getMessage());
  }

  @Test
  void rejectsWhenIntegrityFileIsDeletedAfterASuccessfulLoad() throws Exception {
    CertificateValidator.writeTruststoreHmac(truststore.toFile());
    useTruststore();

    // Attacker swaps the truststore and deletes the integrity file to switch the check off.
    Files.delete(integrityFile);
    writeTruststore(unrelated);
    Files.setLastModifiedTime(truststore,
        java.nio.file.attribute.FileTime.fromMillis(System.currentTimeMillis() + 5_000));
    CertificateValidator.invalidateTrustStoreCache();

    assertThrows(SecurityException.class, this::useTruststore);
  }

  @Test
  void rejectsWhenIntegrityFileIsEmpty() throws Exception {
    Files.writeString(integrityFile, "  \n");
    SecurityException e = assertThrows(SecurityException.class, this::useTruststore);
    assertTrue(e.getMessage().contains("empty"), e.getMessage());
  }

  @Test
  void rejectsWhenTruststoreIsModifiedAfterHmacWasWritten() throws Exception {
    CertificateValidator.writeTruststoreHmac(truststore.toFile());
    Files.write(truststore, new byte[] {0}, StandardOpenOption.APPEND);

    SecurityException e = assertThrows(SecurityException.class, this::useTruststore);
    assertTrue(e.getMessage().contains("tampered"), e.getMessage());
  }
}
