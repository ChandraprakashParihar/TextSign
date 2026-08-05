package com.trustsign.core;

import com.trustsign.testutil.TestKeyMaterial;
import org.junit.jupiter.api.Test;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PfxKeyMaterialTest {

  private static Path buildPfxFile(TestKeyMaterial.Material material, String alias, char[] password) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    ks.setKeyEntry(alias, material.privateKey(), password, new Certificate[] { material.certificate() });

    Path pfxFile = Files.createTempFile("trustsign-test-", ".pfx");
    try (FileOutputStream out = new FileOutputStream(pfxFile.toFile())) {
      ks.store(out, password);
    }
    return pfxFile;
  }

  @Test
  void load_succeedsWithCorrectPassword() throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("PFX Test Signer");
    char[] password = "correct-horse".toCharArray();
    Path pfxFile = buildPfxFile(material, "signer", password);
    try {
      PfxKeyMaterial.Loaded loaded = PfxKeyMaterial.load(pfxFile.toString(), password);
      assertEquals("SunRsaSign", loaded.provider().getName());

      boolean found = false;
      var aliases = loaded.keyStore().aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (loaded.keyStore().isKeyEntry(alias)) {
          X509Certificate cert = (X509Certificate) loaded.keyStore().getCertificate(alias);
          assertArrayEquals(material.certificate().getEncoded(), cert.getEncoded());
          found = true;
        }
      }
      assertTrue(found, "expected a key entry in the loaded PKCS12 keystore");
    } finally {
      Files.deleteIfExists(pfxFile);
    }
  }

  @Test
  void load_rejectsWrongPassword() throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("PFX Wrong Password Test");
    Path pfxFile = buildPfxFile(material, "signer", "the-real-password".toCharArray());
    try {
      assertThrows(IllegalArgumentException.class,
          () -> PfxKeyMaterial.load(pfxFile.toString(), "totally-wrong".toCharArray()));
    } finally {
      Files.deleteIfExists(pfxFile);
    }
  }

  @Test
  void load_rejectsMissingFile() {
    assertThrows(IllegalArgumentException.class,
        () -> PfxKeyMaterial.load("/nonexistent/path/does-not-exist.pfx", "whatever".toCharArray()));
  }

  @Test
  void load_rejectsBlankPath() {
    assertThrows(IllegalArgumentException.class, () -> PfxKeyMaterial.load("", "whatever".toCharArray()));
    assertThrows(IllegalArgumentException.class, () -> PfxKeyMaterial.load(null, "whatever".toCharArray()));
  }

  @Test
  void load_rejectsCorruptFile() throws Exception {
    Path notAPfx = Files.createTempFile("trustsign-test-corrupt-", ".pfx");
    try {
      Files.writeString(notAPfx, "this is not a PKCS12 file");
      assertThrows(IllegalArgumentException.class,
          () -> PfxKeyMaterial.load(notAPfx.toString(), "whatever".toCharArray()));
    } finally {
      Files.deleteIfExists(notAPfx);
    }
  }

  /**
   * Confirms a PFX-sourced key works as a genuine drop-in for a PKCS#11
   * token's (KeyStore, Provider) pair — the whole point of {@link PfxKeyMaterial}
   * matching {@link Pkcs11Token.Loaded}'s shape. Unlike a PKCS#11 key, this
   * needs none of OoxmlSignerService's SunRsaSign-shimming workaround, since
   * a PKCS12 key is fully extractable and directly usable by "SunRsaSign".
   */
  @Test
  void loadedCredentials_signOoxmlDocumentEndToEnd() throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("PFX End To End Signer");
    char[] password = "e2e-password".toCharArray();
    Path pfxFile = buildPfxFile(material, "signer", password);
    try {
      PfxKeyMaterial.Loaded loaded = PfxKeyMaterial.load(pfxFile.toString(), password);

      try (var wb = new org.apache.poi.xssf.usermodel.XSSFWorkbook()) {
        var sheet = wb.createSheet("Sheet1");
        sheet.createRow(0).createCell(0).setCellValue("hello from pfx");
        var out = new java.io.ByteArrayOutputStream();
        wb.write(out);

        byte[] signed = OoxmlSignerService.sign(
            out.toByteArray(), OoxmlSignerService.OoxmlFormat.XLSX,
            material.privateKey(), new Certificate[] { material.certificate() }, loaded.provider());

        OoxmlVerifyService.Result result = OoxmlVerifyService.verify(signed);
        assertTrue(result.ok(), () -> "expected verification to succeed: " + result.reason());
      }
    } finally {
      Files.deleteIfExists(pfxFile);
    }
  }
}
