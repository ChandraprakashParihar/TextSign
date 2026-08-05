package com.trustsign.core;

import com.trustsign.testutil.TestKeyMaterial;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExcelSignerServiceTest {

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static byte[] buildTestWorkbook() throws Exception {
    try (XSSFWorkbook wb = new XSSFWorkbook()) {
      XSSFSheet sheet = wb.createSheet("Sheet1");
      Row row = sheet.createRow(0);
      Cell cell = row.createCell(0);
      cell.setCellValue("hello, signed workbook");
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      wb.write(out);
      return out.toByteArray();
    }
  }

  @Test
  void signAndVerifyRoundTrip_succeeds() throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Excel Test Signer");
    byte[] xlsxBytes = buildTestWorkbook();

    byte[] signedXlsx = ExcelSignerService.sign(
        xlsxBytes, material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC"));

    ExcelVerifyService.Result result = ExcelVerifyService.verify(signedXlsx);
    assertTrue(result.ok(), () -> "expected verification to succeed: " + result.reason());
    assertEquals(1, result.signatureCount());
    assertEquals(
        material.certificate().getSerialNumber().toString(16),
        result.signatures().get(0).certificate().serialNumber());

    // The signed workbook must still open and contain the original content —
    // signing must not corrupt the package.
    try (var wb = new XSSFWorkbook(new java.io.ByteArrayInputStream(signedXlsx))) {
      assertEquals("hello, signed workbook", wb.getSheetAt(0).getRow(0).getCell(0).getStringCellValue());
    }
  }

  @Test
  void verify_failsOnUnsignedWorkbook() throws Exception {
    byte[] xlsxBytes = buildTestWorkbook();
    ExcelVerifyService.Result result = ExcelVerifyService.verify(xlsxBytes);
    assertFalse(result.ok());
    assertEquals(0, result.signatureCount());
  }

  @Test
  void sign_rejectsNonXlsxUpload() {
    byte[] notXlsx = "this is not a zip/xlsx file".getBytes();
    assertThrows(Exception.class, () -> {
      TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Excel Reject Test");
      ExcelSignerService.sign(
          notXlsx, material.privateKey(), new Certificate[] { material.certificate() },
          Security.getProvider("BC"));
    });
  }

  /**
   * ExcelSignerService temporarily registers a narrow, signature-only
   * delegate Provider at top JCA priority to work around a POI/PKCS#11
   * limitation (see the comment in ExcelSignerService.sign). This confirms
   * that provider is fully torn down afterward — both on success and on
   * failure — since the JCA provider list is process-wide state shared with
   * every other concurrent signing operation. POI/Santuario lazily
   * self-registers its own internal XML security provider on first use (a
   * legitimate, permanent, one-time side effect unrelated to our narrow
   * provider's lifecycle — mirrors how this codebase registers BouncyCastle
   * once via static initializers), so that
   * warm-up happens before capturing the "before" snapshot.
   */
  @Test
  void sign_doesNotLeakTemporaryProvider_onSuccessAndOnFailure() throws Exception {
    TestKeyMaterial.Material warmupMaterial = TestKeyMaterial.selfSigned("Provider Order Warmup");
    ExcelSignerService.sign(
        buildTestWorkbook(), warmupMaterial.privateKey(), new Certificate[] { warmupMaterial.certificate() },
        Security.getProvider("BC"));

    String[] before = java.util.Arrays.stream(Security.getProviders())
        .map(java.security.Provider::getName)
        .toArray(String[]::new);

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Provider Order Test");
    ExcelSignerService.sign(
        buildTestWorkbook(), material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC"));

    String[] afterSuccess = java.util.Arrays.stream(Security.getProviders())
        .map(java.security.Provider::getName)
        .toArray(String[]::new);
    assertArrayEquals(before, afterSuccess, "provider order must be restored after a successful sign");

    assertThrows(Exception.class, () -> ExcelSignerService.sign(
        "not an xlsx".getBytes(), material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC")));

    String[] afterFailure = java.util.Arrays.stream(Security.getProviders())
        .map(java.security.Provider::getName)
        .toArray(String[]::new);
    assertArrayEquals(before, afterFailure, "provider order must be restored even when signing fails");
  }
}
