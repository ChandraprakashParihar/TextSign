package com.trustsign.core;

import com.trustsign.testutil.TestKeyMaterial;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.apache.poi.xslf.usermodel.XSLFSlide;
import org.apache.poi.xslf.usermodel.XSLFTextBox;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.apache.poi.xwpf.usermodel.XWPFParagraph;
import org.apache.poi.xwpf.usermodel.XWPFRun;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.ByteArrayOutputStream;
import java.security.Security;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OoxmlSignerServiceTest {

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static byte[] buildTestFile(OoxmlSignerService.OoxmlFormat format) throws Exception {
    return switch (format) {
      case XLSX -> buildTestWorkbook();
      case DOCX -> buildTestDocument();
      case PPTX -> buildTestPresentation();
    };
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

  private static byte[] buildTestDocument() throws Exception {
    try (XWPFDocument doc = new XWPFDocument()) {
      XWPFParagraph paragraph = doc.createParagraph();
      XWPFRun run = paragraph.createRun();
      run.setText("hello, signed document");
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      doc.write(out);
      return out.toByteArray();
    }
  }

  private static byte[] buildTestPresentation() throws Exception {
    try (XMLSlideShow ppt = new XMLSlideShow()) {
      XSLFSlide slide = ppt.createSlide();
      XSLFTextBox textBox = slide.createTextBox();
      textBox.setText("hello, signed presentation");
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ppt.write(out);
      return out.toByteArray();
    }
  }

  @ParameterizedTest
  @EnumSource(OoxmlSignerService.OoxmlFormat.class)
  void signAndVerifyRoundTrip_succeeds(OoxmlSignerService.OoxmlFormat format) throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned(format.name() + " Test Signer");
    byte[] fileBytes = buildTestFile(format);

    byte[] signed = OoxmlSignerService.sign(
        fileBytes, format, material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC"));

    OoxmlVerifyService.Result result = OoxmlVerifyService.verify(signed);
    assertTrue(result.ok(), () -> "expected verification to succeed: " + result.reason());
    assertEquals(1, result.signatureCount());
    assertEquals(
        material.certificate().getSerialNumber().toString(16),
        result.signatures().get(0).certificate().serialNumber());

    // Signing must not corrupt the package — must still be openable as the
    // right format afterward.
    OoxmlSignerService.validateOpenable(signed, format);
  }

  @ParameterizedTest
  @EnumSource(OoxmlSignerService.OoxmlFormat.class)
  void verify_failsOnUnsignedFile(OoxmlSignerService.OoxmlFormat format) throws Exception {
    byte[] fileBytes = buildTestFile(format);
    OoxmlVerifyService.Result result = OoxmlVerifyService.verify(fileBytes);
    assertFalse(result.ok());
    assertEquals(0, result.signatureCount());
  }

  @ParameterizedTest
  @EnumSource(OoxmlSignerService.OoxmlFormat.class)
  void sign_rejectsNonOoxmlUpload(OoxmlSignerService.OoxmlFormat format) {
    byte[] notOoxml = "this is not a zip/OOXML file".getBytes();
    assertThrows(Exception.class, () -> {
      TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Reject Test");
      OoxmlSignerService.sign(
          notOoxml, format, material.privateKey(), new Certificate[] { material.certificate() },
          Security.getProvider("BC"));
    });
  }

  @Test
  void validateOpenable_rejectsMismatchedFormat() throws Exception {
    // A real .pptx uploaded against the Word endpoint's expected format must
    // be rejected with a clear error, not silently signed under the wrong
    // label — this is what catches "wrong endpoint, right OOXML file".
    byte[] pptxBytes = buildTestPresentation();
    assertThrows(IllegalArgumentException.class,
        () -> OoxmlSignerService.validateOpenable(pptxBytes, OoxmlSignerService.OoxmlFormat.DOCX));
  }

  /**
   * OoxmlSignerService temporarily registers a narrow, signature-only
   * delegate Provider at top JCA priority to work around a POI/PKCS#11
   * limitation (see the comment in OoxmlSignerService.sign). This confirms
   * that provider is fully torn down afterward — both on success and on
   * failure — since the JCA provider list is process-wide state shared with
   * every other concurrent signing operation. POI/Santuario lazily
   * self-registers its own internal XML security provider on first use (a
   * legitimate, permanent, one-time side effect unrelated to our narrow
   * provider's lifecycle — mirrors how this codebase registers BouncyCastle
   * once via static initializers), so that
   * warm-up happens before capturing the "before" snapshot. Tested once
   * against XLSX only — this is JVM-global provider-registry behavior, not
   * format-specific, so it doesn't need repeating per format.
   */
  @Test
  void sign_doesNotLeakTemporaryProvider_onSuccessAndOnFailure() throws Exception {
    OoxmlSignerService.OoxmlFormat format = OoxmlSignerService.OoxmlFormat.XLSX;
    TestKeyMaterial.Material warmupMaterial = TestKeyMaterial.selfSigned("Provider Order Warmup");
    OoxmlSignerService.sign(
        buildTestFile(format), format, warmupMaterial.privateKey(), new Certificate[] { warmupMaterial.certificate() },
        Security.getProvider("BC"));

    String[] before = java.util.Arrays.stream(Security.getProviders())
        .map(java.security.Provider::getName)
        .toArray(String[]::new);

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Provider Order Test");
    OoxmlSignerService.sign(
        buildTestFile(format), format, material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC"));

    String[] afterSuccess = java.util.Arrays.stream(Security.getProviders())
        .map(java.security.Provider::getName)
        .toArray(String[]::new);
    assertArrayEquals(before, afterSuccess, "provider order must be restored after a successful sign");

    assertThrows(Exception.class, () -> OoxmlSignerService.sign(
        "not an ooxml file".getBytes(), format, material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC")));

    String[] afterFailure = java.util.Arrays.stream(Security.getProviders())
        .map(java.security.Provider::getName)
        .toArray(String[]::new);
    assertArrayEquals(before, afterFailure, "provider order must be restored even when signing fails");
  }
}
