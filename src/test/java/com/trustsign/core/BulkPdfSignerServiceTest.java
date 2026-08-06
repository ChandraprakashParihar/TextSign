package com.trustsign.core;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.trustsign.testutil.TestKeyMaterial;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BulkPdfSignerServiceTest {

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static byte[] buildTestPdf() throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (PdfDocument pdf = new PdfDocument(new PdfWriter(out))) {
      pdf.addNewPage();
    }
    return out.toByteArray();
  }

  private static void writeFile(Path dir, String name, byte[] content) throws Exception {
    Files.write(dir.resolve(name), content);
  }

  @Test
  void signDirectory_signsAllValidPdfs() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-src-");
    Path destDir = Files.createTempDirectory("bulk-dest-");
    writeFile(sourceDir, "a.pdf", buildTestPdf());
    writeFile(sourceDir, "b.pdf", buildTestPdf());
    writeFile(sourceDir, "c.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk PDF Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), "test reason", "test location", null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, false, null);

    assertTrue(result.ok());
    assertEquals(3, result.totalFiles());
    assertEquals(3, result.succeeded());
    assertEquals(0, result.failed());
    assertEquals(0, result.skipped());
    for (BulkPdfSignerService.FileResult fr : result.results()) {
      assertEquals("signed", fr.status());
      assertTrue(new File(fr.outputPath()).length() > 0);
    }
  }

  @Test
  void signDirectory_progressListenerFiresOncePerFile() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-src-");
    Path destDir = Files.createTempDirectory("bulk-dest-");
    writeFile(sourceDir, "a.pdf", buildTestPdf());
    writeFile(sourceDir, "b.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Progress Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    List<BulkPdfSignerService.FileResult> progressEvents = new java.util.concurrent.CopyOnWriteArrayList<>();
    BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, false, progressEvents::add);

    assertEquals(2, progressEvents.size());
    assertTrue(progressEvents.stream().allMatch(fr -> fr.status().equals("signed")));
  }

  @Test
  void signDirectory_skipsNonPdfFiles() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-src-");
    Path destDir = Files.createTempDirectory("bulk-dest-");
    writeFile(sourceDir, "a.pdf", buildTestPdf());
    writeFile(sourceDir, "notes.txt", "hello".getBytes());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Skip Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, false, null);

    assertTrue(result.ok());
    assertEquals(2, result.totalFiles());
    assertEquals(1, result.succeeded());
    assertEquals(1, result.skipped());
    assertEquals(0, result.failed());
  }

  @Test
  void signDirectory_skipsFileNamedPdfWithInvalidContent() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-src-");
    Path destDir = Files.createTempDirectory("bulk-dest-");
    writeFile(sourceDir, "valid.pdf", buildTestPdf());
    writeFile(sourceDir, "fake.pdf", "this is not a real pdf".getBytes());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Fake Pdf Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, false, null);

    // "fake.pdf" passes the extension filter but fails PDF header sniffing,
    // so it must be recorded as skipped rather than crash the batch.
    assertEquals(1, result.succeeded());
    assertEquals(1, result.skipped());
    assertEquals(0, result.failed());
  }

  @Test
  void listPdfFiles_throwsWhenNoPdfsFound() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-src-");
    writeFile(sourceDir, "notes.txt", "hello".getBytes());

    assertThrows(IllegalArgumentException.class, () -> BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100));
  }

  @Test
  void listPdfFiles_rejectsBatchExceedingMaxFiles() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-src-");
    writeFile(sourceDir, "a.pdf", buildTestPdf());
    writeFile(sourceDir, "b.pdf", buildTestPdf());
    writeFile(sourceDir, "c.pdf", buildTestPdf());

    assertThrows(IllegalArgumentException.class, () -> BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 2));
  }

  @Test
  void signDirectory_postSignCheckFailureIsPerFile_batchContinues() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-src-");
    Path destDir = Files.createTempDirectory("bulk-dest-");
    writeFile(sourceDir, "good.pdf", buildTestPdf());
    writeFile(sourceDir, "reject-me.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk PostCheck Test Signer");

    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        (signResult, signedPdf) -> "simulated TSA failure",
        name -> name, false, null);

    assertFalse(result.ok());
    assertEquals(2, result.totalFiles());
    assertEquals(0, result.succeeded());
    assertEquals(2, result.failed());
    for (BulkPdfSignerService.FileResult fr : result.results()) {
      assertEquals("failed", fr.status());
      assertEquals("simulated TSA failure", fr.error());
    }
  }

  @Test
  void signDirectory_collisionSafeNaming_whenSourceEqualsDest() throws Exception {
    Path dir = Files.createTempDirectory("bulk-inplace-");
    writeFile(dir, "doc.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk InPlace Test Signer");
    BulkPdfSignerService.Listing listing1 = BulkPdfSignerService.listPdfFiles(dir.toFile(), 100);
    BulkPdfSignerService.Result first = BulkPdfSignerService.signDirectory(
        listing1.pdfFiles(), listing1.skippedByName(), dir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, false, null);
    assertEquals(1, first.succeeded());
    String firstOutput = first.results().get(0).outputPath();
    assertTrue(firstOutput.endsWith("doc-signed.pdf"));

    // Second run now sees doc.pdf AND doc-signed.pdf as source inputs (both
    // .pdf files in the same dir) — signing doc-signed.pdf again must not
    // silently overwrite the first run's output.
    BulkPdfSignerService.Listing listing2 = BulkPdfSignerService.listPdfFiles(dir.toFile(), 100);
    BulkPdfSignerService.Result second = BulkPdfSignerService.signDirectory(
        listing2.pdfFiles(), listing2.skippedByName(), dir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, false, null);
    assertEquals(2, second.totalFiles());
    assertEquals(2, second.succeeded());
    List<String> outputs = second.results().stream().map(BulkPdfSignerService.FileResult::outputPath).toList();
    assertTrue(outputs.stream().noneMatch(p -> p.equals(firstOutput)),
        "re-signing must not overwrite a previous run's output: " + outputs);
  }

  @Test
  void signDirectoryConcurrently_signsAllValidPdfsUnderContention() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-conc-src-");
    Path destDir = Files.createTempDirectory("bulk-conc-dest-");
    int fileCount = 25;
    for (int i = 0; i < fileCount; i++) {
      writeFile(sourceDir, String.format("doc%02d.pdf", i), buildTestPdf());
    }

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Concurrent Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 1000);
    // Deliberately fewer threads than files, to actually exercise queuing/contention rather than
    // giving every file its own thread.
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectoryConcurrently(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), "bulk reason", "bulk location", null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, 4, false, null);

    assertTrue(result.ok());
    assertEquals(fileCount, result.totalFiles());
    assertEquals(fileCount, result.succeeded());
    assertEquals(0, result.failed());
    assertEquals(0, result.skipped());

    // Every file must have produced a distinct, real output — concurrent
    // writers must not have clobbered each other's collision-safe paths.
    var outputPaths = result.results().stream().map(BulkPdfSignerService.FileResult::outputPath).toList();
    assertEquals(fileCount, outputPaths.stream().distinct().count(), "expected all output paths to be distinct");
    for (String path : outputPaths) {
      assertTrue(new File(path).length() > 0, "expected non-empty signed output at " + path);
    }
  }

  @Test
  void signDirectoryConcurrently_isolatesPerFileFailures_underContention() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-conc-src-");
    Path destDir = Files.createTempDirectory("bulk-conc-dest-");
    int fileCount = 10;
    for (int i = 0; i < fileCount; i++) {
      writeFile(sourceDir, String.format("doc%02d.pdf", i), buildTestPdf());
    }

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Concurrent Isolation Signer");
    // A shared, thread-safe counter that fails every other call: proves two
    // things at once — (a) this genuinely runs across multiple concurrent
    // workers (a purely sequential implementation would still pass this,
    // but the failure-isolation property is what we're actually asserting),
    // and (b) one worker's failure never corrupts or blocks another
    // worker's successful result.
    java.util.concurrent.atomic.AtomicInteger counter = new java.util.concurrent.atomic.AtomicInteger();
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 1000);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectoryConcurrently(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        (signResult, signedPdf) -> counter.incrementAndGet() % 2 == 0 ? "simulated failure" : null,
        name -> name, 4, false, null);

    assertEquals(fileCount, result.totalFiles());
    assertEquals(fileCount, result.succeeded() + result.failed());
    assertEquals(0, result.skipped());
    assertTrue(result.succeeded() > 0, "expected at least one file to succeed");
    assertTrue(result.failed() > 0, "expected at least one file to fail (alternating post-check)");
    for (BulkPdfSignerService.FileResult fr : result.results()) {
      assertTrue(fr.status().equals("signed") || fr.status().equals("failed"), "unexpected status: " + fr.status());
      if (fr.status().equals("failed")) {
        assertEquals("simulated failure", fr.error());
      }
    }
  }

  @Test
  void signDirectoryConcurrently_boundsThreadCountToFileCount() throws Exception {
    // Requesting far more threads than files must not error — the pool is
    // internally clamped to the file count.
    Path sourceDir = Files.createTempDirectory("bulk-conc-src-");
    Path destDir = Files.createTempDirectory("bulk-conc-dest-");
    writeFile(sourceDir, "only.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Concurrent ThreadBound Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 1000);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectoryConcurrently(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, 64, false, null);

    assertEquals(1, result.succeeded());
  }

  @Test
  void signDirectoryConcurrently_progressListenerFiresOncePerFile() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-conc-src-");
    Path destDir = Files.createTempDirectory("bulk-conc-dest-");
    int fileCount = 8;
    for (int i = 0; i < fileCount; i++) {
      writeFile(sourceDir, String.format("doc%02d.pdf", i), buildTestPdf());
    }

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Concurrent Progress Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 1000);
    List<BulkPdfSignerService.FileResult> progressEvents = new java.util.concurrent.CopyOnWriteArrayList<>();
    BulkPdfSignerService.signDirectoryConcurrently(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, 4, false, progressEvents::add);

    assertEquals(fileCount, progressEvents.size());
  }

  @Test
  void signDirectory_deletesSourceOnSuccess_whenRequested() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-del-src-");
    Path destDir = Files.createTempDirectory("bulk-del-dest-");
    writeFile(sourceDir, "a.pdf", buildTestPdf());
    writeFile(sourceDir, "b.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Delete Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, true, null);

    assertEquals(2, result.succeeded());
    for (BulkPdfSignerService.FileResult fr : result.results()) {
      assertEquals("signed", fr.status());
      assertEquals(null, fr.sourceDeleteError());
    }
    assertFalse(Files.exists(sourceDir.resolve("a.pdf")), "source file should be deleted after successful signing");
    assertFalse(Files.exists(sourceDir.resolve("b.pdf")), "source file should be deleted after successful signing");
    // The signed copies in destDir must be unaffected by deleting the sources.
    assertTrue(Files.exists(destDir.resolve("a-signed.pdf")));
    assertTrue(Files.exists(destDir.resolve("b-signed.pdf")));
  }

  @Test
  void signDirectory_keepsSourceByDefault() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-del-src-");
    Path destDir = Files.createTempDirectory("bulk-del-dest-");
    writeFile(sourceDir, "a.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk No Delete Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, false, null);

    assertTrue(Files.exists(sourceDir.resolve("a.pdf")), "source file must be left alone unless explicitly requested");
  }

  @Test
  void signDirectory_neverDeletesSource_whenSigningFails() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-del-src-");
    Path destDir = Files.createTempDirectory("bulk-del-dest-");
    writeFile(sourceDir, "reject-me.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Delete On Fail Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        (signResult, signedPdf) -> "forced failure", name -> name, true, null);

    assertEquals(1, result.failed());
    assertTrue(Files.exists(sourceDir.resolve("reject-me.pdf")),
        "a failed signing attempt must never delete the source file, even with deleteSourceOnSuccess=true");
  }

  @Test
  void signDirectory_neverDeletesSource_whenSkipped() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-del-src-");
    Path destDir = Files.createTempDirectory("bulk-del-dest-");
    writeFile(sourceDir, "fake.pdf", "not a real pdf".getBytes());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Delete On Skip Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);
    BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectory(
        listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
        material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
        material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
        null, name -> name, true, null);

    assertEquals(1, result.skipped());
    assertTrue(Files.exists(sourceDir.resolve("fake.pdf")),
        "a skipped (not-a-real-PDF) file must never be deleted, even with deleteSourceOnSuccess=true");
  }

  @Test
  void signDirectory_reportsSourceDeleteError_whenDeletionFails() throws Exception {
    Path sourceDir = Files.createTempDirectory("bulk-del-src-");
    Path destDir = Files.createTempDirectory("bulk-del-dest-");
    writeFile(sourceDir, "a.pdf", buildTestPdf());

    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("Bulk Delete Error Test Signer");
    BulkPdfSignerService.Listing listing = BulkPdfSignerService.listPdfFiles(sourceDir.toFile(), 100);

    // Removing write permission on the parent directory makes deleting a
    // file inside it fail on POSIX filesystems, without needing to touch
    // the file's own permissions.
    File sourceDirFile = sourceDir.toFile();
    boolean permissionChangeSupported = sourceDirFile.setWritable(false);
    try {
      BulkPdfSignerService.Result result = BulkPdfSignerService.signDirectory(
          listing.pdfFiles(), listing.skippedByName(), destDir.toFile(),
          material.privateKey(), new Certificate[] { material.certificate() }, Security.getProvider("BC"),
          material.certificate(), null, null, null, PdfSignerService.PdfSigningOptions.DEFAULT,
          null, name -> name, true, null);

      BulkPdfSignerService.FileResult fr = result.results().get(0);
      if (permissionChangeSupported && Files.exists(sourceDir.resolve("a.pdf"))) {
        // Deletion genuinely failed as intended by this test setup.
        assertEquals("signed", fr.status(), "signing itself must still succeed even if cleanup fails");
        assertTrue(fr.sourceDeleteError() != null && fr.sourceDeleteError().contains("failed to delete"),
            "expected a sourceDeleteError, got: " + fr.sourceDeleteError());
      }
      // If the platform/filesystem doesn't honor setWritable(false) for this
      // user (e.g. running as root), deletion may still succeed — that's a
      // property of the test environment, not of the code under test, so
      // there's nothing further to assert in that branch.
    } finally {
      sourceDirFile.setWritable(true);
    }
  }
}
