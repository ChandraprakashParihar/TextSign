package com.trustsign.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SignedPdfOutputPathsTest {

  @TempDir Path tempDir;

  @Test
  void stem_stripsSignedSuffixes() {
    assertEquals("report", SignedPdfOutputPaths.stemForSignedOutput("report-signed.pdf"));
    assertEquals("report", SignedPdfOutputPaths.stemForSignedOutput("report-signed3.pdf"));
    assertEquals("x", SignedPdfOutputPaths.stemForSignedOutput("x-signed-signed1.pdf"));
  }

  @Test
  void predecessor_numberedChain() throws Exception {
    Path a = tempDir.resolve("doc-signed.pdf");
    Path b = tempDir.resolve("doc-signed1.pdf");
    Path c = tempDir.resolve("doc-signed2.pdf");
    Files.createFile(a);
    Files.createFile(b);
    Files.createFile(c);
    assertNull(SignedPdfOutputPaths.predecessorForIncrementalChain(a.toFile()));
    assertEquals(a.toFile(), SignedPdfOutputPaths.predecessorForIncrementalChain(b.toFile()));
    assertEquals(b.toFile(), SignedPdfOutputPaths.predecessorForIncrementalChain(c.toFile()));
  }

  @Test
  void reserve_firstThenNumbered() throws Exception {
    Unary id = new Unary();
    Path p0 = SignedPdfOutputPaths.reserveNextSignedPdfPath(tempDir, "test.pdf", id);
    assertEquals(tempDir.resolve("test-signed.pdf").normalize().toAbsolutePath(), p0.normalize().toAbsolutePath());
    assertTrue(Files.exists(p0));

    Path p1 = SignedPdfOutputPaths.reserveNextSignedPdfPath(tempDir, "test.pdf", id);
    assertEquals(tempDir.resolve("test-signed1.pdf").normalize().toAbsolutePath(), p1.normalize().toAbsolutePath());

    Path p2 = SignedPdfOutputPaths.reserveNextSignedPdfPath(tempDir, "test.pdf", id);
    assertEquals(tempDir.resolve("test-signed2.pdf").normalize().toAbsolutePath(), p2.normalize().toAbsolutePath());
  }

  @Test
  void reserveSignedText_thenCms_numbered() throws Exception {
    Unary id = new Unary();
    Path t0 = SignedPdfOutputPaths.reserveNextSignedTextPath(tempDir, "note.txt", id);
    assertEquals(tempDir.resolve("note-signed.txt").normalize().toAbsolutePath(), t0.normalize().toAbsolutePath());

    Path t1 = SignedPdfOutputPaths.reserveNextSignedTextPath(tempDir, "note.txt", id);
    assertEquals(tempDir.resolve("note-signed1.txt").normalize().toAbsolutePath(), t1.normalize().toAbsolutePath());

    Path c0 = SignedPdfOutputPaths.reserveNextCmsSignedTextPath(tempDir, "note.txt", id);
    assertEquals(tempDir.resolve("note-cms-signed.txt").normalize().toAbsolutePath(), c0.normalize().toAbsolutePath());

    Path c1 = SignedPdfOutputPaths.reserveNextCmsSignedTextPath(tempDir, "note.txt", id);
    assertEquals(tempDir.resolve("note-cms-signed1.txt").normalize().toAbsolutePath(), c1.normalize().toAbsolutePath());
  }

  @Test
  void reserve_concurrent_uniquePaths() throws Exception {
    Unary id = new Unary();
    int threads = 32;
    CyclicBarrier barrier = new CyclicBarrier(threads);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      Set<Path> claimed = new HashSet<>();
      List<Future<Path>> futures = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        futures.add(pool.submit(() -> {
          barrier.await(10, TimeUnit.SECONDS);
          return SignedPdfOutputPaths.reserveNextSignedTextPath(tempDir, "batch.txt", id);
        }));
      }
      for (Future<Path> f : futures) {
        Path p = f.get(30, TimeUnit.SECONDS);
        assertNotNull(p);
        assertTrue(claimed.add(p), "duplicate path reserved: " + p);
      }
      assertEquals(threads, claimed.size());
    } finally {
      pool.shutdown();
      assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
    }
  }

  /** Pass-through sanitizer for tests (filenames are already simple). */
  private static final class Unary implements java.util.function.UnaryOperator<String> {
    @Override
    public String apply(String s) {
      return s;
    }
  }
}
