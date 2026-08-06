package com.trustsign.core;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

/**
 * Signs a list of PDFs and writes each signed output into a destination
 * directory, reusing ONE resolved credential for the whole batch instead of
 * re-authenticating per file. A single bad file (corrupt PDF, DocMDP-locked,
 * TSA/LTV failure, etc.) is recorded as a per-file failure and does NOT
 * abort the rest of the batch — the whole point of a bulk operation is one
 * full report instead of a client having to retry file-by-file after the
 * first failure.
 *
 * <p>Listing and signing are deliberately separate steps ({@link #listPdfFiles}
 * then {@link #signDirectory}/{@link #signDirectoryConcurrently}): the caller
 * (today, {@code ApiServlet}'s async job submission) needs to validate the
 * batch (does sourceDir have any PDFs? does it exceed the file cap?)
 * synchronously and report that immediately, before handing the actual,
 * potentially long-running signing work off to a background job.
 *
 * <p>Two signing entry points, sharing the same per-file logic
 * ({@link #signOneFile}):
 * <ul>
 *   <li>{@link #signDirectory} — sequential. Safe for ANY credential source,
 *   including a PKCS#11 hardware token, since it only ever touches the token
 *   from one thread at a time.
 *   <li>{@link #signDirectoryConcurrently} — parallel across a bounded thread
 *   pool. Safe ONLY for an extractable software key (a PFX/PKCS12-sourced
 *   {@link PrivateKey}, never a PKCS#11 token key) — see that method's
 *   Javadoc for why. Callers MUST NOT pass a PKCS#11 key here.
 * </ul>
 *
 * <p>HTTP-agnostic and independently testable, unlike {@code ApiServlet}'s
 * handler methods: it knows nothing about multipart parsing, JSON responses,
 * or background job tracking. The caller is responsible for resolving
 * credentials, validating directories, and (today) driving
 * {@code BulkSignJobRegistry} with the {@code progressListener} callback.
 */
public final class BulkPdfSignerService {

  public record FileResult(
      String file,
      String status, // "signed" | "failed" | "skipped"
      String outputPath,
      String error,
      Boolean timestamped,
      Long tookMs) {

    static FileResult signed(String file, String outputPath, boolean timestamped, long tookMs) {
      return new FileResult(file, "signed", outputPath, null, timestamped, tookMs);
    }

    static FileResult failed(String file, String error) {
      return new FileResult(file, "failed", null, error, null, null);
    }

    static FileResult skipped(String file, String reason) {
      return new FileResult(file, "skipped", null, reason, null, null);
    }
  }

  public record Result(
      boolean ok,
      int totalFiles,
      int succeeded,
      int failed,
      int skipped,
      List<FileResult> results) {}

  /** Post-signing validation hook (e.g. TSA/LTV checks) — returns a failure reason, or null if OK. */
  public interface PostSignCheck {
    String check(PdfSignerService.PdfSigningResult signResult, byte[] signedPdf) throws Exception;
  }

  public record Listing(List<File> pdfFiles, int skippedByName) {
    public int totalFiles() {
      return pdfFiles.size() + skippedByName;
    }
  }

  /**
   * Lists {@code sourceDir} non-recursively and validates the batch size —
   * called by itself (synchronously) before any signing starts, so "no PDFs
   * found" / "too many files" are reported immediately rather than only
   * surfacing later via a background job's status.
   *
   * @param maxFiles hard cap on how many PDFs a caller will process; throws
   *                 {@link IllegalArgumentException} if {@code sourceDir}
   *                 has more than this many {@code .pdf} files, rather than
   *                 letting a caller silently truncate the batch and leave
   *                 some files unsigned without realizing it.
   */
  public static Listing listPdfFiles(File sourceDir, int maxFiles) {
    File[] listed = sourceDir.listFiles(File::isFile);
    List<File> pdfFiles = new ArrayList<>();
    int skippedByName = 0;
    if (listed != null) {
      Arrays.sort(listed, java.util.Comparator.comparing(File::getName));
      for (File f : listed) {
        if (f.getName().toLowerCase(Locale.ROOT).endsWith(".pdf")) {
          pdfFiles.add(f);
        } else {
          skippedByName++;
        }
      }
    }

    if (pdfFiles.isEmpty()) {
      throw new IllegalArgumentException("No .pdf files found directly in sourceDir: " + sourceDir.getAbsolutePath());
    }
    if (pdfFiles.size() > maxFiles) {
      throw new IllegalArgumentException(
          "sourceDir contains " + pdfFiles.size() + " PDF file(s), which exceeds the configured limit of "
              + maxFiles + ". Split the batch across multiple requests.");
    }
    return new Listing(pdfFiles, skippedByName);
  }

  /**
   * Signs every file in {@code pdfFiles} one at a time, on the calling
   * thread, and writes each signed output into {@code destDir} via
   * {@link SignedPdfOutputPaths#reserveNextSignedPdfPath}, which handles
   * collision-safe naming — safe even when the source and destination are
   * the same directory, since signed outputs always get a different,
   * "-signed"-suffixed name than their source file.
   *
   * <p>Safe for any credential source, including a PKCS#11 hardware token.
   *
   * @param progressListener optional; invoked once per file, immediately
   *                          after that file's result is known, so a caller
   *                          driving a background job can report partial
   *                          progress before the whole batch finishes.
   */
  public static Result signDirectory(
      List<File> pdfFiles,
      int skippedByName,
      File destDir,
      PrivateKey key,
      Certificate[] chain,
      Provider provider,
      X509Certificate signingCert,
      String reason,
      String location,
      List<Integer> stampPages,
      PdfSignerService.PdfSigningOptions pdfOpts,
      PostSignCheck postSignCheck,
      UnaryOperator<String> sanitizeFilename,
      Consumer<FileResult> progressListener) {
    List<FileResult> results = new ArrayList<>();
    int succeeded = 0;
    int failed = 0;
    int skipped = skippedByName;

    for (File pdfFile : pdfFiles) {
      FileResult r = signOneFile(
          pdfFile, destDir, key, chain, provider, signingCert, reason, location, stampPages, pdfOpts,
          postSignCheck, sanitizeFilename);
      results.add(r);
      if (progressListener != null) {
        progressListener.accept(r);
      }
      switch (r.status()) {
        case "signed" -> succeeded++;
        case "skipped" -> skipped++;
        default -> failed++;
      }
    }

    return new Result(failed == 0, pdfFiles.size() + skippedByName, succeeded, failed, skipped, results);
  }

  /**
   * Same as {@link #signDirectory}, but signs up to {@code threadCount} files
   * concurrently on a bounded thread pool — for directories with very large
   * numbers of PDFs, where signing one at a time is the throughput
   * bottleneck.
   *
   * <p><b>Only safe for an extractable software key (PFX/PKCS12), never a
   * PKCS#11 hardware token key.</b> Most PKCS#11 driver/middleware sessions
   * are not safe under concurrent use from multiple threads — the token can
   * corrupt state or throw driver-level errors if hit concurrently. A
   * PFX-sourced {@link PrivateKey} has no such restriction: it's a plain,
   * immutable, in-memory RSA key, and standard JCA usage already assumes many
   * threads can each create their own {@code Signature} instance and call
   * {@code initSign} on the SAME shared {@code PrivateKey} object
   * concurrently (this is exactly how, e.g., a single HTTPS server private
   * key backs many concurrent TLS handshakes). Nothing else in the signing
   * path holds mutable shared state either — {@code PdfSignerService} has no
   * static mutable fields, and {@code RevocationCache} (used for LTV/OCSP)
   * is backed by a {@code ConcurrentHashMap}. It is the caller's
   * responsibility to enforce "PFX only" before calling this — this method
   * has no way to detect where a {@link PrivateKey} object actually came
   * from.
   *
   * <p>The thread pool is created and fully shut down within this call —
   * nothing is left running after it returns. {@code progressListener} may
   * be invoked from any worker thread and from multiple threads concurrently
   * — callers must make it thread-safe (the intended caller,
   * {@code BulkSignJobRegistry}, backs it with a
   * {@code CopyOnWriteArrayList}/atomic counters for exactly this reason).
   */
  public static Result signDirectoryConcurrently(
      List<File> pdfFiles,
      int skippedByName,
      File destDir,
      PrivateKey key,
      Certificate[] chain,
      Provider provider,
      X509Certificate signingCert,
      String reason,
      String location,
      List<Integer> stampPages,
      PdfSignerService.PdfSigningOptions pdfOpts,
      PostSignCheck postSignCheck,
      UnaryOperator<String> sanitizeFilename,
      int threadCount,
      Consumer<FileResult> progressListener) throws InterruptedException {
    int effectiveThreads = Math.max(1, Math.min(threadCount, pdfFiles.size()));
    ExecutorService pool = Executors.newFixedThreadPool(effectiveThreads);
    try {
      List<Future<FileResult>> futures = new ArrayList<>(pdfFiles.size());
      for (File pdfFile : pdfFiles) {
        futures.add(pool.submit(() -> {
          FileResult r = signOneFile(
              pdfFile, destDir, key, chain, provider, signingCert, reason, location, stampPages, pdfOpts,
              postSignCheck, sanitizeFilename);
          if (progressListener != null) {
            progressListener.accept(r);
          }
          return r;
        }));
      }

      List<FileResult> results = new ArrayList<>(pdfFiles.size());
      int succeeded = 0;
      int failed = 0;
      int skipped = skippedByName;
      for (Future<FileResult> future : futures) {
        FileResult r;
        try {
          r = future.get();
        } catch (ExecutionException e) {
          // signOneFile catches its own exceptions internally and always
          // returns a FileResult rather than throwing, so this is only
          // reachable for an unexpected error escaping that contract —
          // still must not abort the rest of the batch.
          r = FileResult.failed("<unknown>", safeMsg(e.getCause() != null ? e.getCause() : e));
        }
        results.add(r);
        switch (r.status()) {
          case "signed" -> succeeded++;
          case "skipped" -> skipped++;
          default -> failed++;
        }
      }

      return new Result(failed == 0, pdfFiles.size() + skippedByName, succeeded, failed, skipped, results);
    } finally {
      pool.shutdown();
      if (!pool.awaitTermination(5, TimeUnit.SECONDS)) {
        pool.shutdownNow();
      }
    }
  }

  /**
   * Signs one PDF and writes its output, or returns a "failed"/"skipped"
   * {@link FileResult} — never throws. Shared by both {@link #signDirectory}
   * and {@link #signDirectoryConcurrently} so the two entry points can never
   * drift in per-file behavior.
   */
  private static FileResult signOneFile(
      File pdfFile,
      File destDir,
      PrivateKey key,
      Certificate[] chain,
      Provider provider,
      X509Certificate signingCert,
      String reason,
      String location,
      List<Integer> stampPages,
      PdfSignerService.PdfSigningOptions pdfOpts,
      PostSignCheck postSignCheck,
      UnaryOperator<String> sanitizeFilename) {
    long fileStartMs = System.currentTimeMillis();
    try {
      byte[] data = Files.readAllBytes(pdfFile.toPath());
      // Every file reaching this point was already filtered by ".pdf"
      // extension when the directory was listed, so this must be a pure
      // content check — re-checking the filename here would make it a
      // no-op (always true) and let a garbage-content file named ".pdf"
      // through to signPdf() as a "failed" instead of correctly "skipped".
      if (!looksLikePdfContent(data)) {
        return FileResult.skipped(pdfFile.getName(), "Not a valid PDF file");
      }

      PdfSignerService.PdfSigningResult signResult;
      try {
        signResult = PdfSignerService.signPdf(data, key, chain, provider, signingCert, reason, location, stampPages, pdfOpts);
      } catch (PdfSignerService.DocMdpNoChangesLockException e) {
        return FileResult.failed(pdfFile.getName(), "DocMDP P=1 (document locked): " + safeMsg(e));
      }

      byte[] signedPdf = signResult.signedPdf();
      if (postSignCheck != null) {
        String postCheckError = postSignCheck.check(signResult, signedPdf);
        if (postCheckError != null) {
          return FileResult.failed(pdfFile.getName(), postCheckError);
        }
      }

      Path reservedOutPath = SignedPdfOutputPaths.reserveNextSignedPdfPath(
          destDir.toPath(), pdfFile.getName(), sanitizeFilename);
      boolean outputWritten = false;
      try {
        Files.write(reservedOutPath, signedPdf, StandardOpenOption.TRUNCATE_EXISTING);
        outputWritten = true;
      } finally {
        if (!outputWritten) {
          Files.deleteIfExists(reservedOutPath);
        }
      }

      return FileResult.signed(
          pdfFile.getName(), reservedOutPath.toAbsolutePath().toString(),
          signResult.isTimestamped(), System.currentTimeMillis() - fileStartMs);
    } catch (Exception e) {
      return FileResult.failed(pdfFile.getName(), safeMsg(e));
    }
  }

  /** True when bytes start with a PDF file header ({@code %PDF-}) within the first 1KB — a pure content check, no filename involved. */
  private static boolean looksLikePdfContent(byte[] data) {
    if (data == null || data.length < 5) {
      return false;
    }
    for (int i = 0; i <= Math.min(1024, data.length - 5); i++) {
      if (data[i] == '%' && data[i + 1] == 'P' && data[i + 2] == 'D' && data[i + 3] == 'F' && data[i + 4] == '-') {
        return true;
      }
    }
    return false;
  }

  private static String safeMsg(Throwable t) {
    String m = t.getMessage();
    return (m != null && !m.isBlank()) ? m : t.getClass().getSimpleName();
  }

  private BulkPdfSignerService() {}
}
