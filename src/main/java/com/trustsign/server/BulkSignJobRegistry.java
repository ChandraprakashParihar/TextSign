package com.trustsign.server;

import com.trustsign.core.BulkPdfSignerService;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Tracks bulk-PDF-signing jobs submitted for background execution, so
 * {@code /auto-sign-pdf-bulk} and {@code /auto-sign-pdf-bulk-pfx} can return
 * immediately (job accepted, HTTP 202) instead of blocking the request for
 * however long the whole batch takes, while
 * {@code /auto-sign-pdf-bulk-status} polls progress and, eventually, the
 * final per-file results.
 *
 * <p>In-memory only — jobs do not survive a server restart, matching this
 * server's overall persistence model (config-file-driven, no database).
 * Finished jobs are evicted after a fixed retention window on a lazy,
 * access-triggered sweep rather than a dedicated background thread.
 */
public final class BulkSignJobRegistry {

  private static final long RETENTION_MS = 30 * 60 * 1000L; // keep finished jobs visible for 30 minutes

  private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(BulkSignJobRegistry.class);

  public enum JobState { RUNNING, COMPLETED, FAILED }

  /** Thrown by {@link #submit} when a job over the same source directory is still running. */
  public static final class DuplicateJobException extends IllegalStateException {
    private final String existingJobId;

    DuplicateJobException(String existingJobId, String sourceDir) {
      super("A bulk signing job is already running for sourceDir: " + sourceDir);
      this.existingJobId = existingJobId;
    }

    public String existingJobId() {
      return existingJobId;
    }
  }

  public record JobSnapshot(
      String jobId,
      JobState state,
      String sourceDir,
      String destDir,
      String subjectDn,
      String serialNumber,
      int totalFiles,
      int processed,
      int succeeded,
      int failed,
      int skipped,
      List<BulkPdfSignerService.FileResult> results,
      String error,
      String startedAt,
      String finishedAt) {}

  /** Runs the whole batch, calling {@code progress} once per file as results become available. Throwing marks the job FAILED. */
  public interface JobBody {
    void run(Consumer<BulkPdfSignerService.FileResult> progress) throws Exception;
  }

  private static final class Job {
    final String jobId;
    final String sourceDir;
    final String destDir;
    final String subjectDn;
    final String serialNumber;
    final int totalFiles;
    final long startedAtMs;
    volatile JobState state = JobState.RUNNING;
    volatile long finishedAtMs;
    volatile String error;
    final List<BulkPdfSignerService.FileResult> results = new CopyOnWriteArrayList<>();
    final AtomicInteger succeeded = new AtomicInteger();
    final AtomicInteger failed = new AtomicInteger();
    final AtomicInteger skipped = new AtomicInteger();

    Job(String jobId, String sourceDir, String destDir, String subjectDn, String serialNumber, int totalFiles) {
      this.jobId = jobId;
      this.sourceDir = sourceDir;
      this.destDir = destDir;
      this.subjectDn = subjectDn;
      this.serialNumber = serialNumber;
      this.totalFiles = totalFiles;
      this.startedAtMs = System.currentTimeMillis();
    }
  }

  private final ConcurrentHashMap<String, Job> jobs = new ConcurrentHashMap<>();
  private final ExecutorService jobExecutor = Executors.newCachedThreadPool(runnable -> {
    Thread t = new Thread(runnable, "bulk-sign-job");
    t.setDaemon(true);
    return t;
  });

  /**
   * Registers a new job and starts {@code body} running on a background
   * thread immediately. Returns the job ID right away — the caller is
   * expected to have already done all synchronous validation (directory
   * safety, file listing/count cap, credential resolution, certificate
   * selection) BEFORE calling this, so those errors are still reported in
   * the initial HTTP response rather than hidden behind a poll.
   */
  public synchronized String submit(
      String sourceDir, String destDir, String subjectDn, String serialNumber, int totalFiles, JobBody body) {
    sweepExpired();
    // Two jobs over the same source directory would sign every file twice
    // (and, with deleteSourceOnSuccess, race each other deleting the
    // originals) — e.g. a client retrying a request whose 202 it never saw.
    for (Job existing : jobs.values()) {
      if (existing.state == JobState.RUNNING && existing.sourceDir != null && existing.sourceDir.equals(sourceDir)) {
        throw new DuplicateJobException(existing.jobId, sourceDir);
      }
    }
    String jobId = UUID.randomUUID().toString();
    Job job = new Job(jobId, sourceDir, destDir, subjectDn, serialNumber, totalFiles);
    jobs.put(jobId, job);

    jobExecutor.execute(() -> {
      try {
        body.run(result -> {
          job.results.add(result);
          switch (result.status()) {
            case "signed" -> job.succeeded.incrementAndGet();
            case "skipped" -> job.skipped.incrementAndGet();
            default -> job.failed.incrementAndGet();
          }
        });
        job.finishedAtMs = System.currentTimeMillis();
        job.state = JobState.COMPLETED;
      } catch (Throwable t) {
        // Throwable, not Exception: an Error (e.g. OutOfMemoryError on a huge
        // PDF) must still mark the job FAILED — otherwise it would report
        // RUNNING forever and block its sourceDir from being resubmitted.
        if (t instanceof InterruptedException) {
          Thread.currentThread().interrupt();
        }
        LOG.error("Bulk signing job {} failed: {}", jobId, safeMsg(t), t);
        job.error = safeMsg(t);
        job.finishedAtMs = System.currentTimeMillis();
        job.state = JobState.FAILED;
      }
    });

    return jobId;
  }

  /** Returns null if no job with this ID exists (never existed, or was already swept after retention expired). */
  public JobSnapshot getStatus(String jobId) {
    sweepExpired();
    Job job = jobs.get(jobId);
    if (job == null) {
      return null;
    }
    return new JobSnapshot(
        job.jobId, job.state, job.sourceDir, job.destDir, job.subjectDn, job.serialNumber, job.totalFiles,
        job.results.size(), job.succeeded.get(), job.failed.get(), job.skipped.get(),
        new ArrayList<>(job.results), job.error,
        Instant.ofEpochMilli(job.startedAtMs).toString(),
        job.finishedAtMs > 0 ? Instant.ofEpochMilli(job.finishedAtMs).toString() : null);
  }

  private void sweepExpired() {
    long cutoff = System.currentTimeMillis() - RETENTION_MS;
    jobs.entrySet().removeIf(e -> {
      Job j = e.getValue();
      return j.state != JobState.RUNNING && j.finishedAtMs > 0 && j.finishedAtMs < cutoff;
    });
  }

  private static String safeMsg(Throwable t) {
    String m = t.getMessage();
    return (m != null && !m.isBlank()) ? m : t.getClass().getSimpleName();
  }
}
