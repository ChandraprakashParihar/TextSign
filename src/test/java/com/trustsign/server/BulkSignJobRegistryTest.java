package com.trustsign.server;

import com.trustsign.core.BulkPdfSignerService;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BulkSignJobRegistryTest {

  private static BulkPdfSignerService.FileResult signed(String name) {
    return new BulkPdfSignerService.FileResult(name, "signed", "/out/" + name, null, true, 5L, null);
  }

  private static BulkPdfSignerService.FileResult failedResult(String name) {
    return new BulkPdfSignerService.FileResult(name, "failed", null, "boom", null, null, null);
  }

  @Test
  void submit_returnsJobId_andStatusIsRunningWhileBodyBlocks() throws Exception {
    BulkSignJobRegistry registry = new BulkSignJobRegistry();
    CountDownLatch releaseJob = new CountDownLatch(1);
    CountDownLatch jobStarted = new CountDownLatch(1);

    String jobId = registry.submit("/src", "/dest", "CN=Test", "abc123", 1, progress -> {
      jobStarted.countDown();
      releaseJob.await();
    });

    assertNotNull(jobId);
    assertTrue(jobStarted.await(2, TimeUnit.SECONDS), "job body should start promptly");

    BulkSignJobRegistry.JobSnapshot snapshot = registry.getStatus(jobId);
    assertNotNull(snapshot);
    assertEquals(BulkSignJobRegistry.JobState.RUNNING, snapshot.state());
    assertEquals("/src", snapshot.sourceDir());
    assertEquals("/dest", snapshot.destDir());
    assertEquals("CN=Test", snapshot.subjectDn());
    assertEquals("abc123", snapshot.serialNumber());
    assertEquals(1, snapshot.totalFiles());
    assertNull(snapshot.finishedAt());

    releaseJob.countDown();
  }

  @Test
  void submit_completesSuccessfully_statusReflectsFinalCounts() throws Exception {
    BulkSignJobRegistry registry = new BulkSignJobRegistry();
    CountDownLatch done = new CountDownLatch(1);

    String jobId = registry.submit("/src", "/dest", "CN=Test", "abc123", 3, progress -> {
      progress.accept(signed("a.pdf"));
      progress.accept(signed("b.pdf"));
      progress.accept(failedResult("c.pdf"));
      done.countDown();
    });

    assertTrue(done.await(2, TimeUnit.SECONDS));
    // The job body returning and the state flip to COMPLETED both happen on
    // the background thread; give it a brief moment to finish that last step.
    BulkSignJobRegistry.JobSnapshot snapshot = awaitFinished(registry, jobId);

    assertEquals(BulkSignJobRegistry.JobState.COMPLETED, snapshot.state());
    assertEquals(3, snapshot.totalFiles());
    assertEquals(3, snapshot.processed());
    assertEquals(2, snapshot.succeeded());
    assertEquals(1, snapshot.failed());
    assertEquals(0, snapshot.skipped());
    assertEquals(3, snapshot.results().size());
    assertNotNull(snapshot.finishedAt());
  }

  @Test
  void submit_jobBodyThrows_marksFailedWithErrorMessage() throws Exception {
    BulkSignJobRegistry registry = new BulkSignJobRegistry();
    String jobId = registry.submit("/src", "/dest", "CN=Test", "abc123", 1, progress -> {
      throw new IllegalStateException("something went wrong mid-batch");
    });

    BulkSignJobRegistry.JobSnapshot snapshot = awaitFinished(registry, jobId);
    assertEquals(BulkSignJobRegistry.JobState.FAILED, snapshot.state());
    assertEquals("something went wrong mid-batch", snapshot.error());
    assertNotNull(snapshot.finishedAt());
  }

  @Test
  void getStatus_returnsNullForUnknownJobId() {
    BulkSignJobRegistry registry = new BulkSignJobRegistry();
    assertNull(registry.getStatus("no-such-job-id"));
  }

  @Test
  void progress_isVisibleWhileJobStillRunning() throws Exception {
    BulkSignJobRegistry registry = new BulkSignJobRegistry();
    CountDownLatch firstFileDone = new CountDownLatch(1);
    CountDownLatch releaseRest = new CountDownLatch(1);

    String jobId = registry.submit("/src", "/dest", "CN=Test", "abc123", 2, progress -> {
      progress.accept(signed("a.pdf"));
      firstFileDone.countDown();
      releaseRest.await();
      progress.accept(signed("b.pdf"));
    });

    assertTrue(firstFileDone.await(2, TimeUnit.SECONDS));
    BulkSignJobRegistry.JobSnapshot partial = registry.getStatus(jobId);
    assertEquals(BulkSignJobRegistry.JobState.RUNNING, partial.state());
    assertEquals(1, partial.processed());
    assertEquals(1, partial.succeeded());
    assertEquals(1, partial.results().size());

    releaseRest.countDown();
    BulkSignJobRegistry.JobSnapshot finished = awaitFinished(registry, jobId);
    assertEquals(2, finished.processed());
    assertEquals(2, finished.succeeded());
  }

  private static BulkSignJobRegistry.JobSnapshot awaitFinished(BulkSignJobRegistry registry, String jobId)
      throws InterruptedException {
    for (int i = 0; i < 100; i++) {
      BulkSignJobRegistry.JobSnapshot snapshot = registry.getStatus(jobId);
      if (snapshot.state() != BulkSignJobRegistry.JobState.RUNNING) {
        return snapshot;
      }
      Thread.sleep(20);
    }
    throw new AssertionError("job did not finish within timeout: " + jobId);
  }
}
