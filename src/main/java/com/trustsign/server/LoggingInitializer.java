package com.trustsign.server;

import com.trustsign.core.AgentConfig;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.ConsoleHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.SimpleFormatter;
import java.util.logging.FileHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Initializes java.util.logging based on config.
 *
 * - Creates parent directories
 * - Appends to existing log file
 * - Thread-safe via JUL handlers
 */
public final class LoggingInitializer {
  private static final Logger LOG = LoggerFactory.getLogger(LoggingInitializer.class);
  private static final AtomicBoolean INITIALIZED = new AtomicBoolean(false);

  private static final DateTimeFormatter TS_FMT = DateTimeFormatter
      .ofPattern("yyyy-MM-dd HH:mm:ss")
      .withLocale(Locale.ROOT)
      .withZone(ZoneId.systemDefault());

  public static void initFromConfig(AgentConfig cfg, File configFile) {
    if (cfg == null) return;
    if (!INITIALIZED.compareAndSet(false, true)) return;

    AgentConfig.LoggingConfig lc = cfg.logging();
    String path = firstNonBlank(
        lc != null ? lc.filePath() : null,
        cfg.logFilePath());

    boolean failOnError = lc != null && Boolean.TRUE.equals(lc.failOnError());
    boolean consoleEnabled = lc == null || lc.consoleEnabled() == null || lc.consoleEnabled();

    Level level = parseLevelOrDefault(lc != null ? lc.level() : null, Level.INFO);

    Path defaultPath = defaultLogPath(configFile);
    Path filePath;
    if (path == null) {
      filePath = defaultPath;
    } else {
      filePath = resolveAgainstConfigDir(path, configFile);
    }

    try {
      configureHandlers(filePath, level, consoleEnabled);
      LOG.info("Logging to: {}", filePath.toAbsolutePath());
    } catch (Exception e) {
      String msg = "Failed to initialize file logging at: " + filePath.toAbsolutePath() + " — " + e.getMessage();
      if (failOnError) {
        throw new IllegalStateException(msg, e);
      }
      System.err.println(msg);
      System.err.println("Falling back to console-only logging.");
      try {
        configureHandlers(null, level, true);
      } catch (Exception ignore) {
        // last resort: leave existing logging as-is
      }
    }
  }

  private static void configureHandlers(Path filePathOrNull, Level level, boolean consoleEnabled) throws Exception {
    java.util.logging.Logger root = java.util.logging.Logger.getLogger("");
    root.setLevel(level);

    // Reset handlers so we don't double-log across restarts in dev.
    for (Handler h : root.getHandlers()) {
      try {
        root.removeHandler(h);
        h.close();
      } catch (Exception ignore) {
      }
    }

    if (consoleEnabled) {
      ConsoleHandler ch = new ConsoleHandler();
      ch.setLevel(level);
      ch.setFormatter(new SimpleFormatter());
      root.addHandler(ch);
    }

    if (filePathOrNull != null) {
      Path filePath = filePathOrNull.toAbsolutePath().normalize();
      Path dir = filePath.getParent();
      if (dir != null) {
        Files.createDirectories(dir);
      }
      if (!Files.exists(filePath)) {
        Files.createFile(filePath);
      }

      // FileHandler uses its own lock and is safe for concurrent logging within the JVM.
      FileHandler fh = new FileHandler(filePath.toString(), true);
      fh.setLevel(level);
      fh.setFormatter(new TrustSignLogFormatter());
      root.addHandler(fh);
    }
  }

  private static Path resolveAgainstConfigDir(String path, File configFile) {
    Path p = Path.of(path.trim());
    if (p.isAbsolute()) return p.normalize();
    Path base = (configFile != null && configFile.getParentFile() != null)
        ? configFile.getParentFile().toPath()
        : Path.of(System.getProperty("user.dir", "."));
    return base.resolve(p).normalize();
  }

  private static Path defaultLogPath(File configFile) {
    Path base = (configFile != null && configFile.getParentFile() != null)
        ? configFile.getParentFile().toPath()
        : Path.of(System.getProperty("user.dir", "."));
    return base.resolve("logs").resolve("trustsign.log").normalize();
  }

  private static Level parseLevelOrDefault(String s, Level def) {
    if (s == null || s.isBlank()) return def;
    String t = s.trim().toUpperCase(Locale.ROOT);
    try {
      return Level.parse(t);
    } catch (Exception ignore) {
      return def;
    }
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) return a.trim();
    if (b != null && !b.isBlank()) return b.trim();
    return null;
  }

  private static final class TrustSignLogFormatter extends Formatter {
    @Override
    public String format(LogRecord r) {
      String ts = TS_FMT.format(Instant.ofEpochMilli(r.getMillis()));
      String lvl = r.getLevel() != null ? r.getLevel().getName() : "INFO";
      String msg = formatMessage(r);
      return ts + " [" + lvl + "] " + Objects.toString(msg, "") + System.lineSeparator();
    }
  }

  private LoggingInitializer() {}
}

