package com.trustsign.server;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.TimeBasedRollingPolicy;
import com.trustsign.core.AgentConfig;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.logging.LoggingSystem;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Configures Logback from {@code config.json} as early as possible so SLF4J logs (including
 * pre-Spring startup) are written to date-based files and rotated daily without manual intervention.
 */
public final class LoggingInitializer {
  private static final AtomicBoolean INITIALIZED = new AtomicBoolean(false);

  private static final String DEFAULT_LOG_DIRECTORY_NAME = "logs";
  private static final String DEFAULT_LOG_BASE_NAME = "application";
  private static final String DAILY_LOG_SUFFIX = "-%d{yyyy-MM-dd}.log";

  private static final String LOG_FORMAT =
      "%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n";

  public static void initFromConfig(AgentConfig cfg, File configFile) {
    if (cfg == null) {
      return;
    }
    if (!INITIALIZED.compareAndSet(false, true)) {
      return;
    }

    AgentConfig.LoggingConfig lc = cfg.logging();
    boolean failOnError = lc != null && Boolean.TRUE.equals(lc.failOnError());
    boolean consoleEnabled = lc == null || lc.consoleEnabled() == null || lc.consoleEnabled();

    java.util.logging.Level julLevel = parseJulLevelOrDefault(
        lc != null ? lc.level() : null,
        java.util.logging.Level.INFO);
    Level logbackLevel = toLogbackLevel(julLevel);

    LogPathSpec spec;
    try {
      spec = resolveLogPathSpec(cfg, lc, configFile);
    } catch (Exception e) {
      if (failOnError) {
        throw new IllegalStateException("Failed to resolve log path: " + e.getMessage(), e);
      }
      System.err.println("Failed to resolve log path: " + e.getMessage());
      return;
    }

    Path absoluteLogDirectory = spec.directory().toAbsolutePath().normalize();
    String fileNamePattern = spec.fileNamePattern().toAbsolutePath().normalize().toString();

    try {
      Files.createDirectories(absoluteLogDirectory);
    } catch (Exception e) {
      String msg =
          "Failed to create log directory at: "
              + absoluteLogDirectory
              + " — "
              + e.getMessage();
      if (failOnError) {
        throw new IllegalStateException(msg, e);
      }
      System.err.println(msg);
      return;
    }

    // Keep logging controlled here so Spring Boot doesn't reset appenders later.
    System.setProperty(LoggingSystem.SYSTEM_PROPERTY, LoggingSystem.NONE);

    try {
      configureLogbackEarly(fileNamePattern, logbackLevel, consoleEnabled);
      Logger log = LoggerFactory.getLogger(LoggingInitializer.class);
      log.info("Logging to date-based files: {}", fileNamePattern);
    } catch (Exception e) {
      String msg =
          "Failed to initialize daily Logback file logging with pattern: "
              + fileNamePattern
              + " — "
              + e.getMessage();
      if (failOnError) {
        throw new IllegalStateException(msg, e);
      }
      System.err.println(msg);
      System.err.println("Continuing with current logger configuration.");
    }
  }

  private static LogPathSpec resolveLogPathSpec(AgentConfig cfg, AgentConfig.LoggingConfig lc, File configFile) {
    String rawPath = firstNonBlank(lc != null ? lc.filePath() : null, cfg.logFilePath());
    if (rawPath != null && !rawPath.isBlank()) {
      String trimmed = rawPath.trim();
      Path resolved = resolveAgainstConfigDir(trimmed, configFile);
      if (looksLikeDirectoryPath(trimmed) || (Files.exists(resolved) && Files.isDirectory(resolved))) {
        return new LogPathSpec(resolved, DEFAULT_LOG_BASE_NAME);
      }
      Path parent = resolved.getParent();
      Path dir = parent != null ? parent : defaultLogDirectory(configFile);
      String fileName = resolved.getFileName() != null ? resolved.getFileName().toString() : null;
      return new LogPathSpec(dir, baseNameOf(fileName));
    }

    if (lc != null && lc.directory() != null && !lc.directory().isBlank()) {
      Path dir = resolveAgainstConfigDir(lc.directory().trim(), configFile);
      return new LogPathSpec(dir, DEFAULT_LOG_BASE_NAME);
    }

    return new LogPathSpec(defaultLogDirectory(configFile), DEFAULT_LOG_BASE_NAME);
  }

  private static boolean looksLikeDirectoryPath(String rawPath) {
    return rawPath.endsWith("/") || rawPath.endsWith("\\");
  }

  private static String baseNameOf(String fileName) {
    if (fileName == null || fileName.isBlank()) {
      return DEFAULT_LOG_BASE_NAME;
    }
    int dot = fileName.lastIndexOf('.');
    String base = dot > 0 ? fileName.substring(0, dot) : fileName;
    String trimmed = base.trim();
    return trimmed.isEmpty() ? DEFAULT_LOG_BASE_NAME : trimmed;
  }

  private static void configureLogbackEarly(String fileNamePattern, Level rootLevel, boolean consoleEnabled) {
    ILoggerFactory factory = LoggerFactory.getILoggerFactory();
    if (!(factory instanceof LoggerContext)) {
      System.err.println(
          "SLF4J is not bound to Logback (got "
              + factory.getClass().getName()
              + "); file logging may only apply after startup.");
      return;
    }

    LoggerContext context = (LoggerContext) factory;
    context.reset();

    PatternLayoutEncoder fileEncoder = newEncoder(context);
    PatternLayoutEncoder consoleEncoder = newEncoder(context);

    RollingFileAppender<ILoggingEvent> fileAppender = new RollingFileAppender<>();
    fileAppender.setContext(context);
    fileAppender.setAppend(true);
    fileAppender.setImmediateFlush(true);
    fileAppender.setEncoder(fileEncoder);

    TimeBasedRollingPolicy<ILoggingEvent> rollingPolicy = new TimeBasedRollingPolicy<>();
    rollingPolicy.setContext(context);
    rollingPolicy.setParent(fileAppender);
    rollingPolicy.setFileNamePattern(fileNamePattern);
    rollingPolicy.setMaxHistory(30);
    rollingPolicy.setCleanHistoryOnStart(false);
    rollingPolicy.start();

    fileAppender.setRollingPolicy(rollingPolicy);
    fileAppender.start();

    ch.qos.logback.classic.Logger root = context.getLogger(Logger.ROOT_LOGGER_NAME);
    root.setLevel(rootLevel);
    root.setAdditive(false);
    root.addAppender(fileAppender);

    if (consoleEnabled) {
      ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<>();
      consoleAppender.setContext(context);
      consoleAppender.setEncoder(consoleEncoder);
      consoleAppender.start();
      root.addAppender(consoleAppender);
    }
  }

  private static PatternLayoutEncoder newEncoder(LoggerContext context) {
    PatternLayoutEncoder encoder = new PatternLayoutEncoder();
    encoder.setContext(context);
    encoder.setPattern(LOG_FORMAT);
    encoder.start();
    return encoder;
  }

  private static Path resolveAgainstConfigDir(String path, File configFile) {
    Path p = Path.of(path.trim());
    if (p.isAbsolute()) {
      return p.normalize();
    }
    Path base =
        (configFile != null && configFile.getParentFile() != null)
            ? configFile.getParentFile().toPath()
            : Path.of(System.getProperty("user.dir", "."));
    return base.resolve(p).normalize();
  }

  private static Path defaultLogDirectory(File configFile) {
    Path base =
        (configFile != null && configFile.getParentFile() != null)
            ? configFile.getParentFile().toPath()
            : Path.of(System.getProperty("user.dir", "."));
    return base.resolve(DEFAULT_LOG_DIRECTORY_NAME).normalize();
  }

  private static java.util.logging.Level parseJulLevelOrDefault(String s, java.util.logging.Level def) {
    if (s == null || s.isBlank()) {
      return def;
    }
    String t = s.trim().toUpperCase(Locale.ROOT);
    try {
      return java.util.logging.Level.parse(t);
    } catch (Exception ignore) {
      return def;
    }
  }

  private static Level toLogbackLevel(java.util.logging.Level jul) {
    int v = jul.intValue();
    if (v >= java.util.logging.Level.SEVERE.intValue()) {
      return Level.ERROR;
    }
    if (v >= java.util.logging.Level.WARNING.intValue()) {
      return Level.WARN;
    }
    if (v >= java.util.logging.Level.INFO.intValue()) {
      return Level.INFO;
    }
    if (v >= java.util.logging.Level.CONFIG.intValue()) {
      return Level.DEBUG;
    }
    if (v >= java.util.logging.Level.FINE.intValue()) {
      return Level.DEBUG;
    }
    return Level.TRACE;
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) {
      return a.trim();
    }
    if (b != null && !b.isBlank()) {
      return b.trim();
    }
    return null;
  }

  private LoggingInitializer() {}

  private record LogPathSpec(Path directory, String fileBaseName) {
    Path fileNamePattern() {
      return directory.resolve(fileBaseName + DAILY_LOG_SUFFIX);
    }
  }
}
