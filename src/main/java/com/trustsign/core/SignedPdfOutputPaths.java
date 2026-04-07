package com.trustsign.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Naming and atomic reservation for signed file outputs under a directory.
 *
 * <p>Plain signed outputs use {@code stem-signed.ext}, then {@code stem-signed1.ext}, … CMS text
 * outputs use {@code stem-cms-signed.ext}, {@code stem-cms-signed1.ext}, … PDF auto-sign uses the
 * same {@code -signed} pattern with {@code .pdf}.
 *
 * <p>Reservation uses {@code CREATE_NEW} so concurrent writers never claim the same path.
 */
public final class SignedPdfOutputPaths {

  private static final int MAX_SIGNED_VARIANTS = 99_999;

  private SignedPdfOutputPaths() {}

  /**
   * Strips the last extension, then repeated trailing {@code -tag} / {@code -tagN} (e.g. tag
   * {@code signed} → {@code -signed}, {@code -signed2}; tag {@code cms-signed} → {@code -cms-signed1}).
   *
   * @param sanitizedFilename filename only (no path), already safe as a single path segment
   */
  public static String stemForSignedOutput(String sanitizedFilename) {
    return stemForTaggedOutput(sanitizedFilename, "signed");
  }

  /**
   * Ensures {@code outputDir} exists, then atomically reserves the next free PDF path by creating an
   * empty file. Caller truncates-writes PDF bytes or deletes on failure.
   */
  public static Path reserveNextSignedPdfPath(
      Path outputDir, String uploadFilename, UnaryOperator<String> sanitizeFilename) throws IOException {
    return reserveTagged(outputDir, uploadFilename, sanitizeFilename, "signed", "document.pdf");
  }

  /**
   * Same as PDF reservation for text outputs: {@code stem-signed.txt}, {@code stem-signed1.txt}, …
   */
  public static Path reserveNextSignedTextPath(
      Path outputDir, String uploadFilename, UnaryOperator<String> sanitizeFilename) throws IOException {
    return reserveTagged(outputDir, uploadFilename, sanitizeFilename, "signed", "text.txt");
  }

  /**
   * CMS text outputs: {@code stem-cms-signed.ext}, {@code stem-cms-signed1.ext}, …
   */
  public static Path reserveNextCmsSignedTextPath(
      Path outputDir, String uploadFilename, UnaryOperator<String> sanitizeFilename) throws IOException {
    return reserveTagged(outputDir, uploadFilename, sanitizeFilename, "cms-signed", "text.txt");
  }

  /**
   * Previous file in the numbered sequence for incremental PDF signing: {@code stem-signedN.ext} →
   * {@code stem-signed(N-1).ext}, {@code stem-signed1.ext} → {@code stem-signed.ext}. Returns null for
   * unnumbered targets or non-matching names.
   */
  public static File predecessorForIncrementalChain(File targetOutFile) {
    return predecessorForTaggedChain(targetOutFile, "signed");
  }

  private static String stemForTaggedOutput(String sanitizedFilename, String tag) {
    String base = stripLastExtension(sanitizedFilename);
    String end = "(?i)-" + Pattern.quote(tag) + "\\d*$";
    while (base.matches("(?i).+-" + Pattern.quote(tag) + "\\d*")) {
      base = base.replaceFirst(end, "");
    }
    return base.isBlank() ? "document" : base;
  }

  private static File predecessorForTaggedChain(File targetOutFile, String tag) {
    String name = targetOutFile.getName();
    int dot = name.lastIndexOf('.');
    String ext = dot > 0 ? name.substring(dot) : "";
    String base = dot > 0 ? name.substring(0, dot) : name;
    Pattern numbered = Pattern.compile("(?i)^(.+)-" + Pattern.quote(tag) + "(\\d+)$");
    Matcher m = numbered.matcher(base);
    if (!m.matches()) {
      return null;
    }
    String stem = m.group(1);
    int n = Integer.parseInt(m.group(2));
    File dir = targetOutFile.getParentFile();
    if (n <= 1) {
      return new File(dir, stem + "-" + tag + ext);
    }
    return new File(dir, stem + "-" + tag + (n - 1) + ext);
  }

  private static Path reserveTagged(
      Path outputDir,
      String uploadFilename,
      UnaryOperator<String> sanitizeFilename,
      String tag,
      String blankDefault)
      throws IOException {
    Files.createDirectories(outputDir);
    String raw = uploadFilename == null || uploadFilename.isBlank() ? blankDefault : uploadFilename;
    String sanitized = sanitizeFilename.apply(raw);
    String stem = stemForTaggedOutput(sanitized, tag);
    String ext = extensionSuffix(sanitized);
    Path dir = outputDir.toAbsolutePath().normalize();

    Path first = dir.resolve(stem + "-" + tag + ext);
    try {
      Files.createFile(first);
      return first;
    } catch (FileAlreadyExistsException e) {
      // try numbered variants
    }

    for (int n = 1; ; n++) {
      if (n > MAX_SIGNED_VARIANTS) {
        throw new IllegalStateException("Too many signed file variants for stem: " + stem + " (tag=" + tag + ")");
      }
      Path candidate = dir.resolve(stem + "-" + tag + n + ext);
      try {
        Files.createFile(candidate);
        return candidate;
      } catch (FileAlreadyExistsException e) {
        // continue
      }
    }
  }

  private static String extensionSuffix(String sanitizedFilename) {
    int dot = sanitizedFilename.lastIndexOf('.');
    if (dot <= 0 || dot >= sanitizedFilename.length() - 1) {
      return "";
    }
    return sanitizedFilename.substring(dot);
  }

  private static String stripLastExtension(String name) {
    int dot = name.lastIndexOf('.');
    if (dot <= 0) {
      return name;
    }
    return name.substring(0, dot);
  }
}
