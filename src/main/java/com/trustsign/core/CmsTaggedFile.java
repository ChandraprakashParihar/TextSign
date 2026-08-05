package com.trustsign.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Appends/parses the {@code <START-CMS-SIGNATURE>...</START-CMS-SIGNATURE>} tag
 * convention already used by {@code /auto-sign-text-cms}, now shared with CSV
 * signing. The signed content is always everything before the tag — signing
 * must not alter the original bytes (byte-for-byte fidelity matters for
 * CSV/data files, unlike plain-text signing which normalizes line endings).
 */
public final class CmsTaggedFile {

  private static final byte[] START_TAG = "<START-CMS-SIGNATURE>".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] END_TAG = "</START-CMS-SIGNATURE>".getBytes(StandardCharsets.US_ASCII);

  public record Parsed(byte[] content, byte[] cmsBytes) {}

  /** Appends {@code content + "\n" + <START-CMS-SIGNATURE>base64(cmsBytes)</START-CMS-SIGNATURE> + "\n"}. */
  public static byte[] append(byte[] content, byte[] cmsBytes) {
    if (content == null) {
      throw new IllegalArgumentException("content is null");
    }
    if (cmsBytes == null) {
      throw new IllegalArgumentException("cmsBytes is null");
    }
    String cmsB64 = Base64.getEncoder().encodeToString(cmsBytes);
    ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + cmsB64.length() + 64);
    out.write(content, 0, content.length);
    out.write('\n');
    out.writeBytes(START_TAG);
    out.writeBytes(cmsB64.getBytes(StandardCharsets.US_ASCII));
    out.writeBytes(END_TAG);
    out.write('\n');
    return out.toByteArray();
  }

  /**
   * Extracts the original content and CMS bytes from a tagged file.
   *
   * @throws IllegalArgumentException if the tag is missing, malformed, or the
   *     base64 payload cannot be decoded
   */
  public static Parsed parse(byte[] signedBytes) {
    if (signedBytes == null) {
      throw new IllegalArgumentException("signedBytes is null");
    }
    int startIdx = indexOf(signedBytes, START_TAG, 0);
    if (startIdx < 0) {
      throw new IllegalArgumentException("No <START-CMS-SIGNATURE> tag found in file");
    }
    int b64Start = startIdx + START_TAG.length;
    int endIdx = indexOf(signedBytes, END_TAG, b64Start);
    if (endIdx < 0) {
      throw new IllegalArgumentException("Malformed <START-CMS-SIGNATURE> tag (missing end marker)");
    }
    // append() always inserts exactly one '\n' separator between the original
    // content and the tag (purely so the tag lands on its own line when the
    // file is viewed as text) — strip it back off so "content" here is
    // byte-for-byte identical to what was actually signed, regardless of
    // whether the original content itself already ended in a newline.
    int contentEnd = startIdx > 0 && signedBytes[startIdx - 1] == '\n' ? startIdx - 1 : startIdx;
    byte[] content = Arrays.copyOfRange(signedBytes, 0, contentEnd);
    String cmsB64 = new String(signedBytes, b64Start, endIdx - b64Start, StandardCharsets.US_ASCII).trim();
    byte[] cmsBytes;
    try {
      cmsBytes = Base64.getDecoder().decode(cmsB64);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid base64 in CMS signature tag", e);
    }
    return new Parsed(content, cmsBytes);
  }

  private static int indexOf(byte[] haystack, byte[] needle, int fromIndex) {
    if (haystack == null || needle == null || needle.length == 0 || fromIndex < 0) {
      return -1;
    }
    outer: for (int i = fromIndex; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

  private CmsTaggedFile() {}
}
