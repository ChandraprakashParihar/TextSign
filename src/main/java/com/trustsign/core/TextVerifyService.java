package com.trustsign.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;

public final class TextVerifyService {

  private static final Logger LOG = LoggerFactory.getLogger(TextVerifyService.class);

  private static final ThreadLocal<String> TARGET_HASH = new ThreadLocal<>();

  // ── Result record — includes certificate details ───────────────────────────

  public record CertificateInfo(
      String subject,
      String issuer,
      String serialNumber,
      String validFrom,
      String validTo,
      String algorithm,
      String email) {
  }

  public record Result(
      boolean ok,
      String reason,
      CertificateInfo certificate) {

    // Convenience constructor for early failures before cert is parsed
    public static Result failure(String reason) {
      return new Result(false, reason, null);
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Verify a signed text file produced by XtraTrust NCode signer.
   * Only the signed file is required — the original file bytes are extracted
   * internally from the content that precedes the signature block.
   *
   * @param signedFileBytes Raw bytes of the signed file as uploaded.
   */
  public static Result verify(byte[] signedFileBytes) {
    if (signedFileBytes == null || signedFileBytes.length == 0)
      return Result.failure("Signed file is empty");

    try {
      // Decode as UTF-8 string for tag parsing
      String signedText = new String(signedFileBytes, StandardCharsets.UTF_8);

      // ── 1. Parse signature blocks ──────────────────────────────────────
      int sigStart = signedText.indexOf("<START-SIGNATURE>");
      if (sigStart < 0)
        return Result.failure("Signature markers not found");

      String textBeforeSig = signedText.substring(0, sigStart);
      String sigB64 = between(signedText, "<START-SIGNATURE>", "</START-SIGNATURE>");
      String certB64 = between(signedText, "<START-CERTIFICATE>", "</START-CERTIFICATE>");

      if (sigB64 == null || sigB64.isBlank())
        return Result.failure("Empty signature block");
      if (certB64 == null || certB64.isBlank())
        return Result.failure("Empty certificate block");

      byte[] sigBytes = Base64.getDecoder().decode(sigB64.trim());
      byte[] certBytes = Base64.getDecoder().decode(certB64.trim());

      // ── 2. Parse certificate ───────────────────────────────────────────
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
      PublicKey publicKey = cert.getPublicKey();

      LOG.info("Subject : {}", cert.getSubjectX500Principal());
      LOG.info("Issuer  : {}", cert.getIssuerX500Principal());
      LOG.info("Key algo: {}", publicKey.getAlgorithm());
      LOG.info("Sig len : {}", sigBytes.length);

      // Build certificate info — returned in every response
      CertificateInfo certInfo = buildCertInfo(cert);

      // Store target hash for diagnostics
      TARGET_HASH.set(extractTargetHash(sigBytes, publicKey));
      LOG.info("Target  : {}", TARGET_HASH.get());

      // ── 3. Build candidates ────────────────────────────────────────────
      //
      // Two byte sources:
      // A) Raw signed file prefix (bytes before <START-SIGNATURE> tag)
      // — preserves exact bytes, no String encoding side-effects
      // B) String-decoded prefix re-encoded as UTF-8
      // — may differ if String constructor normalised line endings
      //
      // For each source we generate all newline/BOM/CRLF variants so we
      // can match regardless of how the NCode signer normalised the content
      // before hashing.

      List<byte[]> rawList = new ArrayList<>();

      // Source A — raw byte prefix
      int tagOff = indexOf(signedFileBytes,
          "<START-SIGNATURE>".getBytes(StandardCharsets.UTF_8));
      if (tagOff >= 0) {
        byte[] rawPrefix = Arrays.copyOf(signedFileBytes, tagOff);
        LOG.info("Source A hex: " + toHex(rawPrefix));
        rawList.addAll(allVariants(rawPrefix));
      }

      // Source B — String-decoded prefix
      byte[] textBytes = textBeforeSig.getBytes(StandardCharsets.UTF_8);
      LOG.info("Source B hex: " + toHex(textBytes));
      rawList.addAll(allVariants(textBytes));

      List<byte[]> unique = deduplicate(rawList);
      LOG.info("Total unique candidates: " + unique.size());

      // ── 4. Try SHA*withRSA ─────────────────────────────────────────────
      String[] algorithms = {
          "SHA256withRSA", "SHA1withRSA", "SHA384withRSA", "SHA512withRSA"
      };

      for (String algo : algorithms) {
        for (byte[] candidate : unique) {
          try {
            Signature sig = Signature.getInstance(algo);
            sig.initVerify(publicKey);
            sig.update(candidate);
            if (sig.verify(sigBytes)) {
              TARGET_HASH.remove();
              LOG.info("Verified with algo=" + algo + " payloadBytes=" + candidate.length);
              return new Result(true,
                  "Signature valid [algo=" + algo
                      + ", payloadBytes=" + candidate.length + "]",
                  certInfo);
            }
          } catch (Exception e) {
            LOG.warn("SHA algo={} len={} exception={}", algo, candidate.length, e.getMessage());
          }
        }
      }

      // ── 5. Try NONEwithRSA over pre-computed digest ────────────────────
      String[] digestAlgos = { "SHA-256", "SHA-1", "SHA-384", "SHA-512" };
      for (String digestAlgo : digestAlgos) {
        for (byte[] candidate : unique) {
          try {
            byte[] digest = MessageDigest.getInstance(digestAlgo).digest(candidate);
            Signature sig = Signature.getInstance("NONEwithRSA");
            sig.initVerify(publicKey);
            sig.update(digest);
            if (sig.verify(sigBytes)) {
              TARGET_HASH.remove();
              LOG.info("Verified with NONEwithRSA+" + digestAlgo
                  + " payloadBytes=" + candidate.length);
              return new Result(true,
                  "Signature valid [NONEwithRSA+" + digestAlgo
                      + ", payloadBytes=" + candidate.length + "]",
                  certInfo);
            }
          } catch (Exception e) {
            LOG.warn("NONEwithRSA digest={} len={} exception={}", digestAlgo, candidate.length, e.getMessage());
          }
        }
      }

      // ── 6. Failure diagnostics ─────────────────────────────────────────
      LOG.warn("All verification attempts failed.");
      logCandidateHashes(unique);
      TARGET_HASH.remove();

      // Still return cert info even on failure — useful for the caller to
      // show who signed and when, even if the content has been tampered with
      return new Result(false,
          "Signature invalid — content may have been modified",
          certInfo);

    } catch (Exception e) {
      TARGET_HASH.remove();
      String msg = e.getMessage();
      return Result.failure(msg != null && !msg.isBlank()
          ? msg
          : e.getClass().getSimpleName());
    }
  }

  // ── Debug endpoint helper — REMOVE BEFORE PRODUCTION ──────────────────────

  public static Map<String, Object> debugBytes(byte[] signedFileBytes) {
    try {
      byte[] sigTag = "<START-SIGNATURE>".getBytes(StandardCharsets.UTF_8);
      int tagOff = indexOf(signedFileBytes, sigTag);
      byte[] rawPrefix = tagOff >= 0 ? Arrays.copyOf(signedFileBytes, tagOff) : new byte[0];

      String signedText = new String(signedFileBytes, StandardCharsets.UTF_8);
      String sigB64 = between(signedText, "<START-SIGNATURE>", "</START-SIGNATURE>");
      String certB64 = between(signedText, "<START-CERTIFICATE>", "</START-CERTIFICATE>");

      String targetHash = "unavailable";
      if (sigB64 != null && certB64 != null) {
        byte[] sigBytes = Base64.getDecoder().decode(sigB64.trim());
        byte[] certBytes = Base64.getDecoder().decode(certB64.trim());
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        targetHash = extractTargetHash(sigBytes, cert.getPublicKey());
      }

      return Map.of(
          "signedFile_prefix_len", rawPrefix.length,
          "signedFile_prefix_hex", toHex(rawPrefix),
          "signedFile_prefix_sha1", toHex(sha1(rawPrefix)),
          "target_hash_in_sig", targetHash);
    } catch (Exception e) {
      return Map.of("error", String.valueOf(e.getMessage()));
    }
  }

  // ── Certificate info builder ───────────────────────────────────────────────

  private static CertificateInfo buildCertInfo(X509Certificate cert) {
    // Extract email from Subject Alternative Names or CN field
    String email = extractEmail(cert);

    return new CertificateInfo(
        cert.getSubjectX500Principal().getName(),
        cert.getIssuerX500Principal().getName(),
        cert.getSerialNumber().toString(16).toUpperCase(),
        cert.getNotBefore().toInstant().toString(),
        cert.getNotAfter().toInstant().toString(),
        cert.getSigAlgName(),
        email);
  }

  private static String extractEmail(X509Certificate cert) {
    // Try Subject Alternative Names first
    try {
      var sans = cert.getSubjectAlternativeNames();
      if (sans != null) {
        for (var san : sans) {
          // SAN type 1 = rfc822Name (email)
          if (san.size() >= 2 && Integer.valueOf(1).equals(san.get(0))) {
            return String.valueOf(san.get(1));
          }
        }
      }
    } catch (Exception ignored) {
    }

    // Fall back to parsing CN or EMAILADDRESS from subject DN
    String dn = cert.getSubjectX500Principal().getName();
    for (String part : dn.split(",")) {
      part = part.trim();
      if (part.toLowerCase().startsWith("emailaddress=")
          || part.toLowerCase().startsWith("e=")) {
        return part.substring(part.indexOf('=') + 1);
      }
    }
    return null;
  }

  // ── Variant generation ─────────────────────────────────────────────────────

  private static List<byte[]> allVariants(byte[] src) {
    LinkedHashMap<String, byte[]> m = new LinkedHashMap<>();

    // Tier 1 — raw and simple appends
    m.put("as-is", src);
    m.put("+lf", cat(src, '\n'));
    m.put("+crlf", cat(src, '\r', '\n'));
    m.put("+cr", cat(src, '\r'));

    // Tier 2 — strip trailing newline variants
    if (endsWith(src, '\r', '\n')) {
      byte[] s = trim(src, 2);
      m.put("-crlf", s);
      m.put("-crlf+lf", cat(s, '\n'));
      m.put("-crlf+cr", cat(s, '\r'));
    }
    if (endsWith(src, '\n')) {
      byte[] s = trim(src, 1);
      m.put("-lf", s);
      m.put("-lf+crlf", cat(s, '\r', '\n'));
      m.put("-lf+cr", cat(s, '\r'));
    }
    if (endsWith(src, '\r')) {
      byte[] s = trim(src, 1);
      m.put("-cr", s);
      m.put("-cr+lf", cat(s, '\n'));
      m.put("-cr+crlf", cat(s, '\r', '\n'));
    }

    // Tier 3 — whole-content line-ending normalisation
    byte[] lfToCrlf = normLfToCrlf(src);
    byte[] crlfToLf = normCrlfToLf(src);

    if (!Arrays.equals(lfToCrlf, src)) {
      m.put("lf>crlf", lfToCrlf);
      m.put("lf>crlf+lf", cat(lfToCrlf, '\n'));
      m.put("lf>crlf+crlf", cat(lfToCrlf, '\r', '\n'));
      if (endsWith(lfToCrlf, '\r', '\n'))
        m.put("lf>crlf-crlf", trim(lfToCrlf, 2));
    }
    if (!Arrays.equals(crlfToLf, src)) {
      m.put("crlf>lf", crlfToLf);
      m.put("crlf>lf+lf", cat(crlfToLf, '\n'));
      m.put("crlf>lf+crlf", cat(crlfToLf, '\r', '\n'));
    }

    // Tier 4 — UTF-8 BOM (0xEF 0xBB 0xBF)
    byte[] bom = { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF };
    if (!startsWith(src, bom)) {
      byte[] bomSrc = cat(bom, src);
      m.put("bom", bomSrc);
      m.put("bom+lf", cat(bomSrc, '\n'));
      m.put("bom+crlf", cat(bomSrc, '\r', '\n'));
      if (!Arrays.equals(lfToCrlf, src)) {
        byte[] bomCrlf = cat(bom, lfToCrlf);
        m.put("bom+lf>crlf", bomCrlf);
        m.put("bom+lf>crlf+lf", cat(bomCrlf, '\n'));
      }
    }

    return new ArrayList<>(m.values());
  }

  // ── Byte utilities ─────────────────────────────────────────────────────────

  private static byte[] cat(byte[] a, char... extra) {
    byte[] out = new byte[a.length + extra.length];
    System.arraycopy(a, 0, out, 0, a.length);
    for (int i = 0; i < extra.length; i++)
      out[a.length + i] = (byte) extra[i];
    return out;
  }

  private static byte[] cat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  private static byte[] trim(byte[] src, int removeFromEnd) {
    return Arrays.copyOf(src, src.length - removeFromEnd);
  }

  private static boolean endsWith(byte[] src, char... suffix) {
    if (src.length < suffix.length)
      return false;
    for (int i = 0; i < suffix.length; i++) {
      if (src[src.length - suffix.length + i] != (byte) suffix[i])
        return false;
    }
    return true;
  }

  private static boolean startsWith(byte[] src, byte[] prefix) {
    if (src.length < prefix.length)
      return false;
    for (int i = 0; i < prefix.length; i++) {
      if (src[i] != prefix[i])
        return false;
    }
    return true;
  }

  private static byte[] normLfToCrlf(byte[] src) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(src.length + 8);
    for (int i = 0; i < src.length; i++) {
      if (src[i] == '\n' && (i == 0 || src[i - 1] != '\r'))
        out.write('\r');
      out.write(src[i]);
    }
    return out.toByteArray();
  }

  private static byte[] normCrlfToLf(byte[] src) {
    ByteArrayOutputStream out = new ByteArrayOutputStream(src.length);
    for (int i = 0; i < src.length; i++) {
      if (src[i] == '\r' && i + 1 < src.length && src[i + 1] == '\n')
        continue;
      out.write(src[i]);
    }
    return out.toByteArray();
  }

  private static int indexOf(byte[] haystack, byte[] needle) {
    outer: for (int i = 0; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j])
          continue outer;
      }
      return i;
    }
    return -1;
  }

  private static List<byte[]> deduplicate(List<byte[]> list) {
    List<byte[]> result = new ArrayList<>();
    outer: for (byte[] c : list) {
      for (byte[] e : result) {
        if (Arrays.equals(e, c))
          continue outer;
      }
      result.add(c);
    }
    return result;
  }

  // ── String parsing ─────────────────────────────────────────────────────────

  private static String between(String text, String startTag, String endTag) {
    int s = text.indexOf(startTag);
    if (s < 0)
      return null;
    int start = s + startTag.length();
    int e = text.indexOf(endTag, start);
    if (e < 0)
      return null;
    return text.substring(start, e).trim();
  }

  // ── Crypto helpers ─────────────────────────────────────────────────────────

  private static byte[] sha1(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-1").digest(data);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static String toHex(byte[] data) {
    StringBuilder sb = new StringBuilder(data.length * 2);
    for (byte b : data)
      sb.append(String.format("%02x", b));
    return sb.toString();
  }

  private static String extractTargetHash(byte[] sigBytes, PublicKey publicKey) {
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, publicKey);
      byte[] recovered = cipher.doFinal(sigBytes);
      for (int i = 0; i < recovered.length - 1; i++) {
        if (recovered[i] == 0x00 && recovered[i + 1] == 0x30) {
          byte[] digestInfo = Arrays.copyOfRange(recovered, i + 1, recovered.length);
          int hashLen = switch (digestInfo.length) {
            case 35 -> 20; // SHA-1
            case 51 -> 32; // SHA-256
            case 67 -> 48; // SHA-384
            case 83 -> 64; // SHA-512
            default -> digestInfo.length - 15;
          };
          return toHex(Arrays.copyOfRange(
              digestInfo, digestInfo.length - hashLen, digestInfo.length));
        }
      }
    } catch (Exception e) {
      LOG.warn("extractTargetHash failed: {}", e.getMessage());
    }
    return "unknown";
  }

  // ── Diagnostic logging ─────────────────────────────────────────────────────

  private static void logCandidateHashes(List<byte[]> unique) {
    String target = TARGET_HASH.get();
    LOG.warn("── Candidate table (target={}) ──────────────────", target);
    for (int i = 0; i < unique.size(); i++) {
      byte[] c = unique.get(i);
      String sha1h = toHex(sha1(c));
      String marker = sha1h.equals(target) ? "  <<< MATCH !!!" : "";
      LOG.warn(String.format("[%02d] len=%-4d hex=%-20s sha1=%s%s",
          i, c.length, toHex(c), sha1h, marker));
    }
    LOG.warn("────────────────────────────────────────────────────────────");
  }

  private TextVerifyService() {
  }
}