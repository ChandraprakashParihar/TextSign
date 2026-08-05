package com.trustsign.core;

import com.trustsign.testutil.TestKeyMaterial;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the CSV signing flow's core logic (CmsTaggedFile + TextSignerService
 * + CmsVerifyService) without needing a physical PKCS#11 token or the HTTP layer.
 */
class CmsTaggedFileTest {

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  void signAndVerifyRoundTrip_succeeds() throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("CSV Test Signer");
    byte[] csvBytes = ("id,name,amount\r\n1,Widget,9.99\r\n2,Gadget,19.99\r\n")
        .getBytes(StandardCharsets.UTF_8);

    byte[] cmsBytes = TextSignerService.signDetached(
        csvBytes, material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC"));
    byte[] signedBytes = CmsTaggedFile.append(csvBytes, cmsBytes);

    // The exact original bytes (including CRLF line endings) must be preserved
    // verbatim ahead of the tag — no normalization, unlike plain-text signing.
    CmsTaggedFile.Parsed parsed = CmsTaggedFile.parse(signedBytes);
    assertArrayEquals(csvBytes, parsed.content());

    CmsVerifyService.Result result = CmsVerifyService.verify(parsed.content(), parsed.cmsBytes());
    assertTrue(result.ok(), () -> "expected verification to succeed: " + result.reason());
    assertEquals(
        material.certificate().getSerialNumber(),
        result.signerCert().getSerialNumber());
  }

  @Test
  void verify_failsWhenContentTampered() throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("CSV Tamper Test");
    byte[] csvBytes = "id,amount\n1,10.00\n".getBytes(StandardCharsets.UTF_8);

    byte[] cmsBytes = TextSignerService.signDetached(
        csvBytes, material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC"));
    byte[] signedBytes = CmsTaggedFile.append(csvBytes, cmsBytes);

    CmsTaggedFile.Parsed parsed = CmsTaggedFile.parse(signedBytes);
    byte[] tamperedContent = new String(parsed.content(), StandardCharsets.UTF_8)
        .replace("10.00", "99.00")
        .getBytes(StandardCharsets.UTF_8);

    CmsVerifyService.Result result = CmsVerifyService.verify(tamperedContent, parsed.cmsBytes());
    assertFalse(result.ok());
  }

  @Test
  void parse_throwsWhenTagMissing() {
    byte[] noTag = "just,a,csv\n1,2,3\n".getBytes(StandardCharsets.UTF_8);
    assertThrows(IllegalArgumentException.class, () -> CmsTaggedFile.parse(noTag));
  }

  @Test
  void parse_throwsWhenEndTagMissing() {
    byte[] malformed = "content\n<START-CMS-SIGNATURE>bm90LXJlYWwtYmFzZTY0"
        .getBytes(StandardCharsets.UTF_8);
    assertThrows(IllegalArgumentException.class, () -> CmsTaggedFile.parse(malformed));
  }
}
