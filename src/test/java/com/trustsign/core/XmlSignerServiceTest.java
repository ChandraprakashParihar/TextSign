package com.trustsign.core;

import com.trustsign.testutil.TestKeyMaterial;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XmlSignerServiceTest {

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  void signAndVerifyRoundTrip_succeeds() throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("XML Test Signer");
    byte[] xmlBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        + "<invoice><id>INV-001</id><amount>199.50</amount></invoice>")
        .getBytes(StandardCharsets.UTF_8);

    byte[] signedXml = XmlSignerService.sign(
        xmlBytes, material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC"));

    String signedXmlString = new String(signedXml, StandardCharsets.UTF_8);
    assertTrue(signedXmlString.contains("<Signature"), "signed XML should contain a Signature element");
    assertTrue(signedXmlString.contains("INV-001"), "original content should be preserved (enveloped signature)");

    XmlVerifyService.Result result = XmlVerifyService.verify(signedXml);
    assertTrue(result.ok(), () -> "expected verification to succeed: " + result.reason());
    assertEquals(1, result.signatureCount());
    assertEquals(
        material.certificate().getSerialNumber().toString(16),
        result.signatures().get(0).certificate().serialNumber());
  }

  @Test
  void verify_failsWhenContentTamperedAfterSigning() throws Exception {
    TestKeyMaterial.Material material = TestKeyMaterial.selfSigned("XML Tamper Test");
    byte[] xmlBytes = "<order><item>Widget</item><qty>1</qty></order>".getBytes(StandardCharsets.UTF_8);

    byte[] signedXml = XmlSignerService.sign(
        xmlBytes, material.privateKey(), new Certificate[] { material.certificate() },
        Security.getProvider("BC"));

    String tampered = new String(signedXml, StandardCharsets.UTF_8).replace("<qty>1</qty>", "<qty>999</qty>");

    XmlVerifyService.Result result = XmlVerifyService.verify(tampered.getBytes(StandardCharsets.UTF_8));
    assertFalse(result.ok());
  }

  @Test
  void verify_failsWhenNoSignaturePresent() {
    byte[] plainXml = "<a><b>c</b></a>".getBytes(StandardCharsets.UTF_8);
    XmlVerifyService.Result result = XmlVerifyService.verify(plainXml);
    assertFalse(result.ok());
    assertEquals(0, result.signatureCount());
  }
}
