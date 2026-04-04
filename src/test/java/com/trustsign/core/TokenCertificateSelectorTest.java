package com.trustsign.core;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class TokenCertificateSelectorTest {

  @Test
  void signerCertificatesMatch_serialAndIssuer() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    X509Certificate a = com.trustsign.tools.TestX509.selfSigned("CN=test", kp, BigInteger.ONE);
    X509Certificate b = com.trustsign.tools.TestX509.selfSigned("CN=test", kp, BigInteger.ONE);
    assertTrue(TokenCertificateSelector.signerCertificatesMatch(a, b));
  }

  @Test
  void signerCertificatesMatch_differentSerialDoesNotMatchUnlessSamePublicKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    X509Certificate a = com.trustsign.tools.TestX509.selfSigned("CN=test", kp, BigInteger.ONE);
    X509Certificate b = com.trustsign.tools.TestX509.selfSigned("CN=test", kp, BigInteger.TWO);
    assertFalse(a.getSerialNumber().equals(b.getSerialNumber()));
    // same public key → still matches via fallback
    assertTrue(TokenCertificateSelector.signerCertificatesMatch(a, b));
  }
}
