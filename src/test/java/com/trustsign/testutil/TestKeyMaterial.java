package com.trustsign.testutil;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Generates an in-memory RSA keypair + self-signed X.509 certificate for unit
 * tests that need a "signing certificate" without a physical PKCS#11 token.
 */
public final class TestKeyMaterial {

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public record Material(PrivateKey privateKey, X509Certificate certificate) {}

  public static Material selfSigned(String subjectCn) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair keyPair = kpg.generateKeyPair();

    X500Name name = new X500Name("CN=" + subjectCn + ",O=TrustSign Test,C=IN");
    Date notBefore = new Date(System.currentTimeMillis() - 60_000L);
    Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
    BigInteger serial = BigInteger.valueOf(System.nanoTime());

    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        name, serial, notBefore, notAfter, name, keyPair.getPublic());
    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider("BC")
        .build(keyPair.getPrivate());
    X509Certificate cert = new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(builder.build(signer));

    return new Material(keyPair.getPrivate(), cert);
  }

  private TestKeyMaterial() {}
}
