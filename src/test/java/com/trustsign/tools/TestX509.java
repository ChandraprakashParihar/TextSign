package com.trustsign.tools;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

public final class TestX509 {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public static X509Certificate selfSigned(String dn, KeyPair kp, BigInteger serial) throws Exception {
    Date now = new Date();
    Date end = new Date(now.getTime() + 86400000L);
    X500Name name = new X500Name(dn);
    var builder = new JcaX509v3CertificateBuilder(name, serial, now, end, name, kp.getPublic());
    var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
    return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
  }

  private TestX509() {}
}
