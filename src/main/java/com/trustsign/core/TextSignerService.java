package com.trustsign.core;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Detached CMS (PKCS#7) signer for arbitrary byte content (e.g. text files).
 */
public final class TextSignerService {
  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   * Creates a detached CMS (PKCS#7) signature over the given content.
   *
   * @param content     bytes to sign (e.g. UTF-8 text file contents)
   * @param privateKey  private key from the PKCS#11 token
   * @param chain       certificate chain (first element is signing cert)
   * @param p11Provider PKCS#11 provider used for signing operations
   * @return encoded CMS/PKCS#7 signature bytes
   */
  public static byte[] signDetached(
      byte[] content,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider
  ) throws Exception {
    if (content == null) throw new IllegalArgumentException("content is null");
    if (privateKey == null) throw new IllegalArgumentException("privateKey is null");
    if (chain == null || chain.length == 0) throw new IllegalArgumentException("certificate chain is empty");

    List<X509Certificate> certs = Arrays.stream(chain)
        .filter(c -> c instanceof X509Certificate)
        .map(c -> (X509Certificate) c)
        .collect(Collectors.toList());
    if (certs.isEmpty()) {
      throw new IllegalArgumentException("certificate chain does not contain X509Certificate entries");
    }

    X509Certificate signingCert = certs.get(0);

    CMSTypedData data = new CMSProcessableByteArray(content);

    var digestProvider = new JcaDigestCalculatorProviderBuilder()
        .setProvider("BC")
        .build();

    var contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider(p11Provider)
        .build(privateKey);

    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    gen.addSignerInfoGenerator(
        new JcaSignerInfoGeneratorBuilder(digestProvider)
            .build(contentSigner, signingCert)
    );

    gen.addCertificates(new JcaCertStore(certs));

    CMSSignedData signedData = gen.generate(data, false); // detached
    return signedData.getEncoded();
  }

  private TextSignerService() {}
}

