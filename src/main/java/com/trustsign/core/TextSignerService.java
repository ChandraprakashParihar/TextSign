package com.trustsign.core;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.stream.Collectors;

public final class TextSignerService {
  private static final Logger LOG = LoggerFactory.getLogger(TextSignerService.class);
  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  /**
   * Creates a detached CMS (PKCS#7) signature over the given content.
   * This is kept for compatibility with existing consumers that expect
   * a full CMS container.
   */
  public static byte[] signDetached(
      byte[] content,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider
  ) throws Exception {
    return signDetached(content, privateKey, chain, p11Provider, null);
  }

  public static byte[] signDetached(
      byte[] content,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider,
      TsaClient.Config tsaConfig
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
    TsaClient.Config cfg = tsaConfig == null ? TsaClient.Config.DISABLED : tsaConfig;
    if (!cfg.enabled()) {
      return signedData.getEncoded();
    }
    try {
      CMSSignedData tsData = addRfc3161SignatureTimestamp(signedData, cfg);
      return tsData.getEncoded();
    } catch (Exception e) {
      if (cfg.failOnError()) {
        throw e;
      }
      LOG.warn("TSA timestamp failed; continuing without timestamp: {}", e.getMessage());
      return signedData.getEncoded();
    }
  }

  private static CMSSignedData addRfc3161SignatureTimestamp(CMSSignedData cms, TsaClient.Config cfg) throws Exception {
    TsaClient tsa = new TsaClient(cfg);
    java.util.List<SignerInformation> out = new java.util.ArrayList<>();
    for (SignerInformation si : cms.getSignerInfos().getSigners()) {
      byte[] token = tsa.requestTimestampToken(si.getSignature());
      ASN1EncodableVector v = new ASN1EncodableVector();
      AttributeTable unsigned = si.getUnsignedAttributes();
      if (unsigned != null) {
        for (Object key : unsigned.toHashtable().keySet()) {
          ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) key;
          v.add(unsigned.get(oid));
        }
      }
      ASN1ObjectIdentifier tsOid = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.14"); // id-aa-signatureTimeStampToken 1.2.840.113549.1.9.16.2.14
      v.add(new Attribute(tsOid, new DERSet(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(token))));
      SignerInformation replaced = SignerInformation.replaceUnsignedAttributes(si, new AttributeTable(v));
      out.add(replaced);
    }
    return CMSSignedData.replaceSigners(cms, new SignerInformationStore(out));
  }

  /**
   * Creates a raw RSA signature (RSASSA-PKCS1-v1_5) over the given content
   * using SHA-256 as the digest. The resulting bytes are suitable for direct
   * Base64 encoding inside &lt;START-SIGNATURE&gt; ... &lt;/START-SIGNATURE&gt;.
   * Uses SHA256withRSA only (Bouncy Castle / PKCS#11).
   */
  public static byte[] signRawSha256WithRsa(
      byte[] content,
      PrivateKey privateKey,
      Provider p11Provider
  ) throws Exception {
    if (content == null) throw new IllegalArgumentException("content is null");
    if (privateKey == null) throw new IllegalArgumentException("privateKey is null");
    if (p11Provider == null) throw new IllegalArgumentException("p11Provider is null");

    Signature signature = Signature.getInstance("SHA256withRSA", p11Provider);
    signature.initSign(privateKey);
    signature.update(content);
    return signature.sign();
  }

  private TextSignerService() {}
}

