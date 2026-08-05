package com.trustsign.core;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Produces an enveloped XML-DSig signature (W3C standard) embedded directly
 * inside the signed XML document, verifiable by any standard XML-DSig tool.
 */
public final class XmlSignerService {

  /**
   * JSR-105 property that binds the actual RSA signing operation to a specific
   * {@link Provider} instead of letting the JVM pick a default one. Required
   * for PKCS#11 tokens: without it, the JDK's XML-DSig implementation may try
   * to translate the (non-extractable) token key to another provider and fail
   * with {@code InvalidKeyException: Missing key encoding} — the same class of
   * issue solved for PDF signing via {@code ProviderBoundPrivateKeySignature}.
   */
  private static final String SIGNATURE_PROVIDER_PROPERTY =
      "org.jcp.xml.dsig.internal.dom.SignatureProvider";

  public static byte[] sign(
      byte[] xmlBytes,
      PrivateKey privateKey,
      Certificate[] chain,
      Provider p11Provider) throws Exception {
    if (xmlBytes == null || xmlBytes.length == 0) {
      throw new IllegalArgumentException("xmlBytes is empty");
    }
    if (privateKey == null) {
      throw new IllegalArgumentException("privateKey is null");
    }
    if (chain == null || chain.length == 0) {
      throw new IllegalArgumentException("certificate chain is empty");
    }
    if (p11Provider == null) {
      throw new IllegalArgumentException("p11Provider is null");
    }

    Document doc = XmlSecurity.parseHardened(xmlBytes);

    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    Reference ref = fac.newReference(
        "",
        fac.newDigestMethod(DigestMethod.SHA256, null),
        Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
        null,
        null);

    SignedInfo signedInfo = fac.newSignedInfo(
        fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
        fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
        Collections.singletonList(ref));

    KeyInfoFactory kif = fac.getKeyInfoFactory();
    List<Object> x509Content = new ArrayList<>();
    for (Certificate c : chain) {
      if (c instanceof X509Certificate) {
        x509Content.add(c);
      }
    }
    if (x509Content.isEmpty()) {
      throw new IllegalArgumentException("certificate chain does not contain X509Certificate entries");
    }
    X509Data x509Data = kif.newX509Data(x509Content);
    KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(x509Data));

    XMLSignature signature = fac.newXMLSignature(signedInfo, keyInfo);

    Element root = doc.getDocumentElement();
    if (root == null) {
      throw new IllegalArgumentException("XML document has no root element");
    }
    XMLSignContext signContext = new DOMSignContext(privateKey, root);
    signContext.setProperty(SIGNATURE_PROVIDER_PROPERTY, p11Provider);

    signature.sign(signContext);

    return serialize(doc);
  }

  /**
   * Parses {@code xmlBytes} with the same XXE-hardened parser used by {@link #sign},
   * throwing if it isn't well-formed XML. Lets callers fail fast with a clear
   * error before doing any token/certificate work.
   */
  public static void validateWellFormed(byte[] xmlBytes) throws Exception {
    XmlSecurity.parseHardened(xmlBytes);
  }

  private static byte[] serialize(Document doc) throws Exception {
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    transformer.transform(new DOMSource(doc), new StreamResult(out));
    return out.toByteArray();
  }

  private XmlSignerService() {}
}
