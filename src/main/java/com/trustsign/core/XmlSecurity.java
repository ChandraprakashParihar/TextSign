package com.trustsign.core;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

/**
 * Shared XXE-hardened XML parsing for {@link XmlSignerService} and
 * {@link XmlVerifyService}. Untrusted XML must never be parsed with DOCTYPE
 * declarations or external entity resolution enabled (OWASP XXE) — this is a
 * real security requirement, not an optional hardening step.
 */
final class XmlSecurity {

  static Document parseHardened(byte[] xmlBytes) throws Exception {
    return parseHardened(new ByteArrayInputStream(xmlBytes));
  }

  static Document parseHardened(InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true); // required for XML-DSig's DOM-based signing/validation
    setFeatureIfSupported(dbf, "http://apache.org/xml/features/disallow-doctype-decl", true);
    setFeatureIfSupported(dbf, "http://xml.org/sax/features/external-general-entities", false);
    setFeatureIfSupported(dbf, "http://xml.org/sax/features/external-parameter-entities", false);
    setFeatureIfSupported(dbf, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    DocumentBuilder builder = dbf.newDocumentBuilder();
    return builder.parse(in);
  }

  private static void setFeatureIfSupported(DocumentBuilderFactory dbf, String feature, boolean value) {
    try {
      dbf.setFeature(feature, value);
    } catch (Exception ignored) {
      // Feature not recognized by this parser implementation — the other
      // hardening settings (setExpandEntityReferences, setXIncludeAware) still apply.
    }
  }

  private XmlSecurity() {}
}
