package com.trustsign.hsm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

/**
 * Direct PKCS#11 signing — bypasses Java's KeyStore CKA_ID limitation.
 *
 * Java's SunPKCS11 KeyStore only exposes private keys that have a certificate with
 * matching CKA_ID. Many HSMs store them as unlinked objects. Other signing utilities
 * (C#, C++) find keys via C_FindObjects and sign via C_Sign, bypassing KeyStore.
 *
 * This class does the same: uses the PKCS#11 C API (via reflection on SunPKCS11's
 * internal wrapper) to find the private key by RSA modulus match and sign directly.
 */
public final class Pkcs11CertificateLinker {

  private static final Logger LOG = LoggerFactory.getLogger(Pkcs11CertificateLinker.class);

  // PKCS#11 constants
  private static final long CKO_PRIVATE_KEY = 3L;
  private static final long CKA_CLASS = 0x00000000L;
  private static final long CKA_KEY_TYPE = 0x00000100L;
  private static final long CKA_MODULUS = 0x00000120L;
  private static final long CKA_TOKEN = 0x00000001L;
  private static final long CKK_RSA = 0x00000000L;
  private static final long CKM_SHA256_RSA_PKCS = 0x00000040L; // correct PKCS#11 v2.40 value
  private static final long CKM_RSA_PKCS = 0x00000001L;

  /**
   * Result of finding a private key and signing directly via PKCS#11.
   */
  public record DirectSignResult(byte[] signature, long keyHandle) {}

  /**
   * Finds an RSA private key on the token whose modulus matches the uploaded certificate's
   * public key, and signs the given data directly using C_Sign.
   *
   * @return signature bytes, or null if no matching key found or signing failed
   */
  public static byte[] tryDirectSign(Provider provider, byte[] dataToSign,
      List<X509Certificate> uploadedCerts) {
    try {
      return doDirectSign(provider, dataToSign, uploadedCerts);
    } catch (Exception e) {
      LOG.warn("Direct PKCS#11 sign failed: [{}] {}",
          e.getClass().getSimpleName(), e.getMessage() != null ? e.getMessage() : "(no message)", e);
      return null;
    }
  }

  /**
   * Finds the RSA private key handle on the token that matches the uploaded certificate.
   * Returns the key handle, or -1 if not found.
   */
  public static long findMatchingKeyHandle(Provider provider,
      List<X509Certificate> uploadedCerts) {
    try {
      LOG.info("findMatchingKeyHandle: accessing PKCS#11 internals via reflection...");
      Object[] p11AndSession = getPkcs11Session(provider);
      Object p11 = p11AndSession[0];
      long sessionId = (long) p11AndSession[1];
      LOG.info("findMatchingKeyHandle: PKCS#11 session obtained (sessionId={})", sessionId);

      for (X509Certificate cert : uploadedCerts) {
        if (!(cert.getPublicKey() instanceof RSAPublicKey rsaPub)) {
          LOG.info("findMatchingKeyHandle: skipping non-RSA cert");
          continue;
        }
        LOG.info("findMatchingKeyHandle: searching for RSA key matching modulus ({} bits)...",
            rsaPub.getModulus().bitLength());
        long handle = findPrivateKeyByModulus(p11, sessionId, rsaPub.getModulus());
        if (handle >= 0) {
          LOG.info("findMatchingKeyHandle: MATCH found, keyHandle={}", handle);
          return handle;
        }
        LOG.warn("findMatchingKeyHandle: no RSA key matched the certificate modulus");
      }
    } catch (Exception e) {
      LOG.warn("findMatchingKeyHandle FAILED: [{}] {}",
          e.getClass().getSimpleName(), e.getMessage() != null ? e.getMessage() : "(no message)", e);
    }
    return -1;
  }

  private static byte[] doDirectSign(Provider provider, byte[] dataToSign,
      List<X509Certificate> uploadedCerts) throws Exception {

    Object[] p11AndSession = getPkcs11Session(provider);
    Object p11 = p11AndSession[0];
    long sessionId = (long) p11AndSession[1];

    for (X509Certificate cert : uploadedCerts) {
      if (!(cert.getPublicKey() instanceof RSAPublicKey rsaPub)) {
        LOG.debug("Skipping non-RSA certificate: {}", cert.getSubjectX500Principal().getName());
        continue;
      }

      long keyHandle = findPrivateKeyByModulus(p11, sessionId, rsaPub.getModulus());
      if (keyHandle < 0) {
        LOG.warn("No RSA private key on token with matching modulus for cert: {}",
            cert.getSubjectX500Principal().getName());
        continue;
      }

      LOG.info("Direct PKCS#11 sign: found matching private key handle={}", keyHandle);

      // Sign using CKM_SHA256_RSA_PKCS (HSM hashes + signs in one step)
      byte[] signature = signWithMechanism(p11, sessionId, keyHandle, CKM_SHA256_RSA_PKCS, dataToSign);
      if (signature != null) {
        LOG.info("Direct PKCS#11 sign: SUCCESS, signatureLen={}", signature.length);
        return signature;
      }

      // Fallback: try CKM_RSA_PKCS (raw PKCS#1 — caller must provide DigestInfo)
      LOG.debug("CKM_SHA256_RSA_PKCS failed, trying CKM_RSA_PKCS with manual DigestInfo");
      byte[] digestInfo = buildSha256DigestInfo(dataToSign);
      signature = signWithMechanism(p11, sessionId, keyHandle, CKM_RSA_PKCS, digestInfo);
      if (signature != null) {
        LOG.info("Direct PKCS#11 sign (CKM_RSA_PKCS): SUCCESS, signatureLen={}", signature.length);
        return signature;
      }
    }
    return null;
  }

  // =========================================================================
  // PKCS#11 operations via reflection
  // =========================================================================

  private static Object[] getPkcs11Session(Provider provider) throws Exception {
    Object token = getFieldFromHierarchy(provider, "token");
    if (token == null) throw new IllegalStateException("SunPKCS11 provider has no 'token' field");

    Object p11 = getFieldFromHierarchy(token, "p11");
    if (p11 == null) throw new IllegalStateException("Token has no 'p11' field");

    Object session = invokeMethod(token, "getObjSession");
    if (session == null) session = invokeMethod(token, "getOpSession");
    if (session == null) throw new IllegalStateException("Cannot obtain PKCS#11 session");

    Method idMethod = session.getClass().getDeclaredMethod("id");
    idMethod.setAccessible(true);
    long sessionId = (long) idMethod.invoke(session);

    return new Object[]{p11, sessionId};
  }

  private static long findPrivateKeyByModulus(Object p11, long session, BigInteger targetModulus)
      throws Exception {
    // Search by CKA_CLASS + CKA_KEY_TYPE only (same as C#/C++ utilities).
    // Do NOT include CKA_TOKEN — Utimaco rejects it as CKR_ATTRIBUTE_VALUE_INVALID
    // because it's a CK_BBOOL, not a CK_ULONG.
    long[] handles = findObjects(p11, session,
        new long[]{CKA_CLASS, CKO_PRIVATE_KEY, CKA_KEY_TYPE, CKK_RSA});

    LOG.info("PKCS#11 C_FindObjects: found {} RSA private key(s)", handles.length);

    for (long handle : handles) {
      byte[] modulusBytes = getAttribute(p11, session, handle, CKA_MODULUS);
      if (modulusBytes == null || modulusBytes.length == 0) continue;

      BigInteger keyModulus = new BigInteger(1, modulusBytes);
      if (targetModulus.equals(keyModulus)) {
        return handle;
      }
    }
    return -1;
  }

  private static byte[] signWithMechanism(Object p11, long session, long keyHandle,
      long mechanismType, byte[] data) {
    try {
      Class<?> ckMechClass = Class.forName("sun.security.pkcs11.wrapper.CK_MECHANISM");
      var mechCtor = ckMechClass.getConstructor(long.class);
      Object mechanism = mechCtor.newInstance(mechanismType);

      Method signInit = p11.getClass().getMethod("C_SignInit", long.class, ckMechClass, long.class);
      signInit.invoke(p11, session, mechanism, keyHandle);

      Method sign = p11.getClass().getMethod("C_Sign", long.class, byte[].class);
      return (byte[]) sign.invoke(p11, session, data);
    } catch (Exception e) {
      LOG.debug("C_Sign with mechanism 0x{} failed: {}", Long.toHexString(mechanismType), e.getMessage());
      return null;
    }
  }

  /**
   * Builds a DigestInfo ASN.1 structure for SHA-256, as required by CKM_RSA_PKCS.
   * DigestInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, digest OCTET STRING }
   */
  private static byte[] buildSha256DigestInfo(byte[] data) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(data);
    // SHA-256 DigestInfo prefix (DER encoded AlgorithmIdentifier)
    byte[] prefix = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    byte[] digestInfo = new byte[prefix.length + hash.length];
    System.arraycopy(prefix, 0, digestInfo, 0, prefix.length);
    System.arraycopy(hash, 0, digestInfo, prefix.length, hash.length);
    return digestInfo;
  }

  // =========================================================================
  // Reflection helpers
  // =========================================================================

  private static Object getFieldFromHierarchy(Object obj, String name) throws Exception {
    Class<?> clazz = obj.getClass();
    while (clazz != null) {
      try {
        Field f = clazz.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(obj);
      } catch (NoSuchFieldException e) {
        clazz = clazz.getSuperclass();
      }
    }
    throw new NoSuchFieldException(name + " not found in " + obj.getClass().getName());
  }

  private static Object invokeMethod(Object obj, String name) {
    try {
      Method m = obj.getClass().getDeclaredMethod(name);
      m.setAccessible(true);
      return m.invoke(obj);
    } catch (Exception e) {
      return null;
    }
  }

  private static long[] findObjects(Object p11, long session, long[] attrPairs) throws Exception {
    Class<?> ckAttrClass = Class.forName("sun.security.pkcs11.wrapper.CK_ATTRIBUTE");
    var ctorLong = ckAttrClass.getConstructor(long.class, long.class);

    int count = attrPairs.length / 2;
    Object attrArray = java.lang.reflect.Array.newInstance(ckAttrClass, count);
    for (int i = 0; i < count; i++) {
      Object attr = ctorLong.newInstance(attrPairs[i * 2], attrPairs[i * 2 + 1]);
      java.lang.reflect.Array.set(attrArray, i, attr);
    }

    Method findInit = p11.getClass().getMethod("C_FindObjectsInit", long.class, ckAttrClass.arrayType());
    findInit.invoke(p11, session, attrArray);

    Method findObjs = p11.getClass().getMethod("C_FindObjects", long.class, long.class);
    long[] handles = (long[]) findObjs.invoke(p11, session, 64L);

    Method findFinal = p11.getClass().getMethod("C_FindObjectsFinal", long.class);
    findFinal.invoke(p11, session);

    return handles;
  }

  private static byte[] getAttribute(Object p11, long session, long objHandle, long attrType) {
    try {
      Class<?> ckAttrClass = Class.forName("sun.security.pkcs11.wrapper.CK_ATTRIBUTE");
      var ctor = ckAttrClass.getConstructor(long.class);
      Object attr = ctor.newInstance(attrType);

      Object attrArray = java.lang.reflect.Array.newInstance(ckAttrClass, 1);
      java.lang.reflect.Array.set(attrArray, 0, attr);

      Method getAttr = p11.getClass().getMethod("C_GetAttributeValue", long.class, long.class, ckAttrClass.arrayType());
      getAttr.invoke(p11, session, objHandle, attrArray);

      Object result = java.lang.reflect.Array.get(attrArray, 0);
      Method getBytes = ckAttrClass.getMethod("getByteArray");
      return (byte[]) getBytes.invoke(result);
    } catch (Exception e) {
      return null;
    }
  }

  private Pkcs11CertificateLinker() {}
}
