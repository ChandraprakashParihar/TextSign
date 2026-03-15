package com.trustsign.core;

import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

/**
 * Verifies detached CMS (PKCS#7) signatures.
 */
public final class CmsVerifyService {

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public record Result(boolean ok, String reason, X509Certificate signerCert) {}

  /**
   * Verifies a detached CMS signature over the given content.
   * @param contentBytes the signed content (exactly what was passed to signDetached)
   * @param cmsBytes the raw CMS detached signature bytes
   */
  @SuppressWarnings("unchecked")
  public static Result verify(byte[] contentBytes, byte[] cmsBytes) {
    if (contentBytes == null || cmsBytes == null) {
      return new Result(false, "Content or CMS bytes null", null);
    }
    try {
      CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(contentBytes), cmsBytes);
      Store<?> certStore = cms.getCertificates();
      SignerInformationStore signers = cms.getSignerInfos();
      Iterator<SignerInformation> it = signers.getSigners().iterator();
      if (!it.hasNext()) {
        return new Result(false, "No signer in CMS", null);
      }
      SignerInformation signerInfo = it.next();
      Collection<X509CertificateHolder> certHolders = (Collection<X509CertificateHolder>) certStore.getMatches(signerInfo.getSID());
      if (certHolders == null || certHolders.isEmpty()) {
        return new Result(false, "No certificate found for signer", null);
      }
      X509Certificate signerCert = new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider("BC")
          .getCertificate(certHolders.iterator().next());
      boolean verified = signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCert));
      if (!verified) {
        return new Result(false, "CMS signature verification failed", signerCert);
      }
      return new Result(true, "CMS signature valid", signerCert);
    } catch (Exception e) {
      String msg = e.getMessage();
      if (msg == null || msg.isBlank()) msg = e.getClass().getSimpleName();
      return new Result(false, msg, null);
    }
  }

  private CmsVerifyService() {}
}
