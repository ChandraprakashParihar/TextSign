package com.trustsign.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.annot.PdfWidgetAnnotation;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class PdfSignerServiceTest {

  @Test
  void multiPageSigning_placesWidgetRectsOnAllRequestedPages() throws Exception {
    byte[] unsignedPdf = createThreePagePdf();
    SignMaterial material = createSigningMaterial();

    PdfSignerService.PdfSigningResult result = PdfSignerService.signPdf(
        unsignedPdf,
        material.privateKey,
        material.chain,
        material.provider,
        material.signingCert,
        "test",
        "test-location",
        List.of(0, 1, 2),
        PdfSignerService.PdfSigningOptions.DEFAULT);

    assertNotNull(result);
    assertNotNull(result.signedPdf());

    List<PDRectangle> expected = expectedRects(unsignedPdf, List.of(0, 1, 2));

    try (PdfDocument itextDoc = new PdfDocument(new PdfReader(new ByteArrayInputStream(result.signedPdf())))) {
      PdfAcroForm acroForm = PdfAcroForm.getAcroForm(itextDoc, false);
      assertNotNull(acroForm);
      PdfFormField field = acroForm.getFormFields().values().iterator().next();
      List<PdfWidgetAnnotation> widgets = field.getWidgets();
      assertEquals(3, widgets.size());
      for (int i = 0; i < widgets.size(); i++) {
        Rectangle got = widgets.get(i).getRectangle().toRectangle();
        PDRectangle exp = expected.get(i);
        assertEquals(exp.getLowerLeftX(), got.getX(), 0.01f);
        assertEquals(exp.getLowerLeftY(), got.getY(), 0.01f);
        assertEquals(exp.getWidth(), got.getWidth(), 0.01f);
        assertEquals(exp.getHeight(), got.getHeight(), 0.01f);
      }
    }
  }

  @Test
  void signatureContentsLookSigned_requiresSignedDataOid() throws Exception {
    Method m = PdfSignerService.class.getDeclaredMethod("signatureContentsLookSigned", byte[].class);
    m.setAccessible(true);

    byte[] zeroFilled = new byte[128];
    assertFalse((Boolean) m.invoke(null, (Object) zeroFilled));

    byte[] wrongOid = new byte[128];
    wrongOid[0] = 0x30;
    wrongOid[1] = 0x0b;
    wrongOid[2] = 0x06;
    wrongOid[3] = 0x09;
    wrongOid[4] = 0x2a;
    wrongOid[5] = (byte) 0x86;
    wrongOid[6] = 0x48;
    wrongOid[7] = (byte) 0x86;
    wrongOid[8] = (byte) 0xf7;
    wrongOid[9] = 0x0d;
    wrongOid[10] = 0x01;
    wrongOid[11] = 0x07;
    wrongOid[12] = 0x03; // wrong last arc (not SignedData)
    assertFalse((Boolean) m.invoke(null, (Object) wrongOid));

    byte[] signedDataPrefix = new byte[128];
    signedDataPrefix[0] = 0x30;
    signedDataPrefix[1] = 0x0b;
    signedDataPrefix[2] = 0x06;
    signedDataPrefix[3] = 0x09;
    signedDataPrefix[4] = 0x2a;
    signedDataPrefix[5] = (byte) 0x86;
    signedDataPrefix[6] = 0x48;
    signedDataPrefix[7] = (byte) 0x86;
    signedDataPrefix[8] = (byte) 0xf7;
    signedDataPrefix[9] = 0x0d;
    signedDataPrefix[10] = 0x01;
    signedDataPrefix[11] = 0x07;
    signedDataPrefix[12] = 0x02; // SignedData
    assertTrue((Boolean) m.invoke(null, (Object) signedDataPrefix));
  }

  private static List<PDRectangle> expectedRects(byte[] unsignedPdf, List<Integer> pages0Based) throws Exception {
    Method m = PdfSignerService.class.getDeclaredMethod(
        "computeSignatureWidgetRect",
        PDDocument.class,
        int.class,
        boolean.class,
        PdfSignerService.SignaturePlacement.class);
    m.setAccessible(true);
    List<PDRectangle> out = new ArrayList<>();
    try (PDDocument doc = PDDocument.load(unsignedPdf)) {
      for (int p : pages0Based) {
        out.add((PDRectangle) m.invoke(null, doc, p, false, PdfSignerService.SignaturePlacement.DEFAULT));
      }
    }
    return out;
  }

  private static byte[] createThreePagePdf() throws Exception {
    try (PDDocument doc = new PDDocument(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      doc.addPage(new PDPage(PDRectangle.A4));
      doc.addPage(new PDPage(PDRectangle.A4));
      doc.addPage(new PDPage(PDRectangle.A4));
      doc.save(out);
      return out.toByteArray();
    }
  }

  private static SignMaterial createSigningMaterial() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();
    X509Certificate cert = selfSigned(kp);
    Certificate[] chain = new Certificate[] { cert };
    Provider provider = Security.getProvider("SunRsaSign");
    return new SignMaterial(kp.getPrivate(), chain, cert, provider);
  }

  private static X509Certificate selfSigned(KeyPair kp) throws Exception {
    Instant now = Instant.now();
    Date notBefore = Date.from(now.minusSeconds(60));
    Date notAfter = Date.from(now.plusSeconds(86400));
    X500Name dn = new X500Name("CN=PdfSignerServiceTest");
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
        dn,
        serial,
        notBefore,
        notAfter,
        dn,
        kp.getPublic());
    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider("BC")
        .build(kp.getPrivate());
    return new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(builder.build(signer));
  }

  private record SignMaterial(
      PrivateKey privateKey,
      Certificate[] chain,
      X509Certificate signingCert,
      Provider provider) {
  }
}

