package com.itextpdf.signatures;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfStream;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.layout.LayoutArea;
import com.itextpdf.layout.layout.LayoutContext;
import com.itextpdf.layout.layout.LayoutResult;
import com.itextpdf.layout.renderer.IRenderer;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Objects;
/**
 * Like iText {@link PdfSignatureAppearance} but for {@link PdfSignatureAppearance.RenderingMode#DESCRIPTION},
 * description text uses the full widget height (minus margins). Stock iText reserves the top 30% of the
 * rectangle ({@code TOP_SECTION}), which leaves empty space when a background image is drawn behind the text.
 * <p>
 * Derived from iText 7.2.5 {@code PdfSignatureAppearance#getAppearance()} (GNU Affero GPL v3).
 */
public final class FullBleedDescriptionSignatureAppearance extends PdfSignatureAppearance {

  private static final float MARGIN = 2f;

  private final PdfDocument documentRef;

  public FullBleedDescriptionSignatureAppearance(PdfDocument document, Rectangle pageRect, int pageNumber) {
    super(document, pageRect, pageNumber);
    this.documentRef = document;
  }

  /**
   * Copies public appearance settings from {@code template} into a new full-bleed instance.
   */
  public static FullBleedDescriptionSignatureAppearance copyFrom(
      PdfDocument document, PdfSignatureAppearance template) {
    FullBleedDescriptionSignatureAppearance a =
        new FullBleedDescriptionSignatureAppearance(document, template.getPageRect(), template.getPageNumber());
    a.setPageRect(template.getPageRect());
    a.setPageNumber(template.getPageNumber());
    if (template.getReason() != null) {
      a.setReason(template.getReason());
    }
    if (template.getLocation() != null) {
      a.setLocation(template.getLocation());
    }
    if (template.getSignatureCreator() != null) {
      a.setSignatureCreator(template.getSignatureCreator());
    }
    if (template.getContact() != null) {
      a.setContact(template.getContact());
    }
    if (template.getCertificate() != null) {
      a.setCertificate(template.getCertificate());
    }
    if (template.getSignatureGraphic() != null) {
      a.setSignatureGraphic(template.getSignatureGraphic());
    }
    if (template.getImage() != null) {
      a.setImage(template.getImage());
    }
    a.setImageScale(template.getImageScale());
    if (template.getLayer2Text() != null) {
      a.setLayer2Text(template.getLayer2Text());
    }
    if (template.getLayer2Font() != null) {
      a.setLayer2Font(template.getLayer2Font());
    }
    a.setLayer2FontSize(template.getLayer2FontSize());
    if (template.getLayer2FontColor() != null) {
      a.setLayer2FontColor(template.getLayer2FontColor());
    }
    a.setRenderingMode(template.getRenderingMode());
    a.setReuseAppearance(readReuseAppearance(template));
    return a;
  }

  @Override
  protected PdfFormXObject getAppearance() throws IOException {
    if (isInvisible()) {
      return super.getAppearance();
    }

    PdfCanvas canvas;
    boolean reuseAppearance = readReuseAppearance(this);
    PdfFormXObject n0 = readN0(this);
    if (n0 == null && !reuseAppearance) {
      createBlankN0();
    }

    Rectangle bounds = new Rectangle(getPageRect().getWidth(), getPageRect().getHeight());
    PdfFormXObject n2 = readN2(this);
    if (n2 == null) {
      n2 = new PdfFormXObject(bounds);
      n2.makeIndirect(documentRef);
      writeN2(this, n2);

      canvas = new PdfCanvas(n2, documentRef);
      int rotation = documentRef.getPage(getPageNumber()).getRotation();

      if (rotation == 90) {
        canvas.concatMatrix(0, 1, -1, 0, bounds.getWidth(), 0);
      } else if (rotation == 180) {
        canvas.concatMatrix(-1, 0, 0, -1, bounds.getWidth(), bounds.getHeight());
      } else if (rotation == 270) {
        canvas.concatMatrix(0, -1, 1, 0, 0, bounds.getHeight());
      }

      Rectangle rotatedRect = rotateRectangle(bounds, documentRef.getPage(getPageNumber()).getRotation());

      String text = getLayer2Text();
      if (text == null) {
        text = generateLayer2Fallback();
      }

      ImageData image = getImage();
      if (image != null) {
        float imageScale = getImageScale();
        if (imageScale == 0) {
          canvas = new PdfCanvas(n2, documentRef);
          canvas.addImageWithTransformationMatrix(image, rotatedRect.getWidth(), 0, 0,
              rotatedRect.getHeight(), 0, 0);
        } else {
          float usableScale = imageScale;
          if (imageScale < 0) {
            usableScale = Math.min(rotatedRect.getWidth() / image.getWidth(),
                rotatedRect.getHeight() / image.getHeight());
          }
          float w = image.getWidth() * usableScale;
          float h = image.getHeight() * usableScale;
          float x = (rotatedRect.getWidth() - w) / 2;
          float y = (rotatedRect.getHeight() - h) / 2;
          canvas = new PdfCanvas(n2, documentRef);
          canvas.addImageWithTransformationMatrix(image, w, 0, 0, h, x, y);
        }
      }

      PdfFont font = getLayer2Font() == null ? PdfFontFactory.createFont() : getLayer2Font();

      Rectangle dataRect;
      Rectangle signatureRect = null;

      PdfSignatureAppearance.RenderingMode renderingMode = getRenderingMode();
      ImageData signatureGraphic = getSignatureGraphic();

      if (renderingMode == PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION
          || (renderingMode == PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION
              && signatureGraphic != null)) {
        if (rotatedRect.getHeight() > rotatedRect.getWidth()) {
          signatureRect = new Rectangle(
              MARGIN,
              rotatedRect.getHeight() / 2,
              rotatedRect.getWidth() - 2 * MARGIN,
              rotatedRect.getHeight() / 2);
          dataRect = new Rectangle(
              MARGIN,
              MARGIN,
              rotatedRect.getWidth() - 2 * MARGIN,
              rotatedRect.getHeight() / 2 - 2 * MARGIN);
        } else {
          signatureRect = new Rectangle(
              MARGIN,
              MARGIN,
              rotatedRect.getWidth() / 2 - 2 * MARGIN,
              rotatedRect.getHeight() - 2 * MARGIN);
          dataRect = new Rectangle(
              rotatedRect.getWidth() / 2 + MARGIN / 2,
              MARGIN,
              rotatedRect.getWidth() / 2 - MARGIN,
              rotatedRect.getHeight() - 2 * MARGIN);
        }
      } else if (renderingMode == PdfSignatureAppearance.RenderingMode.GRAPHIC) {
        if (signatureGraphic == null) {
          throw new IllegalStateException(
              "A signature image must be present when rendering mode is graphic. Use setSignatureGraphic()");
        }
        signatureRect = new Rectangle(
            MARGIN,
            MARGIN,
            rotatedRect.getWidth() - 2 * MARGIN,
            rotatedRect.getHeight() - 2 * MARGIN);
        dataRect = null;
      } else {
        // DESCRIPTION (and any mode that only uses text): use full height — unlike stock iText TOP_SECTION.
        dataRect = new Rectangle(
            MARGIN,
            MARGIN,
            rotatedRect.getWidth() - 2 * MARGIN,
            rotatedRect.getHeight() - 2 * MARGIN);
      }

      switch (renderingMode) {
        case NAME_AND_DESCRIPTION: {
          Certificate cert = getCertificate();
          if (!(cert instanceof X509Certificate x509)) {
            throw new IllegalStateException("Signing certificate must be X509 for NAME_AND_DESCRIPTION");
          }
          String signedBy = CertificateInfo.getSubjectFields(x509).getField("CN");
          if (signedBy == null) {
            signedBy = CertificateInfo.getSubjectFields(x509).getField("E");
          }
          if (signedBy == null) {
            signedBy = "";
          }
          addTextToCanvas(n2, signedBy, font, signatureRect);
          break;
        }
        case GRAPHIC_AND_DESCRIPTION: {
          if (signatureGraphic == null) {
            throw new IllegalStateException(
                "A signature image must be present when rendering mode is graphic and description. "
                    + "Use setSignatureGraphic()");
          }
          Rectangle sr = Objects.requireNonNull(signatureRect, "signatureRect");
          float imgWidth = signatureGraphic.getWidth();
          if (imgWidth == 0) {
            imgWidth = sr.getWidth();
          }
          float imgHeight = signatureGraphic.getHeight();
          if (imgHeight == 0) {
            imgHeight = sr.getHeight();
          }
          float multiplierH = sr.getWidth() / signatureGraphic.getWidth();
          float multiplierW = sr.getHeight() / signatureGraphic.getHeight();
          float multiplier = Math.min(multiplierH, multiplierW);
          imgWidth *= multiplier;
          imgHeight *= multiplier;
          float x = sr.getRight() - imgWidth;
          float y = sr.getBottom() + (sr.getHeight() - imgHeight) / 2;
          canvas = new PdfCanvas(n2, documentRef);
          canvas.addImageWithTransformationMatrix(signatureGraphic, imgWidth, 0, 0, imgHeight, x, y);
          break;
        }
        case GRAPHIC: {
          if (signatureGraphic == null) {
            throw new IllegalStateException("Use setSignatureGraphic()");
          }
          Rectangle sr = Objects.requireNonNull(signatureRect, "signatureRect");
          float imgWidth = signatureGraphic.getWidth();
          if (imgWidth == 0) {
            imgWidth = sr.getWidth();
          }
          float imgHeight = signatureGraphic.getHeight();
          if (imgHeight == 0) {
            imgHeight = sr.getHeight();
          }
          float multiplierH = sr.getWidth() / signatureGraphic.getWidth();
          float multiplierW = sr.getHeight() / signatureGraphic.getHeight();
          float multiplier = Math.min(multiplierH, multiplierW);
          imgWidth *= multiplier;
          imgHeight *= multiplier;
          float x = sr.getLeft() + (sr.getWidth() - imgWidth) / 2;
          float y = sr.getBottom() + (sr.getHeight() - imgHeight) / 2;
          canvas = new PdfCanvas(n2, documentRef);
          canvas.addImageWithTransformationMatrix(signatureGraphic, imgWidth, 0, 0, imgHeight, x, y);
          break;
        }
        default:
          break;
      }

      if (renderingMode != PdfSignatureAppearance.RenderingMode.GRAPHIC) {
        addTextToCanvas(n2, text, font, dataRect);
      }
    }

    Rectangle rotated = new Rectangle(bounds);
    PdfFormXObject topLayer = readTopLayer(this);
    if (topLayer == null) {
      topLayer = new PdfFormXObject(rotated);
      topLayer.makeIndirect(documentRef);
      writeTopLayer(this, topLayer);

      if (reuseAppearance) {
        PdfAcroForm acroForm = PdfAcroForm.getAcroForm(documentRef, true);
        PdfFormField field = acroForm.getField(readFieldName(this));
        PdfStream stream = field.getWidgets().get(0).getAppearanceDictionary().getAsStream(PdfName.N);
        PdfFormXObject xobj = new PdfFormXObject(stream);

        if (stream != null) {
          topLayer.getResources().addForm(xobj, new PdfName("n0"));
          PdfCanvas canvas1 = new PdfCanvas(topLayer, documentRef);
          canvas1.addXObjectWithTransformationMatrix(xobj, 1, 0, 0, 1, 0, 0);
        } else {
          writeReuseAppearance(this, false);
          reuseAppearance = false;
          if (readN0(this) == null) {
            createBlankN0();
          }
        }
      }

      if (!reuseAppearance) {
        PdfFormXObject n0ref = readN0(this);
        topLayer.getResources().addForm(n0ref, new PdfName("n0"));
        PdfCanvas canvas1 = new PdfCanvas(topLayer, documentRef);
        canvas1.addXObjectWithTransformationMatrix(n0ref, 1, 0, 0, 1, 0, 0);
      }

      PdfFormXObject n2ref = readN2(this);
      topLayer.getResources().addForm(n2ref, new PdfName("n2"));
      PdfCanvas canvas1 = new PdfCanvas(topLayer, documentRef);
      canvas1.addXObjectWithTransformationMatrix(n2ref, 1, 0, 0, 1, 0, 0);
    }

    PdfFormXObject napp = new PdfFormXObject(rotated);
    napp.makeIndirect(documentRef);
    PdfFormXObject top = readTopLayer(this);
    napp.getResources().addForm(top, new PdfName("FRM"));

    canvas = new PdfCanvas(napp, documentRef);
    canvas.addXObjectAt(top,
        top.getBBox().getAsNumber(0).floatValue(),
        top.getBBox().getAsNumber(1).floatValue());

    return napp;
  }

  private String generateLayer2Fallback() {
    Certificate cert = getCertificate();
    if (!(cert instanceof X509Certificate x509)) {
      return "";
    }
    StringBuilder buf = new StringBuilder();
    buf.append("Digitally signed by ");
    String name = null;
    CertificateInfo.X500Name x500name = CertificateInfo.getSubjectFields(x509);
    if (x500name != null) {
      name = x500name.getField("CN");
      if (name == null) {
        name = x500name.getField("E");
      }
    }
    if (name == null) {
      name = "";
    }
    buf.append(name).append('\n');
    buf.append("Date: ").append(SignUtils.dateToString(getSignDate()));
    String reason = getReason();
    if (reason != null) {
      buf.append('\n').append("Reason: ").append(reason);
    }
    String location = getLocation();
    if (location != null) {
      buf.append('\n').append("Location: ").append(location);
    }
    return buf.toString();
  }

  private void createBlankN0() {
    PdfFormXObject n0 = new PdfFormXObject(new Rectangle(100, 100));
    n0.makeIndirect(documentRef);
    PdfCanvas canvas = new PdfCanvas(n0, documentRef);
    canvas.writeLiteral("% DSBlank\n");
    writeN0(this, n0);
  }

  private void addTextToCanvas(PdfFormXObject n2, String text, PdfFont font, Rectangle dataRect) {
    PdfCanvas canvas = new PdfCanvas(n2, documentRef);
    Paragraph paragraph = new Paragraph(text).setFont(font).setMargin(0).setMultipliedLeading(0.9f);
    try (Canvas layoutCanvas = new Canvas(canvas, dataRect)) {
      paragraph.setFontColor(getLayer2FontColor());
      float layer2FontSize = getLayer2FontSize();
      if (layer2FontSize == 0) {
        applyCopyFittingFontSize(paragraph, dataRect, layoutCanvas.getRenderer());
      } else {
        paragraph.setFontSize(layer2FontSize);
      }
      layoutCanvas.add(paragraph);
    }
  }

  private void applyCopyFittingFontSize(Paragraph paragraph, Rectangle rect, IRenderer parentRenderer) {
    IRenderer renderer = paragraph.createRendererSubTree().setParent(parentRenderer);
    LayoutContext layoutContext = new LayoutContext(new LayoutArea(1, rect));
    float lFontSize = 0.1f;
    float rFontSize = 100;
    for (int i = 0; i < 15; i++) {
      float mFontSize = (lFontSize + rFontSize) / 2;
      paragraph.setFontSize(mFontSize);
      LayoutResult result = renderer.layout(layoutContext);
      if (result.getStatus() == LayoutResult.FULL) {
        lFontSize = mFontSize;
      } else {
        rFontSize = mFontSize;
      }
    }
    paragraph.setFontSize(lFontSize);
  }

  private static Rectangle rotateRectangle(Rectangle rect, int angle) {
    if (0 == (angle / 90) % 2) {
      return new Rectangle(rect.getWidth(), rect.getHeight());
    }
    return new Rectangle(rect.getHeight(), rect.getWidth());
  }

  private static PdfFormXObject readN0(PdfSignatureAppearance target) {
    return readField(target, "n0", PdfFormXObject.class);
  }

  private static PdfFormXObject readN2(PdfSignatureAppearance target) {
    return readField(target, "n2", PdfFormXObject.class);
  }

  private static PdfFormXObject readTopLayer(PdfSignatureAppearance target) {
    return readField(target, "topLayer", PdfFormXObject.class);
  }

  private static boolean readReuseAppearance(PdfSignatureAppearance target) {
    try {
      Field f = PdfSignatureAppearance.class.getDeclaredField("reuseAppearance");
      f.setAccessible(true);
      return f.getBoolean(target);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String readFieldName(PdfSignatureAppearance target) {
    return readField(target, "fieldName", String.class);
  }

  private static void writeN0(PdfSignatureAppearance target, PdfFormXObject value) {
    writeField(target, "n0", value);
  }

  private static void writeN2(PdfSignatureAppearance target, PdfFormXObject value) {
    writeField(target, "n2", value);
  }

  private static void writeTopLayer(PdfSignatureAppearance target, PdfFormXObject value) {
    writeField(target, "topLayer", value);
  }

  private static void writeReuseAppearance(PdfSignatureAppearance target, boolean value) {
    writeField(target, "reuseAppearance", value);
  }

  private static <T> T readField(PdfSignatureAppearance target, String name, Class<T> type) {
    try {
      Field f = PdfSignatureAppearance.class.getDeclaredField(name);
      f.setAccessible(true);
      Object v = f.get(target);
      if (v == null) {
        return null;
      }
      return type.cast(v);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void writeField(PdfSignatureAppearance target, String name, Object value) {
    try {
      Field f = PdfSignatureAppearance.class.getDeclaredField(name);
      f.setAccessible(true);
      f.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }
}
