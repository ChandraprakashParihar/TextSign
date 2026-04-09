package com.itextpdf.signatures;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.PdfSigFieldLock;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.forms.fields.PdfSignatureFormField;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.kernel.pdf.annot.PdfWidgetAnnotation;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * One PKCS#7 signature field with a visible widget on each selected page, sharing the same normal
 * appearance stream. The stock {@link PdfSigner} only creates one widget; {@link PdfAcroForm#addField}
 * also fails to attach every sibling under {@code /Kids} when there are multiple widgets, so this
 * class adds each widget to its page explicitly.
 */
public final class MultiWidgetPdfSigner extends PdfSigner {

  private final List<Integer> widgetPages1Based;
  private final List<Rectangle> widgetRects;

  public MultiWidgetPdfSigner(
      PdfReader reader,
      OutputStream os,
      StampingProperties props,
      List<Integer> widgetPages1Based,
      List<Rectangle> widgetRects) throws IOException {
    super(reader, os, props);
    if (widgetPages1Based.size() != widgetRects.size() || widgetPages1Based.isEmpty()) {
      throw new IllegalArgumentException("widgetPages1Based and widgetRects must be same non-empty size");
    }
    this.widgetPages1Based = widgetPages1Based;
    this.widgetRects = widgetRects;
  }

  @Override
  protected PdfSigFieldLock createNewSignatureFormField(PdfAcroForm acroForm, String name) throws IOException {
    PdfSignatureAppearance appearance = getSignatureAppearance();
    PdfDocument document = getDocument();

    PdfSignatureFormField sigField = PdfFormField.createSignature(document);
    sigField.setFieldName(name);
    sigField.put(PdfName.V, cryptoDictionary.getPdfObject());

    PdfSigFieldLock sigFieldLock = sigField.getSigFieldLockDictionary();
    if (fieldLock != null) {
      fieldLock.getPdfObject().makeIndirect(document);
      sigField.put(PdfName.Lock, fieldLock.getPdfObject());
      sigFieldLock = fieldLock;
    }

    PdfFormXObject appearanceXo = null;
    if (!appearance.isInvisible()) {
      appearanceXo = appearance.getAppearance();
      appearanceXo.makeIndirect(document);
    }

    // Create the primary widget first; let acroForm.addField(sigField, primaryPage)
    // attach it to the page to avoid duplicate attach/remove churn on page 1.
    int primaryPage = widgetPages1Based.get(0);
    Rectangle primaryRect = widgetRects.get(0);
    PdfWidgetAnnotation primaryWidget = new PdfWidgetAnnotation(primaryRect);
    primaryWidget.setFlags(PdfAnnotation.PRINT | PdfAnnotation.LOCKED);
    primaryWidget.setPage(document.getPage(primaryPage));
    if (appearance.isInvisible()) {
      primaryWidget.remove(PdfName.AP);
    } else {
      PdfDictionary apDict = new PdfDictionary();
      apDict.put(PdfName.N, appearanceXo.getPdfObject());
      primaryWidget.put(PdfName.AP, apDict);
    }
    sigField.addKid(primaryWidget);
    primaryWidget.makeIndirect(document);

    // Additional widgets are attached directly to their pages.
    for (int i = 1; i < widgetPages1Based.size(); i++) {
      int pageNum = widgetPages1Based.get(i);
      Rectangle rect = widgetRects.get(i);
      PdfWidgetAnnotation widget = new PdfWidgetAnnotation(rect);
      widget.setFlags(PdfAnnotation.PRINT | PdfAnnotation.LOCKED);
      widget.setPage(document.getPage(pageNum));
      if (appearance.isInvisible()) {
        widget.remove(PdfName.AP);
      } else {
        PdfDictionary apDict = new PdfDictionary();
        apDict.put(PdfName.N, appearanceXo.getPdfObject());
        widget.put(PdfName.AP, apDict);
      }
      sigField.addKid(widget);
      widget.makeIndirect(document);
      document.getPage(pageNum).addAnnotation(widget);
    }
    acroForm.addField(sigField, document.getPage(primaryPage));

    if (acroForm.getPdfObject().isIndirect()) {
      acroForm.setModified();
    } else {
      document.getCatalog().setModified();
    }
    return sigFieldLock;
  }
}
