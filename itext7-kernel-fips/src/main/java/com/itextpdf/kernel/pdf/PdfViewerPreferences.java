/*

    This file is part of the iText (R) project.
    Copyright (c) 1998-2021 iText Group NV
    Authors: Bruno Lowagie, Paulo Soares, et al.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation with the addition of the
    following permission added to Section 15 as permitted in Section 7(a):
    FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
    ITEXT GROUP. ITEXT GROUP DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
    OF THIRD PARTY RIGHTS

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses or write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA, 02110-1301 USA, or download the license from the following URL:
    http://itextpdf.com/terms-of-use/

    The interactive user interfaces in modified source and object code versions
    of this program must display Appropriate Legal Notices, as required under
    Section 5 of the GNU Affero General Public License.

    In accordance with Section 7(b) of the GNU Affero General Public License,
    a covered work must retain the producer line in every PDF that is created
    or manipulated using iText.

    You can be released from the requirements of the license by purchasing
    a commercial license. Buying such a license is mandatory as soon as you
    develop commercial activities involving the iText software without
    disclosing the source code of your own applications.
    These activities include: offering paid services to customers as an ASP,
    serving PDFs on the fly in a web application, shipping iText with a closed
    source product.

    For more information, please contact iText Software Corp. at this
    address: sales@itextpdf.com
 */
package com.itextpdf.kernel.pdf;

import com.itextpdf.kernel.PdfException;

public class PdfViewerPreferences extends PdfObjectWrapper<PdfDictionary> {

    private static final long serialVersionUID = -6885879361985241602L;

	public enum PdfViewerPreferencesConstants {
        /**
         * PageMode constant for {@link PdfName#NonFullScreenPageMode}.
         */
        USE_NONE,
        /**
         * PageMode constant for {@link PdfName#NonFullScreenPageMode}.
         */
        USE_OUTLINES,
        /**
         * PageMode constant for {@link PdfName#NonFullScreenPageMode}.
         */
        USE_THUMBS,
        /**
         * PageMode constant for {@link PdfName#NonFullScreenPageMode}.
         */
        USE_OC,
        /**
         * Direction constant for {@link PdfName#Direction}.
         */
        LEFT_TO_RIGHT,
        /**
         * Direction constant for {@link PdfName#Direction}.
         */
        RIGHT_TO_LEFT,
        /**
         * PageBoundary constant for {@link #VIEW_AREA}, {@link #VIEW_CLIP}, {@link #PRINT_AREA}, {@link #PRINT_CLIP}.
         */
        MEDIA_BOX,
        /**
         * PageBoundary constant for {@link #VIEW_AREA}, {@link #VIEW_CLIP}, {@link #PRINT_AREA}, {@link #PRINT_CLIP}.
         */
        CROP_BOX,
        /**
         * PageBoundary constant for {@link #VIEW_AREA}, {@link #VIEW_CLIP}, {@link #PRINT_AREA}, {@link #PRINT_CLIP}.
         */
        BLEED_BOX,
        /**
         * PageBoundary constant for {@link #VIEW_AREA}, {@link #VIEW_CLIP}, {@link #PRINT_AREA}, {@link #PRINT_CLIP}.
         */
        TRIM_BOX,
        /**
         * PageBoundary constant for {@link #VIEW_AREA}, {@link #VIEW_CLIP}, {@link #PRINT_AREA}, {@link #PRINT_CLIP}.
         */
        ART_BOX,
        /**
         * ViewArea constant.
         */
        VIEW_AREA,
        /**
         * ViewClip constant.
         */
        VIEW_CLIP,
        /**
         * PrintArea constant.
         */
        PRINT_AREA,
        /**
         * PrintClip constant.
         */
        PRINT_CLIP,
        /**
         * Page scaling option constant for {@link PdfName#PrintScaling}.
         */
        NONE,
        /**
         * Page scaling option constant for {@link PdfName#PrintScaling}.
         */
        APP_DEFAULT,
        /**
         * The paper handling option constant for {@link PdfName#Duplex}.
         */
        SIMPLEX,
        /**
         * The paper handling option constant for {@link PdfName#Duplex}.
         */
        DUPLEX_FLIP_SHORT_EDGE,
        /**
         * The paper handling option constant for {@link PdfName#Duplex}.
         */
        DUPLEX_FLIP_LONG_EDGE
    }

    public PdfViewerPreferences() {
        this(new PdfDictionary());
    }

    public PdfViewerPreferences(PdfDictionary pdfObject) {
        super(pdfObject);
    }

    /**
     * This method sets HideToolBar flag to true or false
     *
     * @param hideToolbar HideToolBar flag's boolean value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setHideToolbar(boolean hideToolbar) {
        return put(PdfName.HideToolbar, PdfBoolean.valueOf(hideToolbar));
    }

    /**
     * This method sets HideMenuBar flag to true or false
     *
     * @param hideMenubar HideMenuBar flag's boolean value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setHideMenubar(boolean hideMenubar) {
        return put(PdfName.HideMenubar, PdfBoolean.valueOf(hideMenubar));
    }

    /**
     * This method sets HideWindowUI flag to true or false
     *
     * @param hideWindowUI HideWindowUI flag's boolean value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setHideWindowUI(boolean hideWindowUI) {
        return put(PdfName.HideWindowUI, PdfBoolean.valueOf(hideWindowUI));
    }

    /**
     * This method sets FitWindow flag to true or false
     *
     * @param fitWindow FitWindow flag's boolean value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setFitWindow(boolean fitWindow) {
        return put(PdfName.FitWindow, PdfBoolean.valueOf(fitWindow));
    }

    /**
     * This method sets CenterWindow flag to true or false
     *
     * @param centerWindow CenterWindow flag's boolean value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setCenterWindow(boolean centerWindow) {
        return put(PdfName.CenterWindow, PdfBoolean.valueOf(centerWindow));
    }

    /**
     * This method sets DisplayDocTitle flag to true or false
     *
     * @param displayDocTitle DisplayDocTitle flag's boolean value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setDisplayDocTitle(boolean displayDocTitle) {
        return put(PdfName.DisplayDocTitle, PdfBoolean.valueOf(displayDocTitle));
    }

    /**
     * This method sets NonFullScreenPageMode property. Allowed values are UseNone, UseOutlines, useThumbs, UseOC.
     * This entry is meaningful only if the value of the PageMode entry in the Catalog dictionary is FullScreen
     *
     * @param nonFullScreenPageMode NonFullScreenPageMode property type value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setNonFullScreenPageMode(PdfViewerPreferencesConstants nonFullScreenPageMode) {
        switch (nonFullScreenPageMode) {
            case USE_NONE:
                put(PdfName.NonFullScreenPageMode, PdfName.UseNone);
                break;
            case USE_OUTLINES:
                put(PdfName.NonFullScreenPageMode, PdfName.UseOutlines);
                break;
            case USE_THUMBS:
                put(PdfName.NonFullScreenPageMode, PdfName.UseThumbs);
                break;
            case USE_OC:
                put(PdfName.NonFullScreenPageMode, PdfName.UseOC);
                break;
            default:
        }
        return this;
    }

    /**
     * This method sets predominant reading order of text.
     *
     * @param direction reading order type value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setDirection(PdfViewerPreferencesConstants direction) {
        switch (direction) {
            case LEFT_TO_RIGHT:
                put(PdfName.Direction, PdfName.L2R);
                break;
            case RIGHT_TO_LEFT:
                put(PdfName.Direction, PdfName.R2L);
                break;
            default:
        }
        return this;
    }

    /**
     * This method sets the name of the page boundary representing the area of a page that shall be displayed when
     * viewing the document on the screen.
     * Deprecated in PDF 2.0.
     *
     * @param pageBoundary page boundary type value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setViewArea(PdfViewerPreferencesConstants pageBoundary) {
        return setPageBoundary(PdfViewerPreferencesConstants.VIEW_AREA, pageBoundary);
    }

    /**
     * This method sets the name of the page boundary to which the contents of a page shall be clipped when
     * viewing the document on the screen.
     * Deprecated in PDF 2.0.
     *
     * @param pageBoundary page boundary type value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setViewClip(PdfViewerPreferencesConstants pageBoundary) {
        return setPageBoundary(PdfViewerPreferencesConstants.VIEW_CLIP, pageBoundary);
    }

    /**
     * This method sets the name of the page boundary representing the area of a page that shall be
     * rendered when printing the document.
     * Deprecated in PDF 2.0.
     *
     * @param pageBoundary page boundary type value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setPrintArea(PdfViewerPreferencesConstants pageBoundary) {
        return setPageBoundary(PdfViewerPreferencesConstants.PRINT_AREA, pageBoundary);
    }

    /**
     * This method sets the name of the page boundary to which the contents of a page shall be clipped when
     * printing the document.
     * Deprecated in PDF 2.0.
     *
     * @param pageBoundary page boundary type value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setPrintClip(PdfViewerPreferencesConstants pageBoundary) {
        return setPageBoundary(PdfViewerPreferencesConstants.PRINT_CLIP, pageBoundary);
    }

    /**
     * This method sets the page scaling option that shall be selected when a print dialog is displayed for this
     * document. Valid values are None and AppDefault.
     *
     * @param printScaling page scaling option's type value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setPrintScaling(PdfViewerPreferencesConstants printScaling) {
        switch (printScaling) {
            case NONE:
                put(PdfName.PrintScaling, PdfName.None);
                break;
            case APP_DEFAULT:
                put(PdfName.PrintScaling, PdfName.AppDefault);
                break;
            default:
        }

        return this;
    }

    /**
     * This method sets the paper handling option that shall be used when printing the file from the print dialog.
     * The following values are valid: Simplex, DuplexFlipShortEdge, DuplexFlipLongEdge.
     *
     * @param duplex paper handling option's type value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setDuplex(PdfViewerPreferencesConstants duplex) {
        switch (duplex) {
            case SIMPLEX:
                put(PdfName.Duplex, PdfName.Simplex);
                break;
            case DUPLEX_FLIP_SHORT_EDGE:
                put(PdfName.Duplex, PdfName.DuplexFlipShortEdge);
                break;
            case DUPLEX_FLIP_LONG_EDGE:
                put(PdfName.Duplex, PdfName.DuplexFlipLongEdge);
                break;
            default:
        }
        return this;
    }

    /**
     * This method sets PickTrayByPDFSize flag to true or false.
     *
     * @param pickTrayByPdfSize PickTrayByPDFSize flag's boolean value
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setPickTrayByPDFSize(boolean pickTrayByPdfSize) {
        return put(PdfName.PickTrayByPDFSize, PdfBoolean.valueOf(pickTrayByPdfSize));
    }

    /**
     * This method sets the page numbers used to initialize the print dialog box when the file is printed.
     *
     * @param printPageRange the array of page numbers
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setPrintPageRange(int[] printPageRange) {
        return put(PdfName.PrintPageRange, new PdfArray(printPageRange));
    }

    /**
     * This method sets the number of copies that shall be printed when the print dialog is opened for this file.
     *
     * @param numCopies the number of copies to print when the print dialog is opened
     * @return current instance of {@link PdfViewerPreferences}
     */
    public PdfViewerPreferences setNumCopies(int numCopies) {
        return put(PdfName.NumCopies, new PdfNumber(numCopies));
    }

    /**
     * PDF 2.0. Sets an array of names of Viewer preference settings that
     * shall be enforced by PDF processors and that shall not be overridden by
     * subsequent selections in the application user interface
     *
     * @param enforce array of names specifying settings to enforce in the PDF processors
     * @return this {@link PdfViewerPreferences} instance
     */
    public PdfViewerPreferences setEnforce(PdfArray enforce) {
        for (int i = 0; i < enforce.size(); i++) {
            PdfName curEnforce = enforce.getAsName(i);
            if (curEnforce == null) {
                throw new IllegalArgumentException("Enforce array shall contain PdfName entries");
            } else if (PdfName.PrintScaling.equals(curEnforce)) {
                // This name may appear in the Enforce array only if the corresponding entry in
                // the viewer preferences dictionary specifies a valid value other than AppDefault
                PdfName curPrintScaling = getPdfObject().getAsName(PdfName.PrintScaling);
                if (curPrintScaling == null || PdfName.AppDefault.equals(curPrintScaling)) {
                    throw new PdfException(PdfException.PrintScalingEnforceEntryInvalid);
                }
            }
        }
        return put(PdfName.Enforce, enforce);
    }

    /**
     * PDF 2.0. Gets an array of names of Viewer preference settings that
     * shall be enforced by PDF processors and that shall not be overridden by
     * subsequent selections in the application user interface
     *
     * @return array of names specifying settings to enforce in the PDF processors
     */
    public PdfArray getEnforce() {
        return getPdfObject().getAsArray(PdfName.Enforce);
    }

    public PdfViewerPreferences put(PdfName key, PdfObject value) {
        getPdfObject().put(key, value);
        setModified();
        return this;
    }

    @Override
    protected boolean isWrappedObjectMustBeIndirect() {
        return false;
    }

    private PdfViewerPreferences setPageBoundary(PdfViewerPreferencesConstants viewerPreferenceType, PdfViewerPreferencesConstants pageBoundary) {
        PdfName type = null;
        switch (viewerPreferenceType) {
            case VIEW_AREA :
                type = PdfName.ViewArea;
                break;
            case VIEW_CLIP :
                type = PdfName.ViewClip;
                break;
            case PRINT_AREA :
                type = PdfName.PrintArea;
                break;
            case PRINT_CLIP :
                type = PdfName.PrintClip;
                break;
            default:
        }
        if (type != null) {
            switch (pageBoundary) {
                case MEDIA_BOX:
                    put(type, PdfName.MediaBox);
                    break;
                case CROP_BOX:
                    put(type, PdfName.CropBox);
                    break;
                case BLEED_BOX:
                    put(type, PdfName.BleedBox);
                    break;
                case TRIM_BOX:
                    put(type, PdfName.TrimBox);
                    break;
                case ART_BOX:
                    put(type, PdfName.ArtBox);
                    break;
                default:
            }
        }

        return this;
    }
}
