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
package com.itextpdf.kernel.font;

import com.itextpdf.io.font.FontNames;
import com.itextpdf.io.font.FontProgram;
import com.itextpdf.io.font.constants.FontDescriptorFlags;
import com.itextpdf.io.font.constants.FontStretches;
import com.itextpdf.io.font.constants.FontWeights;
import com.itextpdf.io.font.otf.Glyph;

import java.util.HashMap;
import java.util.Map;

/**
 * FontProgram class for Type 3 font. Contains map of {@link Type3Glyph}.
 * Type3Glyphs belong to a particular pdf document.
 * Note, an instance of Type3Font can not be reused for multiple pdf documents.
 */
public class Type3Font extends FontProgram {

    private static final long serialVersionUID = 1027076515537536993L;

    private final Map<Integer, Type3Glyph> type3Glyphs = new HashMap<>();
    /**
     * Stores glyphs without associated unicode.
     */
    private final Map<Integer, Type3Glyph> type3GlyphsWithoutUnicode = new HashMap<>();
    private boolean colorized = false;
    private int flags = 0;

    /**
     * Creates a Type 3 font program.
     *
     * @param colorized defines whether the glyph color is specified in the glyph descriptions in the font.
     */
    Type3Font(boolean colorized) {
        this.colorized = colorized;
        this.fontNames = new FontNames();
        getFontMetrics().setBbox(0, 0, 0, 0);
    }

    /**
     * Returns a glyph by unicode.
     *
     * @param unicode glyph unicode
     *
     * @return {@link Type3Glyph} glyph, or {@code null} if this font does not contain glyph for the unicode
     */
    public Type3Glyph getType3Glyph(int unicode) {
        return type3Glyphs.get(unicode);
    }

    /**
     * Returns a glyph by its code. These glyphs may not have unicode.
     *
     * @param code glyph code
     *
     * @return {@link Type3Glyph} glyph, or {@code null} if this font does not contain glyph for the code
     */
    public Type3Glyph getType3GlyphByCode(int code) {
        Type3Glyph glyph = type3GlyphsWithoutUnicode.get(code);
        if (glyph == null && codeToGlyph.get(code) != null) {
            glyph = type3Glyphs.get(codeToGlyph.get(code).getUnicode());
        }
        return glyph;
    }

    @Override
    public int getPdfFontFlags() {
        return flags;
    }

    @Override
    public boolean isFontSpecific() {
        return false;
    }

    public boolean isColorized() {
        return colorized;
    }

    @Override
    public int getKerning(Glyph glyph1, Glyph glyph2) {
        return 0;
    }


    /**
     * Returns number of glyphs for this font.
     * Its also count glyphs without unicode.
     * See {@link #type3GlyphsWithoutUnicode}.
     *
     * @return {@code int} number off all glyphs
     */
    public int getNumberOfGlyphs() {
        return type3Glyphs.size() + type3GlyphsWithoutUnicode.size();
    }

    /**
     * Sets the PostScript name of the font.
     * <p>
     * If full name is null, it will be set as well.
     *
     * @param fontName the PostScript name of the font, shall not be null or empty.
     */
    @Override
    protected void setFontName(String fontName) {
        //This dummy override allows PdfType3Font to set font name because of different modules.
        super.setFontName(fontName);
    }

    /**
     * Sets a preferred font family name.
     *
     * @param fontFamily a preferred font family name.
     */
    @Override
    protected void setFontFamily(String fontFamily) {
        //This dummy override allows PdfType3Font to set font name because of different modules.
        super.setFontFamily(fontFamily);
    }

    /**
     * Sets font weight.
     *
     * @param fontWeight integer form 100 to 900. See {@link FontWeights}.
     */
    @Override
    protected void setFontWeight(int fontWeight) {
        //This dummy override allows PdfType3Font to set font name because of different modules.
        super.setFontWeight(fontWeight);
    }

    /**
     * Sets font width in css notation (font-stretch property)
     *
     * @param fontWidth {@link FontStretches}.
     */
    @Override
    protected void setFontStretch(String fontWidth) {
        //This dummy override allows PdfType3Font to set font name because of different modules.
        super.setFontStretch(fontWidth);
    }

    /**
     * Sets the PostScript italic angel.
     * <p>
     * Italic angle in counter-clockwise degrees from the vertical. Zero for upright text, negative for text that leans to the right (forward).
     *
     * @param italicAngle in counter-clockwise degrees from the vertical
     */
    @Override   //This dummy override allows PdfType3Font to set the PostScript italicAngel because of different modules.
    protected void setItalicAngle(int italicAngle) {
        //This dummy override allows PdfType3Font to set font name because of different modules.
        super.setItalicAngle(italicAngle);
    }

    /**
     * Sets Font descriptor flags.
     * @see FontDescriptorFlags
     *
     * @param flags {@link FontDescriptorFlags}.
     */
    void setPdfFontFlags(int flags) {
        this.flags = flags;
    }

    void addGlyph(int code, int unicode, int width, int[] bbox, Type3Glyph type3Glyph) {
        if (codeToGlyph.containsKey(code)) {
            removeGlyphFromMappings(code);
        }
        Glyph glyph = new Glyph(code, width, unicode, bbox);
        codeToGlyph.put(code, glyph);
        if (unicode < 0) {
            type3GlyphsWithoutUnicode.put(code, type3Glyph);
        } else {
            unicodeToGlyph.put(unicode, glyph);
            type3Glyphs.put(unicode, type3Glyph);
        }
        recalculateAverageWidth();
    }

    private void removeGlyphFromMappings(int glyphCode) {
        Glyph removed = codeToGlyph.remove(glyphCode);
        if (removed == null) {
            return;
        }
        int unicode = removed.getUnicode();
        if (unicode < 0) {
            type3GlyphsWithoutUnicode.remove(glyphCode);
        } else {
            unicodeToGlyph.remove(unicode);
            type3Glyphs.remove(unicode);
        }
    }

    private void recalculateAverageWidth() {
        int widthSum = 0;
        int glyphsNumber = codeToGlyph.size();
        for (Glyph glyph : codeToGlyph.values()) {
            if (glyph.getWidth() == 0) {
                glyphsNumber--;
                continue;
            }
            widthSum += glyph.getWidth();
        }
        avgWidth = glyphsNumber == 0 ? 0 : widthSum / glyphsNumber;
    }
}
