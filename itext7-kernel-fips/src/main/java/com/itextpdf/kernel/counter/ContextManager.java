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
package com.itextpdf.kernel.counter;

import com.itextpdf.kernel.counter.context.GenericContext;
import com.itextpdf.kernel.counter.context.IContext;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * The class that retrieves context of its invocation.
 */
public class ContextManager {

    private static final ContextManager instance = new ContextManager();

    private final SortedMap<String, IContext> contextMappings = new TreeMap<>(new LengthComparator());

    private ContextManager() {
        registerGenericContext(Arrays.asList(
                NamespaceConstant.CORE_IO,
                NamespaceConstant.CORE_KERNEL,
                NamespaceConstant.CORE_LAYOUT,
                NamespaceConstant.CORE_BARCODES,
                NamespaceConstant.CORE_PDFA,
                NamespaceConstant.CORE_SIGN,
                NamespaceConstant.CORE_FORMS,
                NamespaceConstant.CORE_SXP,
                NamespaceConstant.CORE_SVG), Collections.singletonList(NamespaceConstant.ITEXT));
        registerGenericContext(Collections.singletonList(NamespaceConstant.PDF_DEBUG),
                Collections.singletonList(NamespaceConstant.PDF_DEBUG));
        registerGenericContext(Collections.singletonList(NamespaceConstant.PDF_HTML),
                Collections.singletonList(NamespaceConstant.PDF_HTML));
        registerGenericContext(Collections.singletonList(NamespaceConstant.PDF_INVOICE),
                Collections.singletonList(NamespaceConstant.PDF_INVOICE));
        registerGenericContext(Collections.singletonList(NamespaceConstant.PDF_SWEEP),
                Collections.singletonList(NamespaceConstant.PDF_SWEEP));
        registerGenericContext(Collections.singletonList(NamespaceConstant.PDF_OCR_TESSERACT4),
                Collections.singletonList(NamespaceConstant.PDF_OCR_TESSERACT4));
        registerGenericContext(Collections.singletonList(NamespaceConstant.PDF_OCR), Collections.<String>emptyList());
    }

    /**
     * Gets the singelton instance of this class
     *
     * @return the {@link ContextManager} instance
     */
    public static ContextManager getInstance() {
        return instance;
    }

    /**
     * Gets the context associated with the passed class object.
     * The context is determined by class namespace.
     *
     * @param clazz the class for which the context will be determined.
     * @return the {@link IContext} associated with the class, or {@code null} if the class is unknown.
     */
    public IContext getContext(Class<?> clazz) {
        return clazz != null ? getContext(clazz.getName()) : null;
    }

    /**
     * Gets the context associated with the passed class object.
     * The context is determined by class namespace.
     *
     * @param className the class name with the namespace for which the context will be determined.
     * @return the {@link IContext} associated with the class, or {@code null} if the class is unknown.
     */
    public IContext getContext(String className) {
        return getNamespaceMapping(getRecognisedNamespace(className));
    }

    String getRecognisedNamespace(String className) {
        if (className != null) {
            // If both "a" and "a.b" namespaces are registered,
            // iText should consider the context of "a.b" for an "a.b" event,
            // that's why the contexts are sorted by the length of the namespace
            for (String namespace : contextMappings.keySet()) {
                //Conversion to lowercase is done to be compatible with possible changes in case of packages/namespaces
                if (className.toLowerCase().startsWith(namespace)) {
                    return namespace;
                }
            }
        }
        return null;
    }

    private IContext getNamespaceMapping(String namespace) {
        if (namespace != null) {
            return contextMappings.get(namespace);
        }
        return null;
    }

    private void registerGenericContext(Collection<String> namespaces, Collection<String> eventIds) {
        GenericContext context = new GenericContext(eventIds);
        for (String namespace : namespaces) {
            //Conversion to lowercase is done to be compatible with possible changes in case of packages/namespaces
            registerContext(namespace.toLowerCase(), context);
        }
    }

    private void registerContext(String namespace, IContext context) {
        contextMappings.put(namespace, context);
    }

    private static class LengthComparator implements Comparator<String> {
        @Override
        public int compare(String o1, String o2) {
            int lengthComparison = -Integer.compare(o1.length(), o2.length());
            if (0 != lengthComparison) {
                return lengthComparison;
            } else {
                return o1.compareTo(o2);
            }
        }
    }
}
