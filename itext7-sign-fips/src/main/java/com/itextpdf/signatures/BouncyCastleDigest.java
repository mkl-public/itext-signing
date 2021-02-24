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
package com.itextpdf.signatures;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;

/**
 * Implementation for digests accessed directly from the BouncyCastle library bypassing
 * any provider definition.
 */
public class BouncyCastleDigest implements IExternalDigest {
    DefaultJcaJceHelper helper = new DefaultJcaJceHelper();

    @Override
    public MessageDigest getMessageDigest(String hashAlgorithm) throws GeneralSecurityException {
        String oid = DigestAlgorithms.getAllowedDigest(hashAlgorithm);

        switch (oid) {
            case "1.2.840.113549.2.2":      //MD2
                return helper.createDigest("MD2");
            case "1.2.840.113549.2.5":      //MD5
                return helper.createDigest("MD5");
            case "1.3.14.3.2.26":           //SHA1
                return helper.createDigest("SHA1");
            case "2.16.840.1.101.3.4.2.4":  //SHA224
                return helper.createDigest("SHA224");
            case "2.16.840.1.101.3.4.2.1":  //SHA256
                return helper.createDigest("SHA256");
            case "2.16.840.1.101.3.4.2.2":  //SHA384
                return helper.createDigest("SHA384");
            case "2.16.840.1.101.3.4.2.3":  //SHA512
                return helper.createDigest("SHA512");
            case "1.3.36.3.2.2":            //RIPEMD128
                return helper.createDigest("RIPEMD128");
            case "1.3.36.3.2.1":            //RIPEMD160
                return helper.createDigest("RIPEMD160");
            case "1.3.36.3.2.3":            //RIPEMD256
                return helper.createDigest("RIPEMD256");
            case "1.2.643.2.2.9":           //GOST3411
                return helper.createDigest("GOST3411");
            default:
                throw new NoSuchAlgorithmException(hashAlgorithm);
        }
    }
}
