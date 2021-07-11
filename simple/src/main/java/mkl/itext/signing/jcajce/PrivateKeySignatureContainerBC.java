package mkl.itext.signing.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.PrivateKeySignature;

/**
 * <p>
 * This {@link IExternalSignatureContainer} implementation allows signing a PDF
 * with iText 7 using a JCS/JCE private key and X509 certificate. In contrast to
 * the {@link PrivateKeySignature} already included in iText 7 this class also
 * generates the CMS container to be embedded in the PDF. Thus, it in particular
 * is not restricted by the limitations of the CMS container generation code
 * used by iText itself.
 * </p>
 * <p>
 * This class as is obviously has its own limitations. As it's no an embedded
 * part of the iText signature API, though, you can easily improve it to match
 * your requirements.
 * </p>
 * 
 * @author mkl
 */
public class PrivateKeySignatureContainerBC implements IExternalSignatureContainer {

    public PrivateKeySignatureContainerBC(String signatureAlgorithm, PrivateKey privateKey, X509Certificate x509Certificate, PdfName subfilter) throws OperatorCreationException {
        this.subfilter = subfilter;
        this.x509Certificate = x509Certificate;
        this.contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
    }

    @Override
    public byte[] sign(InputStream data) throws GeneralSecurityException {
        try {
            CMSTypedData msg = new CMSTypedDataInputStream(data);

            X509CertificateHolder signCert = new X509CertificateHolder(x509Certificate.getEncoded());

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(contentSigner, signCert));

            gen.addCertificates(new JcaCertStore(Collections.singleton(signCert)));

            CMSSignedData sigData = gen.generate(msg, false);
            return sigData.getEncoded();
        } catch (IOException | OperatorCreationException | CMSException e) {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public void modifySigningDictionary(PdfDictionary signDic) {
        signDic.put(PdfName.Filter, new PdfName("MKLx_GENERIC_SIGNER"));
        signDic.put(PdfName.SubFilter, subfilter);
    }

    final ContentSigner contentSigner;
    final X509Certificate x509Certificate;
    final PdfName subfilter;

    class CMSTypedDataInputStream implements CMSTypedData {
        InputStream in;

        public CMSTypedDataInputStream(InputStream is) {
            in = is;
        }

        @Override
        public ASN1ObjectIdentifier getContentType() {
            return PKCSObjectIdentifiers.data;
        }

        @Override
        public Object getContent() {
            return in;
        }

        @Override
        public void write(OutputStream out) throws IOException,
                CMSException {
            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            in.close();
        }
    }
}
