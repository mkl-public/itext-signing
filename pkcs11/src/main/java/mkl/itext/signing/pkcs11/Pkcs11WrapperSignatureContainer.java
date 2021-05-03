package mkl.itext.signing.pkcs11;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.util.Arrays;
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
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.signatures.IExternalSignatureContainer;

import iaik.pkcs.pkcs11.TokenException;

/**
 * This {@link IExternalSignatureContainer} implementation is based on the
 * <a href="https://jce.iaik.tugraz.at/products/core-crypto-toolkits/pkcs11-wrapper/">
 * IAIK PKCS#11 Wrapper</a>.
 * 
 * @author mkl
 */
public class Pkcs11WrapperSignatureContainer extends Pkcs11WrapperKeyAndCertificate implements IExternalSignatureContainer {
    String signatureAlgorithm = null;

    public Pkcs11WrapperSignatureContainer(String libraryPath, long slotId) throws IOException, TokenException {
        super(libraryPath, slotId);
    }

    @Override
    public Pkcs11WrapperSignatureContainer select(String alias, String certLabel, char[] pin)
            throws TokenException, CertificateException {
        super.select(alias, certLabel, pin);
        return this;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public Pkcs11WrapperSignatureContainer setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    @Override
    public byte[] sign(InputStream data) throws GeneralSecurityException {
        try {
            CMSTypedData msg = new CMSTypedDataInputStream(data);

            X509CertificateHolder signCert = new X509CertificateHolder(chain[0].getEncoded());

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(buildContentSigner(signatureAlgorithm), signCert));

            gen.addCertificates(new JcaCertStore(Arrays.asList(chain)));

            CMSSignedData sigData = gen.generate(msg, false);
            return sigData.getEncoded();
        } catch (IOException | OperatorCreationException | CMSException | TokenException e) {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public void modifySigningDictionary(PdfDictionary signDic) {
        signDic.put(PdfName.Filter, new PdfName("MKLx_PKCS11_WRAPPER_SIGNER"));
        signDic.put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);
    }

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
