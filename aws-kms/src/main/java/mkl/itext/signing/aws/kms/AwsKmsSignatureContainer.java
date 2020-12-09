package mkl.itext.signing.aws.kms;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

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
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.signatures.IExternalSignatureContainer;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * @author mkl
 */
public class AwsKmsSignatureContainer implements IExternalSignatureContainer {
    public AwsKmsSignatureContainer(X509Certificate x509Certificate, String keyId) {
        this(x509Certificate, keyId, a -> a != null && a.size() > 0 ? a.get(0) : null);
    }

    public AwsKmsSignatureContainer(X509Certificate x509Certificate, String keyId, Function<List<SigningAlgorithmSpec>, SigningAlgorithmSpec> selector) {
        this.x509Certificate = x509Certificate;
        this.keyId = keyId;

        try (   KmsClient kmsClient = KmsClient.create() ) {
            GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder()
                    .keyId(keyId)
                    .build();
            GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);
            signingAlgorithmSpec = selector.apply(getPublicKeyResponse.signingAlgorithms());
            if (signingAlgorithmSpec == null)
                throw new IllegalArgumentException("KMS key has no signing algorithms");
            contentSigner = new AwsKmsContentSigner(keyId, signingAlgorithmSpec);
        }
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
        signDic.put(PdfName.Filter, new PdfName("MKLx_AWS_KMS_SIGNER"));
        signDic.put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);
    }

    final X509Certificate x509Certificate;
    final String keyId;
    final SigningAlgorithmSpec signingAlgorithmSpec;
    final ContentSigner contentSigner;

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
