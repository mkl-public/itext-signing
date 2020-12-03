package mkl.itext.signing.aws.kms;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;

/**
 * @author mkl
 */
class TestSignSimple {
    final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    @Test
    void testSignSimpleRsa() throws IOException, GeneralSecurityException {
        String keyId = "alias/SigningExamples-RSA_2048";
        AwsKmsSignature signature = new AwsKmsSignature(keyId);
        Certificate certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS PDF Signing Test,OU=mkl tests,O=mkl");

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-aws-kms-signed-simple-RSA.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest , signature, new Certificate[] {certificate}, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    @Test
    void testSignSimpleEcdsa() throws IOException, GeneralSecurityException {
        String keyId = "alias/SigningExamples-ECC_NIST_P256";
        AwsKmsSignature signature = new AwsKmsSignature(keyId);
        Certificate certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS PDF Signing Test,OU=mkl tests,O=mkl");

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-aws-kms-signed-simple-ECDSA.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest , signature, new Certificate[] {certificate}, null, null, null, 0, CryptoStandard.CMS);
        }
    }
}
