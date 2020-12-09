package mkl.itext.signing.aws.kms;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;

import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

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

    @Test
    void testSignSimpleRsaSsaPss() throws IOException, GeneralSecurityException {
        String keyId = "alias/SigningExamples-RSA_2048";
        X509Certificate certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS PDF Signing Test,OU=mkl tests,O=mkl", TestSignSimple::selectRsaSsaPss);
        AwsKmsSignatureContainer signatureContainer = new AwsKmsSignatureContainer(certificate, keyId, TestSignSimple::selectRsaSsaPss);

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-aws-kms-signed-simple-RSASSA_PSS.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signatureContainer, 8192);
        }
    }

    static SigningAlgorithmSpec selectRsaSsaPss (List<SigningAlgorithmSpec> specs) {
        if (specs != null)
            return specs.stream().filter(spec -> spec.toString().startsWith("RSASSA_PSS")).findFirst().orElse(null);
        else
            return null;
    }

    @Test
    void testSignSimpleEcdsaExternal() throws IOException, GeneralSecurityException {
        String keyId = "alias/SigningExamples-ECC_NIST_P256";
        X509Certificate certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS PDF Signing Test,OU=mkl tests,O=mkl");
        AwsKmsSignatureContainer signatureContainer = new AwsKmsSignatureContainer(certificate, keyId);

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-aws-kms-signed-simple-ECDSA-External.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signatureContainer, 8192);
        }
    }
}
