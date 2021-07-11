package mkl.itext.signing.jcajce;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.PdfSigner;

/**
 * @author mkl
 */
class TestSignBCSimple {
    final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    final static String STORE_PATH = "keystore/test1234.p12";
    final static char[] STORE_PASS = "test1234".toCharArray();
    static PrivateKey pk;
    static Certificate[] chain;

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance("pkcs12", "SunJSSE");
        ks.load(new FileInputStream(STORE_PATH), STORE_PASS);
        String alias = "";
        Enumeration<String> aliases = ks.aliases();
        while (alias.equals("demo") == false && aliases.hasMoreElements()) {
            alias = aliases.nextElement();
        }
        pk = (PrivateKey) ks.getKey(alias, STORE_PASS);
        chain = ks.getCertificateChain(alias);
    }

    @Test
    void testSignSimpleRsa() throws OperatorException, IOException, GeneralSecurityException {
        PrivateKeySignatureContainerBC signatureContainer = new PrivateKeySignatureContainerBC("SHA512withRSA", pk, (X509Certificate) chain[0], PdfName.Adbe_pkcs7_detached);

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-signed-simple-RSA.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signatureContainer, 8192);
        }
    }

    @Test
    void testSignSimpleRsaSsaPss() throws OperatorException, IOException, GeneralSecurityException {
        PrivateKeySignatureContainerBC signatureContainer = new PrivateKeySignatureContainerBC("SHA512withRSAandMGF1", pk, (X509Certificate) chain[0], PdfName.Adbe_pkcs7_detached);

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-signed-simple-RSASSA-PSS.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signatureContainer, 8192);
        }
    }

}
