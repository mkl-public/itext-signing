package mkl.itext.signing.pkcs11.dtrust;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Properties;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import mkl.itext.signing.pkcs11.Pkcs11Signature;

/**
 * <p>
 * This test class signs a PDF file using a {@link Pkcs11Signature}
 * initialized to access a D-Trust card via the Nexus Personal
 * PKCS#11 driver as configured and initialized on the original
 * development machine. It uses the IAIK Java PKCS#11 security
 * provider.
 * </p>
 * <p>
 * In contrast to {@link TestSignSimple} the output of this test is
 * valid: The IAIK provider does not only offer the pairing of the
 * private key and the first certificate with the same ID like the
 * SunPKCS11 provider but instead all pairings of the private key
 * with such a certificate, with an alias derived from the label
 * of the certificate. By selecting the pairing for the alias
 * "Signaturzertifikat", therefore, the used private key and
 * certificate do cryptographically match, making the result
 * signature valid.
 * </p>
 * 
 * @author mkl
 */
class TestSignSimpleIaik {
    public final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
    }

    @Test
    void test() throws GeneralSecurityException, IOException {
        String alias = "Signaturzertifikat";
        char[] pin = "12345678".toCharArray();
        File result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-dtrust-iaik.pdf");
        ITSAClient tsaClient = null;

        Properties properties = new Properties();
        properties.setProperty("PKCS11_NATIVE_MODULE", "c:/Program Files (x86)/Personal/bin64/personal64.dll");
        properties.setProperty("SLOT_ID", "1");
        IAIKPkcs11 provider = new IAIKPkcs11(properties);
        Security.addProvider(provider);

        Pkcs11Signature signature = new Pkcs11Signature(provider).select(alias, pin).setHashAlgorithm("SHA256");

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream resultStream = new FileOutputStream(result)    ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, resultStream, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest , signature, signature.getChain(), null, null, tsaClient, 0, CryptoStandard.CMS);
        }
    }
}
