package mkl.itext.signing.pkcs11.dtrust;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;

import iaik.pkcs.pkcs11.TokenException;
import mkl.itext.signing.pkcs11.Pkcs11WrapperSignature;

/**
 * <p>
 * This test class signs a PDF file using a {@link Pkcs11WrapperSignature}
 * initialized to access a D-Trust card via the Nexus Personal PKCS#11
 * driver as configured and initialized on the original development machine.
 * It uses the IAIK Java PKCS#11 Wrapper.
 * </p>
 * <p>
 * In contrast to {@link TestSignSimple} the output of this test is
 * valid, just like that of {@link TestSignSimpleIaik}. This signature
 * class allows selecting the certificate explicitly by its label alone
 * without any ID or label relationship with the private key. In case
 * of the given PKCS#11 device this is very comfortable.
 * </p>
 * 
 * @author mkl
 */
class TestSignSimpleWrapper {
    public final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
    }

    @Test
    void test() throws TokenException, IOException, GeneralSecurityException {
        String certLabel = "Signaturzertifikat";
        char[] pin = "12345678".toCharArray();
        File result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-dtrust-wrapper.pdf");
        ITSAClient tsaClient = null;

        try (   Pkcs11WrapperSignature signature = new Pkcs11WrapperSignature("c:/Program Files (x86)/Personal/bin64/personal64.dll", 1)
                    .select(null, certLabel, pin).setHashAlgorithm("SHA256");
                InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream resultStream = new FileOutputStream(result)    ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, resultStream, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest , signature, signature.getChain(), null, null, tsaClient, 0, CryptoStandard.CMS);
        }

    }

}
