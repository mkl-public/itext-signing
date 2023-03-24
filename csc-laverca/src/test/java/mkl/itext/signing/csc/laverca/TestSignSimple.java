package mkl.itext.signing.csc.laverca;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;

/**
 * @author mkl
 */
class TestSignSimple {
    // from laverca-csc-client tests
    public static final String METHICS_BASE_URL = "https://demo.methics.fi";
    public static final String METHICS_VERSION = "v1";
    public static final String METHICS_USERNAME = "35847001001";
    public static final String METHICS_API_KEY  = "E6v31rAxWoY7";

    final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    /**
     * Test using the custom {@link UtimacoJceSignature} implementation
     * of {@link IExternalSignature} with the methics demo server.
     */
    @Test
    void testSignSimpleMethics() throws IOException, GeneralSecurityException {
        CscLavercaClientSignature signature = new CscLavercaClientSignature(METHICS_BASE_URL, METHICS_VERSION, METHICS_USERNAME, METHICS_API_KEY,
                client -> client.listCredentials().credentialIDs.get(0),
                algorithms -> "1.2.840.113549.1.1.11");

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-csc-lavera-signed-simple-methics.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest, signature, signature.getChain(), null, null, null, 0, CryptoStandard.CMS);
        }
    }

}
