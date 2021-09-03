package mkl.itext.signing.pkcs11;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;

import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;

/**
 * This class provides a simple test routine that signs a PDF
 * using a {@link Pkcs11Signature}. It furthermore houses variables
 * for the PKCS11 configuration, alias, PIN, and the result file name.
 * It is meant to serve as a base class for actual unit test classes
 * which first set those variables and then call the test routine.
 * 
 * @author mkl
 */
public class BaseSignSimple {
    public final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    protected void testSignSimple() throws IOException, GeneralSecurityException {
        Pkcs11Signature signature = (config.startsWith("--") ? new Pkcs11Signature(config) : new Pkcs11Signature(new File(config)))
                .select(alias, pin).setHashAlgorithm("SHA256");

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream resultStream = new FileOutputStream(result)    ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, resultStream, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest , signature, signature.getChain(), null, null, tsaClient, 0, CryptoStandard.CMS);
        }
    }

    protected void testSignSimpleContainer() throws IOException, GeneralSecurityException {
        Pkcs11SignatureContainer signature = (config.startsWith("--") ? new Pkcs11SignatureContainer(config, PdfName.Adbe_pkcs7_detached) : new Pkcs11SignatureContainer(new File(config), PdfName.Adbe_pkcs7_detached))
                .select(alias, pin).with("SHA256withRSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream resultStream = new FileOutputStream(result)    ) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, resultStream, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signature, 8192);
        }
    }

    protected String config;
    protected String alias;
    protected char[] pin;
    protected File result;

    protected ITSAClient tsaClient = null;
}
