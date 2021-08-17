package mkl.itext.signing.jce.utimaco;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;
import com.itextpdf.signatures.PrivateKeySignature;

import CryptoServerAPI.CryptoServerException;
import CryptoServerJCE.CryptoServerProvider;

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

    /**
     * Test using the custom {@link UtimacoJceSignature} implementation
     * of {@link IExternalSignature}.
     */
    @Test
    void testSignSimpleUtimacoJceSignature() throws IOException, CryptoServerException, GeneralSecurityException {
        String config = "Device = 3001@192.168.178.49\n"
                + "DefaultUser = JCE\n"
                + "KeyGroup = JCE";
        UtimacoJceSignature signature = new UtimacoJceSignature(new ByteArrayInputStream(config.getBytes()))
                .select(null, "5678".toCharArray()).setHashAlgorithm("SHA256");

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-specific.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest, signature, signature.getChain(), null, null, null, 0, CryptoStandard.CMS);
        }
    }

    /**
     * Test using the iText {@link PrivateKeySignature} implementation
     * of {@link IExternalSignature}.
     */
    @Test
    void testSignSimpleGeneric() throws NumberFormatException, IOException, CryptoServerException, GeneralSecurityException {
        String config = "Device = 3001@192.168.178.49\n"
                + "DefaultUser = JCE\n"
                + "KeyGroup = JCE";
        char[] pin = "5678".toCharArray();
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(config.getBytes()));
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, pin);

        Enumeration<String> aliases = ks.aliases();
        Assertions.assertTrue(aliases.hasMoreElements(), "No alias in CryptoServerProvider key store");
        String alias = aliases.nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pin);
        Assertions.assertNotNull(pk, "No key for alias");
        Certificate[] chain = ks.getCertificateChain(alias);
        Assertions.assertNotNull(chain, "No chain for alias");

        IExternalSignature signature = new PrivateKeySignature(pk, "SHA256", provider.getName());
        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-generic.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            IExternalDigest externalDigest = new BouncyCastleDigest();
            pdfSigner.signDetached(externalDigest, signature, chain, null, null, null, 0, CryptoStandard.CMS);
        }
    }

    /**
     * Test using the custom {@link UtimacoJceSignatureContainer} implementation
     * of {@link IExternalSignature} to create a RSA signature with PKCS#1 v1.5
     * padding.
     */
    @Test
    void testSignSimpleUtimacoJceSignatureContainerRsaPkcs1() throws IOException, CryptoServerException, GeneralSecurityException {
        String config = "Device = 3001@192.168.178.49\n"
                + "DefaultUser = JCE\n"
                + "KeyGroup = JCE";
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(config.getBytes()));
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);

        UtimacoJceSignatureContainer signature = new UtimacoJceSignatureContainer(
                provider, PdfName.Adbe_pkcs7_detached)
                .select(null, "5678".toCharArray()).with("SHA256withRSA", null);

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-container-specific-pkcs1.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signature, 8192);
        }
    }

    /**
     * Test using the custom {@link UtimacoJceSignatureContainer} implementation
     * of {@link IExternalSignature} to create a RSASSA-PSS signature.
     */
    @Test
    void testSignSimpleUtimacoJceSignatureContainerRsaSsaPss() throws IOException, CryptoServerException, GeneralSecurityException {
        String config = "Device = 3001@192.168.178.49\n"
                + "DefaultUser = JCE\n"
                + "KeyGroup = JCE";
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(config.getBytes()));
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);

        UtimacoJceSignatureContainer signature = new UtimacoJceSignatureContainer(
                provider, PdfName.Adbe_pkcs7_detached)
                .select(null, "5678".toCharArray()).with("SHA256withRSA", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));

        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf");
                PdfReader pdfReader = new PdfReader(resource);
                OutputStream result = new FileOutputStream(new File(RESULT_FOLDER, "circles-utimaco-signed-simple-container-specific-pss.pdf"))) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

            pdfSigner.signExternalContainer(signature, 8192);
        }
    }
}
