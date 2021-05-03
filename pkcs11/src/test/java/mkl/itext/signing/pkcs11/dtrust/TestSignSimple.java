package mkl.itext.signing.pkcs11.dtrust;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

import mkl.itext.signing.pkcs11.BaseSignSimple;

/**
 * <p>
 * This test class attempts to sign a PDF file using {@link
 * BaseSignSimple} with variables set to access a D-Trust
 * card via the Nexus Personal PKCS#11 driver as configured
 * and initialized on the original development machine.
 * </p>
 * <p>
 * The output of this test is invalid, though: The SunPKCS11
 * provider, when looking for keys and certificates on a PKCS11
 * device iterates over the private keys and associates each of
 * them with the certificate with the same ID. Unfortunately,
 * though, the Nexus driver for D-Trust cards offers all
 * certificates with the same ID and SunPKCS11 uses the one it
 * retrieves first, by chance the root certificate, not the
 * signer certificate. Thus, private key and certificate do not
 * cryptographically match, making the result signature invalid.
 * </p>
 * <p>
 * See {@link TestSignSimpleIaik} for comparison, though.
 * </p>
 * 
 * @author mkl
 */
class TestSignSimple extends BaseSignSimple {

    @Test
    void test() throws IOException, GeneralSecurityException {
        config = "--name = DTrustOnNexus\n"
                + "library = \"c:/Program Files (x86)/Personal/bin64/personal64.dll\"\n"
                + "slot = 1\n";
        alias = null;
        pin = "12345678".toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-dtrust.pdf");
        testSignSimple();
    }

}
