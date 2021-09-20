package mkl.itext.signing.pkcs11.utimaco;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

import mkl.itext.signing.pkcs11.BaseSignSimple;

/**
 * <p>
 * This test class signs a PDF file using {@link BaseSignSimple}
 * with variables set to access an Utimaco Simulator as
 * configured and initialized on the original development
 * machine.
 * </p>
 * <p>
 * Please remember to set the <code>CS_PKCS11_R2_CFG</code>
 * environment variable to point to the Utimaco configuration
 * file <code>cs_pkcs11_R2.cfg</code>.
 * </p>
 * 
 * @author mkl
 */
class TestSignSimple extends BaseSignSimple {

    @Test
    void test() throws IOException, GeneralSecurityException {
        config = "--name = Utimaco\n"
                + "library = d:/Program Files/Utimaco/CryptoServer/Lib/cs_pkcs11_R2.dll\n"
                + "slot = 0\n";
        alias = null;
        pin = "5678".toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-utimaco.pdf");
        testSignSimple();
    }

    @Test
    void testContainer() throws IOException, GeneralSecurityException {
        config = "--name = Utimaco\n"
                + "library = d:/Program Files/Utimaco/CryptoServer/Lib/cs_pkcs11_R2.dll\n"
                + "slot = 0\n";
        alias = null;
        pin = "5678".toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-utimaco-container.pdf");
        testSignSimpleContainer();
    }
}
