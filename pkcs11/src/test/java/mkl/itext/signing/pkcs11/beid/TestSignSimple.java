package mkl.itext.signing.pkcs11.beid;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

import mkl.itext.signing.pkcs11.BaseSignSimple;

/**
 * <p>
 * This test class signs a PDF file using {@link BaseSignSimple}
 * with variables set to access a Belgian ID card as
 * configured and initialized on the original development
 * machine.
 * </p>
 * 
 * @author mkl
 */
class TestSignSimple extends BaseSignSimple {

    @Test
    void test() throws IOException, GeneralSecurityException {
        config = "--name = BeID\n"
                + "library = \"c:/Program Files (x86)/Belgium Identity Card/FireFox Plugin Manifests/beid_ff_pkcs11_64.dll\"\n"
                + "slot = 0\n";
        alias = "Signature";
        pin = "1234".toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-beid.pdf");
        testSignSimple();
    }

    @Test
    void testContainer() throws IOException, GeneralSecurityException {
        config = "--name = BeID\n"
                + "library = \"c:/Program Files (x86)/Belgium Identity Card/FireFox Plugin Manifests/beid_ff_pkcs11_64.dll\"\n"
                + "slot = 0\n";
        alias = "Signature";
        pin = "1234".toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-beid-container.pdf");
        testSignSimpleContainer();
    }
}
