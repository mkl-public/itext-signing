package mkl.itext.signing.pkcs11.softhsm;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

import mkl.itext.signing.pkcs11.BaseSignSimple;

/**
 * This test class signs a PDF file using {@link BaseSignSimple}
 * with variables set to access a SoftHSM simulator as
 * configured and initialized on the original development
 * machine.
 * 
 * @author mkl
 */
class TestSignSimple extends BaseSignSimple {

    @Test
    void test() throws IOException, GeneralSecurityException {
        boolean msWindowsOs = System.getProperty("os.name").toLowerCase().contains("win");
        config = msWindowsOs ?
                "--name = 171137967\n"
                + "library = d:/Program Files/SoftHSM2/lib/softhsm2-x64.dll\n"
                + "slot = 171137967\n"
                :
                "--name = 925991530\n"
                + "library = /lib/softhsm/libsofthsm2.so\n"
                + "slot = 925991530";
        alias = null;
        pin = "5678".toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-softhsm.pdf");
        testSignSimple();
    }

}
