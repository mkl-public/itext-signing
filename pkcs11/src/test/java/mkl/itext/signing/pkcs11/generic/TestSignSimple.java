package mkl.itext.signing.pkcs11.generic;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

import mkl.itext.signing.pkcs11.BaseSignSimple;

/**
 * This test class signs a PDF file using {@link BaseSignSimple}
 * configured according to the values the {@link TestEnvironment}
 * utility provides.
 * 
 * @author mkl
 */
class TestSignSimple extends BaseSignSimple {

    @Test
    void test() throws IOException, GeneralSecurityException {
        config = TestEnvironment.getPkcs11Config();
        alias = TestEnvironment.getPkcs11Alias();
        pin = TestEnvironment.getPkcs11Pin();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-generic.pdf");
        testSignSimple();
    }

}
