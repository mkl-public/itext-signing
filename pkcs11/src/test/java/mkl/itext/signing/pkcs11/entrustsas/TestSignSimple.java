package mkl.itext.signing.pkcs11.entrustsas;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

import com.itextpdf.signatures.OCSPVerifier;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.TSAClientBouncyCastle;

import mkl.itext.signing.pkcs11.BaseSignSimple;

/**
 * This test class signs a PDF file using {@link BaseSignSimple}
 * with variables set to access the Entrust Signing Automation
 * Service as configured and initialized on the original development
 * machine.
 * 
 * @author mkl
 */
class TestSignSimple extends BaseSignSimple {

    @Test
    void test() throws IOException, GeneralSecurityException {
        boolean msWindowsOs = System.getProperty("os.name").toLowerCase().contains("win");
        config = msWindowsOs ?
                "--name = Entrust\n"
                + "library = c:\\Program Files\\Entrust\\SigningClient\\P11SigningClient64.dll\n"
                + "slot = 1\n"
                :
                "--name = Entrust\n"
                + "library = /home/mkl/bin/libp11signingclient64.so\n"
                + "slot = 1";
        alias = null;
        pin = (msWindowsOs ? "1234" : "5678").toCharArray();
        result = new File(RESULT_FOLDER, "circles-pkcs11-signed-simple-entrust-sas.pdf");
        ocspClient = new OcspClientBouncyCastle(null);
        tsaClient = new TSAClientBouncyCastle("http://timestamp.entrust.net/TSS/RFC3161sha2TS");
        testSignSimple();
    }

}
