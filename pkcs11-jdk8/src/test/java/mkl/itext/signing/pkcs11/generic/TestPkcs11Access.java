package mkl.itext.signing.pkcs11.generic;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import sun.security.pkcs11.SunPKCS11;

/**
 * This test class executes some simple tests addressing the
 * PKCS11 device to retrieve key handles and certificates.
 * The {@link TestEnvironment} utility is used to retrieve
 * parameters for accessing the device.
 * 
 * @author mkl
 */
class TestPkcs11Access {

    @Test
    void testAccessKeyAndCertificate() throws GeneralSecurityException, IOException {
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        String config = TestEnvironment.getPkcs11Config();

        Provider providerPKCS11 = new SunPKCS11(config);
        assertNotNull(providerPKCS11, "No provider generated for PKCS#11 configuration.");
        Security.addProvider(providerPKCS11);
        System.out.printf("Provider name: %s\n", providerPKCS11.getName());

        KeyStore ks = KeyStore.getInstance("PKCS11", providerPKCS11);
        assertNotNull(ks, "Provider did not provide a key store.");
        ks.load(null, TestEnvironment.getPkcs11Pin());

        Enumeration<String> aliases = ks.aliases();
        assertNotNull(aliases, "Key store did not provide an aliases enumeration.");
        assertTrue(aliases.hasMoreElements(), "Aliases enumeration is empty.");
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.printf("Alias name: %s\n", alias);
            PrivateKey pk = (PrivateKey) ks.getKey(alias, TestEnvironment.getPkcs11Pin());
            System.out.printf("  has private key: %s\n", (pk != null));
            if (pk == null)
                continue;

            Certificate[] chain = ks.getCertificateChain(alias);
            assertNotNull(chain, "Key store did not provide a certificate chain for the alias " + alias);
            assertNotEquals(0, chain.length, "Key store provided an empty certificate chain for the alias " + alias);
            for (Certificate certificate : chain)
                if (certificate instanceof X509Certificate)
                    System.out.printf("Subject: %s\n", ((X509Certificate) certificate).getSubjectDN());
        }
    }
}
