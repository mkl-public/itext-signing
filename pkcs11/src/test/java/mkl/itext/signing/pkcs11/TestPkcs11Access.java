package mkl.itext.signing.pkcs11;

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

class TestPkcs11Access {

    @Test
    void testAccessKeyAndCertificate() throws GeneralSecurityException, IOException {
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        String config = TestEnvironment.getPkcs11Config();

        Provider p = Security.getProvider("SunPKCS11");
        assertNotNull(p, "Could not find SunPKCS11 provider.");

        Provider providerPKCS11 = p.configure(config);
        assertNotNull(providerPKCS11, "No provider generated for PKCS#11 configuration.");
        Security.addProvider(providerPKCS11);
        System.out.printf("Provider name: %s\n", providerPKCS11.getName());

        KeyStore ks = KeyStore.getInstance("PKCS11", providerPKCS11);
        assertNotNull(ks, "Provider did not provide a key store.");
        ks.load(null, "5678".toCharArray());

        Enumeration<String> aliases = ks.aliases();
        assertNotNull(aliases, "Key store did not provide an aliases enumeration.");
        assertTrue(aliases.hasMoreElements(), "Aliases enumeration is empty.");
        String alias = aliases.nextElement();
        System.out.printf("Alias name: %s\n", alias);

        PrivateKey pk = (PrivateKey) ks.getKey(alias, "5678".toCharArray());
        assertNotNull(pk, "Key store did not provide a private key for the alias " + alias);

        Certificate[] chain = ks.getCertificateChain(alias);
        assertNotNull(chain, "Key store did not provide a certificate chain for the alias " + alias);
        assertNotEquals(0, chain.length, "Key store provided an empty certificate chain for the alias " + alias);
        for (Certificate certificate : chain)
            if (certificate instanceof X509Certificate)
                System.out.printf("Subject: %s\n", ((X509Certificate) certificate).getSubjectDN());
    }
}
