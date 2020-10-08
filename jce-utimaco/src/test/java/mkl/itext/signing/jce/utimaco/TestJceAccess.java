package mkl.itext.signing.jce.utimaco;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.junit.jupiter.api.Test;

import CryptoServerAPI.CryptoServerException;
import CryptoServerJCE.CryptoServerProvider;

class TestJceAccess {
    @Test
    void test() throws IOException, CryptoServerException, GeneralSecurityException {
        String config = "Device = 3001@127.0.0.1\n"
                + "DefaultUser = JCE\n"
                + "KeyGroup = JCE";
        CryptoServerProvider provider = new CryptoServerProvider(new ByteArrayInputStream(config.getBytes()));
        Security.addProvider(provider);
        provider.loginPassword("JCE","5678");

        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, null);

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
