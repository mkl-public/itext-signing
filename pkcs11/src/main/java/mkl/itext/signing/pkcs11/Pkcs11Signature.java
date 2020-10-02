package mkl.itext.signing.pkcs11;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Enumeration;

import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;

/**
 * @author mkl
 */
public class Pkcs11Signature implements IExternalSignature {
    /** The alias. */
    String alias;

    /** The private key object. */
    PrivateKey pk;

    /** The certificate chain. */
    Certificate[] chain;

    /** The hash algorithm. */
    String hashAlgorithm;

    /** The encryption algorithm (obtained from the private key) */
    String encryptionAlgorithm;

    /** The security provider */
    final Provider provider;

    public Pkcs11Signature(File pkcs11configFile) {
        Provider p = Security.getProvider("SunPKCS11");
        provider = p.configure(pkcs11configFile.getAbsolutePath());
        Security.addProvider(provider);
    }

    public Pkcs11Signature(String pkcs11config) {
        Provider p = Security.getProvider("SunPKCS11");
        if (!pkcs11config.startsWith("--"))
            pkcs11config = "--" + pkcs11config;
        provider = p.configure(pkcs11config);
        Security.addProvider(provider);
    }

    public Pkcs11Signature(Provider pkcs11provider) {
        provider = pkcs11provider;
        Security.addProvider(provider);
    }

    public Pkcs11Signature select(String alias, char[] pin) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS11", provider);
        ks.load(null, pin);

        boolean found = false;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String thisAlias = aliases.nextElement();
            if (alias == null || alias.equals(thisAlias)) {
                PrivateKey thisPk = (PrivateKey) ks.getKey(thisAlias, pin);
                if (thisPk == null)
                    continue;
                Certificate[] thisChain = ks.getCertificateChain(thisAlias);
                if (thisChain == null)
                    continue;

                found = true;
                pk = thisPk;
                chain = thisChain;
                this.alias = thisAlias;
                break;
            }
        }

        if (found) {
            String algorithm = pk.getAlgorithm();
            encryptionAlgorithm = "EC".equals(algorithm) ? "ECDSA" : algorithm;
        } else {
            pk = null;
            chain = null;
            this.alias = null;
            encryptionAlgorithm = null;
        }

        return this;
    }

    public String getAlias() {
        return alias;
    }

    public Certificate[] getChain() {
        return chain;
    }

    @Override
    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    @Override
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public Pkcs11Signature setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigest(hashAlgorithm));
        return this;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        String algorithm = hashAlgorithm + "with" + encryptionAlgorithm;
        Signature sig = Signature.getInstance(algorithm, provider);
        sig.initSign(pk);
        sig.update(message);
        return sig.sign();
    }
}
