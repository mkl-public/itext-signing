package mkl.itext.signing.pkcs11;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertificateException;

import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This {@link IExternalSignature} implementation is based on the
 * <a href="https://jce.iaik.tugraz.at/products/core-crypto-toolkits/pkcs11-wrapper/">
 * IAIK PKCS#11 Wrapper</a>
 * 
 * @author mkl
 */
public class Pkcs11WrapperSignature extends Pkcs11WrapperKeyAndCertificate implements IExternalSignature {
    String encryptionAlgorithm;
    String hashAlgorithm;

    public Pkcs11WrapperSignature(String libraryPath, long slotId) throws IOException, TokenException {
        super(libraryPath, slotId);
    }

    public Pkcs11WrapperSignature select(String alias, String certLabel, char[] pin) throws TokenException, CertificateException {
        super.select(alias, certLabel, pin);
        if (Key.KeyType.RSA.equals(keyType)) {
            encryptionAlgorithm = "RSA";
        } else if (Key.KeyType.DSA.equals(keyType)) {
            encryptionAlgorithm = "DSA";
        } else if (Key.KeyType.ECDSA.equals(keyType)) {
            encryptionAlgorithm = "ECDSA";
        } else {
            encryptionAlgorithm = null;
        }

        return this;
    }

    @Override
    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    @Override
    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public Pkcs11WrapperSignature setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigest(hashAlgorithm));
        return this;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        long mechanismId;
        switch(encryptionAlgorithm) {
        case "DSA":
            switch(hashAlgorithm) {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_DSA_SHA1;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_DSA_SHA224;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_DSA_SHA256;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_DSA_SHA384;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_DSA_SHA512;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + hashAlgorithm + "with" + encryptionAlgorithm);
            }
        case "ECDSA":
            switch (hashAlgorithm)
            {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA1;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA224;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA256;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA384;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA512;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + hashAlgorithm + "with" + encryptionAlgorithm);
            }
            break;
        case "RSA":
            switch (hashAlgorithm)
            {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_SHA1_RSA_PKCS;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_SHA224_RSA_PKCS;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_SHA256_RSA_PKCS;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_SHA384_RSA_PKCS;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_SHA512_RSA_PKCS;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + hashAlgorithm + "with" + encryptionAlgorithm);
            }
            break;
        default:
            throw new InvalidAlgorithmParameterException("Not supported: " + hashAlgorithm + "with" + encryptionAlgorithm);

        }

        Mechanism signatureMechanism = Mechanism.get(mechanismId);
        try {
            session.signInit(signatureMechanism, privateKey);
            return session.sign(message);
        } catch (TokenException e) {
            throw new GeneralSecurityException(e);
        } 
    }
}
