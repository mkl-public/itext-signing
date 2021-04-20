package mkl.itext.signing.pkcs11;

import static iaik.pkcs.pkcs11.Module.SlotRequirement.ALL_SLOTS;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This {@link IExternalSignature} implementation is based on the
 * <a href="https://jce.iaik.tugraz.at/products/core-crypto-toolkits/pkcs11-wrapper/">
 * IAIK PKCS#11 Wrapper</a>
 * 
 * @author mkl
 */
public class Pkcs11WrapperSignature implements IExternalSignature, AutoCloseable {
    iaik.pkcs.pkcs11.Module pkcs11Module = null;;
    Slot slot = null;
    Session session = null;
    PrivateKey privateKey = null;

    String alias;
    X509Certificate[] chain;
    String encryptionAlgorithm;
    String hashAlgorithm;

    public Pkcs11WrapperSignature(String libraryPath, long slotId) throws IOException, TokenException {
        pkcs11Module = iaik.pkcs.pkcs11.Module.getInstance("c:/Program Files (x86)/Personal/bin64/personal64.dll");
        try {
            pkcs11Module.initialize(null);

            Slot[] slots = pkcs11Module.getSlotList(ALL_SLOTS);
            
            for (Slot oneSlot : slots) {
                if (oneSlot.getSlotID() == 1) {
                    slot = oneSlot;
                }
            }
        } catch (TokenException e) {
            try {
                close();
            } catch (Exception e2) {
                e.addSuppressed(e2);
            }
            throw e;
        } 
    }

    public Pkcs11WrapperSignature select(String alias, String certLabel, char[] pin) throws TokenException, CertificateException {
        closeSession();
        Token token = slot.getToken();
        session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
        session.login(Session.UserType.USER, pin); 

        boolean found = false;

        PrivateKey searchTemplate = new PrivateKey();
        searchTemplate.getSign().setBooleanValue(Boolean.TRUE);

        session.findObjectsInit(searchTemplate);
        List<PrivateKey> privateKeys = new ArrayList<>();
        try {
            Object[] matchingKeys;
            while ((matchingKeys = session.findObjects(1)).length > 0) {
                PrivateKey privateKey = (PrivateKey) matchingKeys[0];
                if (alias != null && alias.length() > 0) {
                    if (privateKey.getLabel().isPresent()) {
                        if (!Arrays.equals(privateKey.getLabel().getCharArrayValue(), alias.toCharArray()))
                            continue;
                    } else if(privateKey.getId().isPresent()) {
                        if (!new BigInteger(privateKey.getId().getByteArrayValue()).toString().equals(alias))
                            continue;
                    } else {
                        // nothing to compare the alias to; assuming it matches
                    }
                }
                privateKeys.add(privateKey);
            }
        } finally {
            session.findObjectsFinal();
        }

        for (PrivateKey privateKey : privateKeys) {
            String encryptionAlgorithm;
            Long type = privateKey.getKeyType().getLongValue();
            if (Key.KeyType.RSA.equals(type)) {
                encryptionAlgorithm = "RSA";
            } else if (Key.KeyType.DSA.equals(type)) {
                encryptionAlgorithm = "DSA";
            } else if (Key.KeyType.ECDSA.equals(type)) {
                encryptionAlgorithm = "ECDSA";
            } else {
                continue;
            }

            String thisAlias;
            if (privateKey.getLabel().isPresent())
                thisAlias = new String(privateKey.getLabel().getCharArrayValue());
            else if (privateKey.getId().isPresent())
                thisAlias = new BigInteger(privateKey.getId().getByteArrayValue()).toString();
            else
                thisAlias = null;
            if (alias != null && !alias.equals(thisAlias))
                continue;

            X509PublicKeyCertificate signatureCertificate = null;
            X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
            if (certLabel == null && thisAlias != null && thisAlias.length() > 0)
                certLabel = thisAlias;
            if (certLabel != null)
                certificateTemplate.getLabel().setCharArrayValue(certLabel.toCharArray());
            session.findObjectsInit(certificateTemplate);
            try {
                Object[] correspondingCertificates = session.findObjects(2);
                if (correspondingCertificates.length != 1)
                    continue;
                signatureCertificate = (X509PublicKeyCertificate) correspondingCertificates[0];
            } finally {
                session.findObjectsFinal();
            }

            List<X509Certificate> certificates = new ArrayList<>();
            certificates.add(new iaik.x509.X509Certificate(signatureCertificate.getValue().getByteArrayValue()));

            certificateTemplate = new X509PublicKeyCertificate();
            session.findObjectsInit(certificateTemplate);
            try {
                Object[] correspondingCertificates;
                while ((correspondingCertificates = session.findObjects(1)).length > 0) {
                    X509PublicKeyCertificate certObject = (X509PublicKeyCertificate) correspondingCertificates[0];
                    if (certObject.getObjectHandle() != signatureCertificate.getObjectHandle()) {
                        certificates.add(new iaik.x509.X509Certificate(certObject.getValue().getByteArrayValue()));
                    }
                }
            } finally {
                session.findObjectsFinal();
            }

            found = true;
            this.alias = thisAlias;
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.privateKey = privateKey;
            this.chain = certificates.toArray(i -> new X509Certificate[i]);
            break;
        }

        if (!found)
        {
            this.alias = null;
            this.encryptionAlgorithm = null;
            this.privateKey = null;
            this.chain = null;
        }

        return this;
    }

    @Override
    public void close() throws TokenException {
        closeSession();
        slot = null;
        pkcs11Module.finalize(null);
    }

    private void closeSession() throws TokenException {
        if (session != null) {
            try {
                session.closeSession();
            } finally {
                session = null;
            }
        }
    }

    public X509Certificate[] getChain() {
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

    public Pkcs11WrapperSignature setHashAlgorithm(String hashAlgorithm)
    {
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
