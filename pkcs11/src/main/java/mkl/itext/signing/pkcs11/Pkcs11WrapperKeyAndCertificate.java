package mkl.itext.signing.pkcs11;

import static iaik.pkcs.pkcs11.Module.SlotRequirement.ALL_SLOTS;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * @author mkl
 */
public class Pkcs11WrapperKeyAndCertificate implements AutoCloseable {
    protected iaik.pkcs.pkcs11.Module pkcs11Module = null;
    protected Slot slot = null;
    protected Session session = null;

    protected PrivateKey privateKey = null;
    protected Long keyType = null;
    protected String alias = null;
    protected X509Certificate[] chain = null;

    public Pkcs11WrapperKeyAndCertificate(String libraryPath, long slotId) throws IOException, TokenException {
        pkcs11Module = iaik.pkcs.pkcs11.Module.getInstance(libraryPath);
        try {
            pkcs11Module.initialize(null);

            Slot[] slots = pkcs11Module.getSlotList(ALL_SLOTS);
            
            for (Slot oneSlot : slots) {
                if (oneSlot.getSlotID() == slotId) {
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

    public Pkcs11WrapperKeyAndCertificate select(String alias, String certLabel, char[] pin) throws TokenException, CertificateException {
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
            Long type = privateKey.getKeyType().getLongValue();
            if (!isValidPrivateKeyType(type))
                continue;

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
            this.keyType = type;
            this.privateKey = privateKey;
            this.chain = certificates.toArray(i -> new X509Certificate[i]);
            break;
        }

        if (!found)
        {
            this.alias = null;
            this.keyType = null;
            this.privateKey = null;
            this.chain = null;
        }

        return this;
    }

    public X509Certificate[] getChain() {
        return chain;
    }

    static Collection<Long> SIGNATURE_KEY_TYPES = List.of(Key.KeyType.DSA, Key.KeyType.ECDSA, Key.KeyType.RSA); 
    protected boolean isValidPrivateKeyType(Long type) {
        return SIGNATURE_KEY_TYPES.contains(type);
    }

    @Override
    public void close() throws TokenException {
        closeSession();
        slot = null;
        pkcs11Module.finalize(null);
    }

    protected void closeSession() throws TokenException {
        if (session != null) {
            try {
                session.closeSession();
            } finally {
                session = null;
            }
        }
    }
}
