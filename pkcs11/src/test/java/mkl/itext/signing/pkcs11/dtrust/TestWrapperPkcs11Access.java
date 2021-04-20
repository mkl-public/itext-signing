package mkl.itext.signing.pkcs11.dtrust;

import static iaik.pkcs.pkcs11.Module.SlotRequirement.TOKEN_PRESENT;

import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This test class executes some simple tests addressing the
 * D-Trust card via the Nexus Personal PKCS#11 driver and the
 * IAIK Java PKCS#11 Wrapper to retrieve key handles and
 * certificates.
 * 
 * @author mkl
 */
class TestWrapperPkcs11Access {
    @Test
    void testAccessKeyAndCertificate() throws IOException, TokenException {
        iaik.pkcs.pkcs11.Module pkcs11Module = iaik.pkcs.pkcs11.Module.getInstance("c:/Program Files (x86)/Personal/bin64/personal64.dll");
        try {
            pkcs11Module.initialize(null); 

            Slot[] slotsWithToken = pkcs11Module.getSlotList(TOKEN_PRESENT);
            Slot slot1 = null;
            for (Slot slot : slotsWithToken) {
                if (slot.getSlotID() == 1) {
                    slot1 = slot;
                }
            }

            if (slot1 != null) {
                Token token = slot1.getToken();
                Session session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
                try {
                    session.login(Session.UserType.USER, "12345678".toCharArray()); 

                    PrivateKey searchTemplate = new PrivateKey();
                    searchTemplate.getSign().setBooleanValue(Boolean.TRUE);

                    session.findObjectsInit(searchTemplate);
                    PrivateKey signatureKey = null;
                    try {
                        Object[] matchingKeys = session.findObjects(1);
                        if ((matchingKeys).length > 0) {
                            signatureKey = (PrivateKey) matchingKeys[0];
                        }
                    } finally {
                        session.findObjectsFinal();
                    }

                    if (signatureKey != null) {
                        byte[] signature = null;
                        System.out.printf("Private key of type %d\n", signatureKey.getKeyType().getLongValue());
                        
                        if (signatureKey instanceof RSAPrivateKey) {
                            Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_SHA256_RSA_PKCS);
                            session.signInit(signatureMechanism, signatureKey); 
                            signature = session.sign("test".getBytes());
                        } else {
                            System.out.println("Private key is not a RSA key.");
                        }

                        X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
                        certificateTemplate.getId().setByteArrayValue(signatureKey.getId().getByteArrayValue()); 
                        session.findObjectsInit(certificateTemplate);
                        X509PublicKeyCertificate signatureCertificate = null;
                        try {
                            Object[] correspondingCertificates;
                            while ((correspondingCertificates = session.findObjects(1)).length > 0) {
                                X509PublicKeyCertificate certObject = (X509PublicKeyCertificate) correspondingCertificates[0];
                                char[] label = certObject.getLabel().getCharArrayValue();
                                if (label != null && Arrays.equals(label, "Signaturzertifikat".toCharArray())) {
                                    signatureCertificate = certObject;
                                    break;
                                }
                            }
                        } finally {
                            session.findObjectsFinal(); 
                        }

                        if (signatureCertificate != null) {
                            System.out.printf("Signer certificate: %s\n", signatureCertificate);
                        } else {
                            System.out.println("No signer certificate found.");
                        }
                    } else {
                        System.out.println("No private key found.");
                    }
                } finally {
                    session.closeSession();
                }
            } else {
                System.out.println("No slots found.");
            }
        } finally {
            pkcs11Module.finalize(null);
        }
    }

}
