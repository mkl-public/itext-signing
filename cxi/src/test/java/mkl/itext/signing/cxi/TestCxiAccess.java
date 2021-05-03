package mkl.itext.signing.cxi;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import CryptoServerAPI.CryptoServerException;
import CryptoServerAPI.CryptoServerUtil;
import CryptoServerCXI.CryptoServerCXI;
import CryptoServerCXI.CryptoServerCXI.Key;
import CryptoServerCXI.CryptoServerCXI.KeyAttributes;

class TestCxiAccess {

    @Test
    void testUseRsaViaCxi() throws IOException, CryptoServerException, GeneralSecurityException {
        String device = "3001@127.0.0.1";

        CryptoServerCXI cxi = null;
        String group = "test";

        try {
            // create instance of CryptoServerCXI (opens connection to CryptoServer)
            cxi = new CryptoServerCXI(device, 3000);
            cxi.setTimeout(60000);

            System.out.println("device: " + cxi.getDevice());

            // logon
            cxi.logonPassword("CXI_USER", "utimaco");

            // generate RSA key
            System.out.println("generate RSA key...");
            CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
            attr.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
            attr.setSize(2048);
            attr.setName("RSA_DEMO_KEY");
            attr.setGroup(group);

            CryptoServerCXI.Key rsaKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);

            // export public RSA key part
            System.out.println("export public part of RSA key...");
            CryptoServerCXI.KeyAttAndComp kb = cxi.exportClearKey(rsaKey, CryptoServerCXI.KEY_TYPE_PUBLIC);
            byte[] modulus = kb.keyComponents.getItem(CryptoServerCXI.KeyComponents.TYPE_MOD);
            CryptoServerUtil.xtrace("modulus", modulus);
            byte[] pexp = kb.keyComponents.getItem(CryptoServerCXI.KeyComponents.TYPE_PEXP);
            CryptoServerUtil.xtrace("public exponent", pexp);

            // encrypt data
            System.out.println("encrypting data...");
            int mech = CryptoServerCXI.MECH_MODE_ENCRYPT | CryptoServerCXI.MECH_PAD_PKCS1;
            byte[] data = "Yes we can!".getBytes();
            byte[] crypto = cxi.crypt(rsaKey, mech, null, data, null);

            // decrypt data
            System.out.println("decrypting data...");
            mech = CryptoServerCXI.MECH_MODE_DECRYPT | CryptoServerCXI.MECH_PAD_PKCS1;
            byte[] plain = cxi.crypt(rsaKey, mech, null, crypto, null);

            if (!Arrays.equals(plain, data))
                throw new CryptoServerException(-1, "decrypted data doesn't match originla data");

            // hash data
            System.out.println("hash data...");
            MessageDigest md = MessageDigest.getInstance("SHA-512", "SUN");
            md.update(data, 0, data.length);
            byte[] hash = md.digest();

            // RSA sign hash
            System.out.println("sign data...");
            mech = CryptoServerCXI.MECH_HASH_ALGO_SHA512 | CryptoServerCXI.MECH_PAD_PKCS1;
            byte[] sign = cxi.sign(rsaKey, mech, hash);
            CryptoServerUtil.xtrace("signature", sign);

            // RSA verify signature
            System.out.println("verify signature...");
            boolean result = cxi.verify(rsaKey, mech, hash, sign);

            if (result != true)
                throw new CryptoServerException(-1, "signature verification failed");

            // manipulate signature
            System.out.println("verify manipulated signature...");
            sign[5] += 1;
            result = cxi.verify(rsaKey, mech, hash, sign);

            if (result == true)
                throw new CryptoServerException(-1, "verification of manipulated signature succeded (?)");

            listKeys(cxi, group);

        } finally {
            System.out.println("closing connection");
            if (cxi != null) {
                cxi.logoff();
                cxi.close();
            }
        }

        System.out.println("Done");
    }

    @Test
    void testAccessKeyAndCertificate() throws IOException, CryptoServerException, GeneralSecurityException {
        String device = "3001@127.0.0.1";
        String user = "USR_0000";
        String pin = "5678";
        String group = "SLOT_0000";

        CryptoServerCXI cxi = null;

        try {
            // create instance of CryptoServerCXI (opens connection to CryptoServer)
            cxi = new CryptoServerCXI(device, 3000);
            cxi.setTimeout(60000);

            System.out.println("device: " + cxi.getDevice());

            // logon
            cxi.logonPassword(user, pin);

            listKeys(cxi, group);



/*
            
            // generate RSA key
            System.out.println("generate RSA key...");
            CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
            attr.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
            attr.setSize(2048);
            attr.setName("RSA_DEMO_KEY");
            attr.setGroup(group);

            CryptoServerCXI.Key rsaKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);

            // export public RSA key part
            System.out.println("export public part of RSA key...");
            CryptoServerCXI.KeyAttAndComp kb = cxi.exportClearKey(rsaKey, CryptoServerCXI.KEY_TYPE_PUBLIC);
            byte[] modulus = kb.keyComponents.getItem(CryptoServerCXI.KeyComponents.TYPE_MOD);
            CryptoServerUtil.xtrace("modulus", modulus);
            byte[] pexp = kb.keyComponents.getItem(CryptoServerCXI.KeyComponents.TYPE_PEXP);
            CryptoServerUtil.xtrace("public exponent", pexp);

            // encrypt data
            System.out.println("encrypting data...");
            int mech = CryptoServerCXI.MECH_MODE_ENCRYPT | CryptoServerCXI.MECH_PAD_PKCS1;
            byte[] data = "Yes we can!".getBytes();
            byte[] crypto = cxi.crypt(rsaKey, mech, null, data, null);

            // decrypt data
            System.out.println("decrypting data...");
            mech = CryptoServerCXI.MECH_MODE_DECRYPT | CryptoServerCXI.MECH_PAD_PKCS1;
            byte[] plain = cxi.crypt(rsaKey, mech, null, crypto, null);

            if (!Arrays.equals(plain, data))
                throw new CryptoServerException(-1, "decrypted data doesn't match originla data");

            // hash data
            System.out.println("hash data...");
            MessageDigest md = MessageDigest.getInstance("SHA-512", "SUN");
            md.update(data, 0, data.length);
            byte[] hash = md.digest();

            // RSA sign hash
            System.out.println("sign data...");
            mech = CryptoServerCXI.MECH_HASH_ALGO_SHA512 | CryptoServerCXI.MECH_PAD_PKCS1;
            byte[] sign = cxi.sign(rsaKey, mech, hash);
            CryptoServerUtil.xtrace("signature", sign);

            // RSA verify signature
            System.out.println("verify signature...");
            boolean result = cxi.verify(rsaKey, mech, hash, sign);

            if (result != true)
                throw new CryptoServerException(-1, "signature verification failed");

            // manipulate signature
            System.out.println("verify manipulated signature...");
            sign[5] += 1;
            result = cxi.verify(rsaKey, mech, hash, sign);

            if (result == true)
                throw new CryptoServerException(-1, "verification of manipulated signature succeded (?)");
*/
        } finally {
            System.out.println("closing connection");
            if (cxi != null) {
                cxi.logoff();
                cxi.close();
            }
        }

        System.out.println("Done");
    }

    void listKeys(CryptoServerCXI cxi, String group) throws CryptoServerException, IOException, NoSuchAlgorithmException {
        KeyAttributes attributes = new KeyAttributes();
        attributes.setGroup(group);
        KeyAttributes[] keyAttributes = group != null ? cxi.listKeys(attributes) : cxi.listKeys();
        if (keyAttributes == null) {
            System.out.println("Keys: null");
        } else {
            System.out.printf("Keys: %d\n", keyAttributes.length);
            for (KeyAttributes theseAttributes : keyAttributes) {
                Key key = cxi.findKey(theseAttributes);
                if (key != null) {
                    attributes = cxi.getKeyAttributes(key, true);
                    System.out.println("* All attributes via key:");
                } else {
                    attributes = theseAttributes;
                    System.out.println("* Limited attributes:");
                }
                    
                System.out.printf("  Algorithm: %s\n", attributes.getAlgo());
                if (attributes.getCertificate() != null)
                    System.out.printf("  Certificate: %s\n", Hex.toHexString(attributes.getCertificate()));
                if (attributes.getCurve() != null)
                    System.out.printf("  Curve: %s\n", Hex.toHexString(attributes.getCurve()));
                if (attributes.getCurve() != null && attributes.getCurveEncoded() != null)
                    System.out.printf("  Curve encoded: %s\n", Hex.toHexString(attributes.getCurveEncoded()));
                if (attributes.getDSAPub() != null)
                    System.out.printf("  DSA public: %s\n", Hex.toHexString(attributes.getDSAPub()));
                if (attributes.getECPub() != null)
                    System.out.printf("  EC public: %s\n", Hex.toHexString(attributes.getECPub()));
                if (attributes.getExpirationDate() != null)
                    System.out.printf("  Expiration date: %s\n", attributes.getExpirationDate());
                if (attributes.getExponent() != null)
                    System.out.printf("  Exponent: %s\n", Hex.toHexString(attributes.getExponent()));
                System.out.printf("  Export: %s\n", attributes.getExport());
                System.out.printf("  FIPS usage: %s\n", attributes.getFIPSUsage());
                if (attributes.getGenerationDate() != null)
                    System.out.printf("  Generation date: %s\n", attributes.getGenerationDate());
                if (attributes.getGroup() != null)
                    System.out.printf("  Group: %s\n", attributes.getGroup());
                if (attributes.getLabel() != null)
                    System.out.printf("  Label: %s\n", attributes.getLabel());
                if (attributes.getMechs() != null)
                    System.out.printf("  Mechanisms: %s\n", Hex.toHexString(attributes.getMechs()));
                if (attributes.getModulus() != null)
                    System.out.printf("  Modulus : %s\n", Hex.toHexString(attributes.getModulus()));
                if (attributes.getName() != null)
                    System.out.printf("  Name: %s\n", attributes.getName());
                if (attributes.getParamG() != null)
                    System.out.printf("  Param G: %s\n", Hex.toHexString(attributes.getParamG()));
                if (attributes.getParamP() != null)
                    System.out.printf("  Param P: %s\n", Hex.toHexString(attributes.getParamP()));
                if (attributes.getParamQ() != null)
                    System.out.printf("  Param Q: %s\n", Hex.toHexString(attributes.getParamQ()));
                System.out.printf("  Size: %s\n", attributes.getSize());
                System.out.printf("  Specifier: %s\n", attributes.getSpecifier());
                System.out.printf("  Type: %s\n", attributes.getType());
                System.out.printf("  Usage: %s\n", attributes.getUsage());

                if (key.getUName() != null) {
                    System.out.printf("  UName: %s\n", Hex.toHexString(key.getUName()));
                }

                try {
                    byte[] export = cxi.exportKey(key, CryptoServerCXI.KEY_TYPE_PUBLIC, null);
                    if (export != null) {
                        System.out.printf("  Export: %s\n", Hex.toHexString(export));
                    }
                } catch(Exception e) {
                    
                }

                System.out.println("  ---");
                
            }
        }

    }
}
