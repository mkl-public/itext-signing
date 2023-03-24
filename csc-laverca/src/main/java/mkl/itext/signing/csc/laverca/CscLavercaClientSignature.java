package mkl.itext.signing.csc.laverca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.mime.encoding.Base64InputStream;

import com.itextpdf.io.codec.Base64;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.EncryptionAlgorithms;
import com.itextpdf.signatures.IExternalSignature;

import fi.methics.laverca.csc.CscClient;
import fi.methics.laverca.csc.json.credentials.CscCredentialsInfoResp;
import fi.methics.laverca.csc.json.signatures.CscSignHashResp;
import mkl.itext.signing.csc.laverca.vx.CscClientVx;

/**
 * <p>
 * This {@link IExternalSignature} implementation allows signing a PDF
 * with iText 7 using the CSC API via the Laverca CSC client.
 * </p>
 * 
 * @author mkl
 */
public class CscLavercaClientSignature implements IExternalSignature {

    public CscLavercaClientSignature(String baseUrl, String version, String username, String password,
            Function<CscClientVx, String> credentialSelector, Function<List<String>, String> algorithmSelector) {
        client = new CscClientVx.Builder().withBaseUrl(baseUrl).withVersion(version)
                .withTrustInsecureConnections(true)
                .withUsername(username)
                .withPassword(password)
                .build();
        client.authLogin();

        credentialId = credentialSelector.apply(client);
        credentialInfo = client.getCredentialInfo(credentialId);
        algorithmOid = algorithmSelector.apply(credentialInfo.key.algo);

        if (!credentialInfo.isScal2()) {
            client.authorize(credentialId);
            // In case of SCAL2 authorization occurs in each
            // client.signHash call for the given hash value.
        }
    }

    public Certificate[] getChain() {
        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X509");
            List<Certificate> certificates = new ArrayList<>();
            for (String cert : credentialInfo.cert.certificates) {
                certificates.addAll(factory.generateCertificates(new Base64InputStream(new ByteArrayInputStream(cert.getBytes()))));
            }
            return certificates.toArray(i -> new Certificate[i]);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getHashAlgorithm() {
        return DigestAlgorithms.getDigest(algorithmOid);
    }

    @Override
    public String getEncryptionAlgorithm() {
        return EncryptionAlgorithms.getAlgorithm(algorithmOid);
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        try {
            byte[] digest = DigestAlgorithms.digest(new ByteArrayInputStream(message), getHashAlgorithm(), null);
            String base64Digest = Base64.encodeBytes(digest);
            CscSignHashResp signhash = client.signHash(credentialId, Collections.singletonList(base64Digest), algorithmOid);
            return Base64.decode(signhash.signatures.get(0));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    final CscClientVx client;
    final String credentialId;
    final CscCredentialsInfoResp credentialInfo;
    final String algorithmOid;
}
