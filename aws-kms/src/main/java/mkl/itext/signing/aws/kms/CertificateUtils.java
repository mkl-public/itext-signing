package mkl.itext.signing.aws.kms;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;

import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * @author mkl
 */
public class CertificateUtils {
 // based on https://stackoverflow.com/a/43918337/1729265
    public static Certificate generateSelfSignedCertificate(String keyId, String subjectDN) throws IOException, GeneralSecurityException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(subjectDN);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

        Date endDate = calendar.getTime();

        PublicKey publicKey = null;
        SigningAlgorithmSpec signingAlgorithmSpec = null;
        try (   KmsClient kmsClient = KmsClient.create() ) {
            GetPublicKeyResponse response = kmsClient.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(response.publicKey().asByteArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            publicKey = converter.getPublicKey(spki);
            List<SigningAlgorithmSpec> signingAlgorithms = response.signingAlgorithms();
            if (signingAlgorithms != null && !signingAlgorithms.isEmpty())
                signingAlgorithmSpec = signingAlgorithms.get(0);
        }
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, publicKey);

        ContentSigner contentSigner = new AwsKmsContentSigner(keyId, signingAlgorithmSpec);

        // Extensions --------------------------

        // Basic Constraints
        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

        // -------------------------------------

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));
    }
}
