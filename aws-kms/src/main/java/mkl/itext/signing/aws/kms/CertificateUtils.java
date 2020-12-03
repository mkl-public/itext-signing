package mkl.itext.signing.aws.kms;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import com.itextpdf.io.source.ByteArrayOutputStream;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * @author mkl
 *
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

    static class AwsKmsContentSigner implements ContentSigner {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final String keyId;
        final SigningAlgorithmSpec signingAlgorithmSpec;
        final String signatureAlgorithm;

        public AwsKmsContentSigner(String keyId, SigningAlgorithmSpec signingAlgorithmSpec) {
            this.keyId = keyId;
            this.signingAlgorithmSpec = signingAlgorithmSpec;
            switch(signingAlgorithmSpec) {
            case ECDSA_SHA_256:
                this.signatureAlgorithm = "SHA256withECDSA";
                break;
            case ECDSA_SHA_384:
                this.signatureAlgorithm = "SHA384withECDSA";
                break;
            case ECDSA_SHA_512:
                this.signatureAlgorithm = "SHA512withECDSA";
                break;
            case RSASSA_PKCS1_V1_5_SHA_256:
                this.signatureAlgorithm = "SHA256withRSA";
                break;
            case RSASSA_PKCS1_V1_5_SHA_384:
                this.signatureAlgorithm = "SHA384withRSA";
                break;
            case RSASSA_PKCS1_V1_5_SHA_512:
                this.signatureAlgorithm = "SHA512withRSA";
                break;
            case RSASSA_PSS_SHA_256:
                this.signatureAlgorithm = "SHA256withRSAandMGF1";
                break;
            case RSASSA_PSS_SHA_384:
                this.signatureAlgorithm = "SHA384withRSAandMGF1";
                break;
            case RSASSA_PSS_SHA_512:
                this.signatureAlgorithm = "SHA512withRSAandMGF1";
                break;
            default:
                throw new IllegalArgumentException("Unknown signature algorithm " + signingAlgorithmSpec);
            }
        }

        @Override
        public byte[] getSignature() {
            try (   KmsClient kmsClient = KmsClient.create() ) {
                SignRequest signRequest = SignRequest.builder()
                        .signingAlgorithm(signingAlgorithmSpec)
                        .keyId(keyId)
                        .messageType(MessageType.RAW)
                        .message(SdkBytes.fromByteArray(outputStream.toByteArray()))
                        .build();
                SignResponse signResponse = kmsClient.sign(signRequest);
                SdkBytes signatureSdkBytes = signResponse.signature();
                return signatureSdkBytes.asByteArray();
            }
        }

        @Override
        public OutputStream getOutputStream() {
            return outputStream;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
        }
    }
}
