package mkl.itext.signing.aws.kms;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import com.itextpdf.io.source.ByteArrayOutputStream;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

public class AwsKmsContentSigner implements ContentSigner {
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