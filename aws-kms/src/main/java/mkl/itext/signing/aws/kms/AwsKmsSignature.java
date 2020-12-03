package mkl.itext.signing.aws.kms;

import java.security.GeneralSecurityException;

import com.itextpdf.signatures.IExternalSignature;

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
 */
public class AwsKmsSignature implements IExternalSignature {
    public AwsKmsSignature(String keyId) {
        this.keyId = keyId;

        try (   KmsClient kmsClient = KmsClient.create() ) {
            GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder()
                    .keyId(keyId)
                    .build();
            GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);
            signingAlgorithmSpec = getPublicKeyResponse.signingAlgorithms().get(0);
            switch(signingAlgorithmSpec) {
            case ECDSA_SHA_256:
            case ECDSA_SHA_384:
            case ECDSA_SHA_512:
            case RSASSA_PKCS1_V1_5_SHA_256:
            case RSASSA_PKCS1_V1_5_SHA_384:
            case RSASSA_PKCS1_V1_5_SHA_512:
                break;
            case RSASSA_PSS_SHA_256:
            case RSASSA_PSS_SHA_384:
            case RSASSA_PSS_SHA_512:
                throw new IllegalArgumentException(String.format("Signing algorithm %s not supported directly by iText", signingAlgorithmSpec));
            default:
                throw new IllegalArgumentException(String.format("Unknown signing algorithm: %s", signingAlgorithmSpec));
            }
        }
    }

    @Override
    public String getHashAlgorithm() {
        switch(signingAlgorithmSpec) {
        case ECDSA_SHA_256:
        case RSASSA_PKCS1_V1_5_SHA_256:
            return "SHA-256";
        case ECDSA_SHA_384:
        case RSASSA_PKCS1_V1_5_SHA_384:
            return "SHA-384";
        case ECDSA_SHA_512:
        case RSASSA_PKCS1_V1_5_SHA_512:
            return "SHA-512";
        default:
            return null;
        }
    }

    @Override
    public String getEncryptionAlgorithm() {
        switch(signingAlgorithmSpec) {
        case ECDSA_SHA_256:
        case ECDSA_SHA_384:
        case ECDSA_SHA_512:
            return "ECDSA";
        case RSASSA_PKCS1_V1_5_SHA_256:
        case RSASSA_PKCS1_V1_5_SHA_384:
        case RSASSA_PKCS1_V1_5_SHA_512:
            return "RSA";
        default:
            return null;
        }
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        try (   KmsClient kmsClient = KmsClient.create() ) {
            SignRequest signRequest = SignRequest.builder()
                    .signingAlgorithm(signingAlgorithmSpec)
                    .keyId(keyId)
                    .messageType(MessageType.RAW)
                    .message(SdkBytes.fromByteArray(message))
                    .build();
            SignResponse signResponse = kmsClient.sign(signRequest);
            return signResponse.signature().asByteArray();
        }
    }

    final String keyId;
    final SigningAlgorithmSpec signingAlgorithmSpec;
}
