package mkl.itext.signing.aws.kms;

import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

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

/**
 * @author mkl
 */
public class AwsKmsContentSigner implements ContentSigner {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final String keyId;
    final SigningAlgorithmSpec signingAlgorithmSpec;
    final AlgorithmIdentifier signatureAlgorithm;

    public AwsKmsContentSigner(String keyId, SigningAlgorithmSpec signingAlgorithmSpec) {
        this.keyId = keyId;
        this.signingAlgorithmSpec = signingAlgorithmSpec;
        String signatureAlgorithmName = signingAlgorithmNameBySpec.get(signingAlgorithmSpec);
        if (signatureAlgorithmName == null)
            throw new IllegalArgumentException("Unknown signature algorithm " + signingAlgorithmSpec);
        this.signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithmName);
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
        } finally {
            outputStream.reset();
        }
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return signatureAlgorithm;
    }

    final static Map<SigningAlgorithmSpec, String> signingAlgorithmNameBySpec;

    static {
        signingAlgorithmNameBySpec = new HashMap<>();
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.ECDSA_SHA_256, "SHA256withECDSA");
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.ECDSA_SHA_384, "SHA384withECDSA");
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.ECDSA_SHA_512, "SHA512withECDSA");
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256, "SHA256withRSA");
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384, "SHA384withRSA");
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512, "SHA512withRSA");
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.RSASSA_PSS_SHA_256, "SHA256withRSAandMGF1");
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.RSASSA_PSS_SHA_384, "SHA384withRSAandMGF1");
        signingAlgorithmNameBySpec.put(SigningAlgorithmSpec.RSASSA_PSS_SHA_512, "SHA512withRSAandMGF1");
    }
}