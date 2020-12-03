package mkl.itext.signing.aws.kms;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.itextpdf.io.source.ByteArrayOutputStream;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.AliasListEntry;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.VerifyRequest;
import software.amazon.awssdk.services.kms.model.VerifyResponse;

/**
 * @author mkl
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SimpleAwsConnectivity {
    final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    @BeforeAll
    static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    @Test
    @Order(0)
    void testListRegions() {
        DynamoDbClient.serviceMetadata().regions().forEach(System.out::println);
    }

    @Test
    @Order(1)
    void testListAliases() {
        try (   KmsClient kmsClient = KmsClient.create() ) {
            List<AliasListEntry> aliases = kmsClient.listAliases().aliases();
            aliases.forEach(System.out::println);
            assertTrue(() -> aliases.stream().anyMatch(alias -> alias.aliasName().equals("alias/SigningExamples-ECC_NIST_P256")));
        }
    }

    @Test
    @Order(2)
    void testSignSimple() {
        try (   KmsClient kmsClient = KmsClient.create() ) {
            SignRequest signRequest = SignRequest.builder()
                    .signingAlgorithm("ECDSA_SHA_256")
                    .keyId("alias/SigningExamples-ECC_NIST_P256")
                    .messageType(MessageType.RAW)
                    .message(SdkBytes.fromUtf8String("Test"))
                    .build();
            SignResponse signResponse = kmsClient.sign(signRequest);
            assertNotNull(signResponse, "SignResponse");
            SdkBytes signatureSdkBytes = signResponse.signature();
            assertNotNull(signatureSdkBytes, "signature SdkBytes");
            byte[] signatureBytes = signatureSdkBytes.asByteArray();
            assertNotNull(signatureBytes, "signature Bytes");

            VerifyRequest verifyRequest = VerifyRequest.builder()
                    .signingAlgorithm("ECDSA_SHA_256")
                    .keyId("alias/SigningExamples-ECC_NIST_P256")
                    .messageType(MessageType.RAW)
                    .message(SdkBytes.fromUtf8String("Test"))
                    .signature(SdkBytes.fromByteArray(signatureBytes))
                    .build();
            VerifyResponse verifyResponse = kmsClient.verify(verifyRequest);
            assertNotNull(verifyResponse, "VerifyResponse");
            Boolean signatureValid = verifyResponse.signatureValid();
            assertNotNull(signatureValid, "signatureValid Boolean");
            assertTrue(signatureValid, "signatureValid");
        }
    }

    // see https://stackoverflow.com/a/34496509/1729265
    @Test
    @Order(3)
    void testPublicKey() throws PEMException {
        try (   KmsClient kmsClient = KmsClient.create() ) {
            GetPublicKeyRequest getPublicKeyRequest = GetPublicKeyRequest.builder()
                    .keyId("alias/SigningExamples-ECC_NIST_P256")
                    .build();
            GetPublicKeyResponse getPublicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest);
            assertNotNull(getPublicKeyResponse, "Response");
            SdkBytes spkiSdkBytes = getPublicKeyResponse.publicKey();
            assertNotNull(spkiSdkBytes, "public key info SdkBytes");
            byte[] spkiBytes = spkiSdkBytes.asByteArray();
            assertNotNull(spkiBytes, "public key info Bytes");
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiBytes);
            assertNotNull(spki, "public key info");
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PublicKey publicKey = converter.getPublicKey(spki);
            assertNotNull(publicKey, "public key");
            List<SigningAlgorithmSpec> signingAlgorithms = getPublicKeyResponse.signingAlgorithms();
            assertNotNull(signingAlgorithms, "signing algorithms");
            assertFalse(signingAlgorithms.isEmpty(), "signing algorithms empty");
            assertEquals(Collections.singletonList(SigningAlgorithmSpec.ECDSA_SHA_256), signingAlgorithms);
        }
    }

    @Test
    @Order(4)
    void testGenerateCertificate() throws IOException, OperatorCreationException, CertificateException {
        X509Certificate x509Certificate = selfSign("alias/SigningExamples-ECC_NIST_P256", "CN=mkl aws test,OU=testing,O=mkl", "SHA256withECDSA");
        Files.write(new File(RESULT_FOLDER, "certificate.crt").toPath(), x509Certificate.getEncoded());
    }

    // based on https://stackoverflow.com/a/43918337/1729265
    public static X509Certificate selfSign(String keyId, String subjectDN, String signatureAlgorithm) throws OperatorCreationException, CertificateException, IOException
    {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(subjectDN);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

        Date endDate = calendar.getTime();

        ContentSigner contentSigner = new AwsKmsContentSigner(keyId, signatureAlgorithm);

        PublicKey publicKey = null;
        try (   KmsClient kmsClient = KmsClient.create() ) {
            GetPublicKeyResponse response = kmsClient.getPublicKey(GetPublicKeyRequest.builder().keyId(keyId).build());
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(response.publicKey().asByteArray());
            assertNotNull(spki, "public key info");
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            publicKey = converter.getPublicKey(spki);
        }
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, publicKey);

        // Extensions --------------------------

        // Basic Constraints
        BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

        // -------------------------------------

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
    }

    @Test
    @Order(5)
    void testGenerateSignatureContainer() throws IOException, OperatorCreationException, CertificateEncodingException, CMSException {
        CMSTypedData msg = new CMSProcessableByteArray("Test".getBytes());

        X509CertificateHolder signCert = new X509CertificateHolder(
                Files.readAllBytes(new File(RESULT_FOLDER, "certificate.crt").toPath()));

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new AwsKmsContentSigner("alias/SigningExamples-ECC_NIST_P256", "SHA256withECDSA");

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(sha1Signer, signCert));

        gen.addCertificates(new JcaCertStore(Collections.singleton(signCert)));

        CMSSignedData sigData = gen.generate(msg, false);

        Files.write(new File(RESULT_FOLDER, "exampleSignature.p7s").toPath(), sigData.getEncoded());
    }

    static class AwsKmsContentSigner implements ContentSigner {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final String keyId;
        final String signatureAlgorithm;

        public AwsKmsContentSigner(String keyId, String signatureAlgorithm) {
            this.keyId = keyId;
            this.signatureAlgorithm = signatureAlgorithm;
        }

        @Override
        public byte[] getSignature() {
            try (   KmsClient kmsClient = KmsClient.create() ) {
                SignRequest signRequest = SignRequest.builder()
                        .signingAlgorithm("ECDSA_SHA_256")
                        .keyId(keyId)
                        .messageType(MessageType.RAW)
                        .message(SdkBytes.fromByteArray(outputStream.toByteArray()))
                        .build();
                SignResponse signResponse = kmsClient.sign(signRequest);
                assertNotNull(signResponse, "SignResponse");
                SdkBytes signatureSdkBytes = signResponse.signature();
                assertNotNull(signatureSdkBytes, "signature SdkBytes");
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
