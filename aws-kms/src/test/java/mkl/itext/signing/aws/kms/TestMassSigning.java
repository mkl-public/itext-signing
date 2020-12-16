package mkl.itext.signing.aws.kms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.itextpdf.io.util.StreamUtil;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSigner.CryptoStandard;

/**
 * @author mkl
 */
class TestMassSigning {
    final static File RESULT_FOLDER = new File("target/test-outputs", "signature");

    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        RESULT_FOLDER.mkdirs();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
    }

    @BeforeEach
    void sleep() throws InterruptedException {
        Thread.sleep(1000);
    }

    @Test
    void testNaiveSignSimpleRsa10Times() throws IOException, GeneralSecurityException {
        final byte[] sourcePdf;
        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf")   ) {
            sourcePdf = StreamUtil.inputStreamToArray(resource);
        }

        String keyId = "alias/SigningExamples-RSA_2048";
        Certificate certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS PDF Signing Test,OU=mkl tests,O=mkl");

        int count = 10;
        long totalTime = 0;
        System.out.printf("Naively signing with RSA %d times\n", count);
        for (int i = 0; i < count; i++) {
            //System.out.printf("run %3d - ", i);
            long time = timer(() -> {
                AwsKmsSignature signature = new AwsKmsSignature(keyId);
                try (   PdfReader pdfReader = new PdfReader(new ByteArrayInputStream(sourcePdf));
                        OutputStream result = new ByteArrayOutputStream()   ) {
                    PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

                    IExternalDigest externalDigest = new BouncyCastleDigest();
                    pdfSigner.signDetached(externalDigest , signature, new Certificate[] {certificate}, null, null, null, 0, CryptoStandard.CMS);
                }
            });
            totalTime += time;
            //System.out.printf("%d ms\n", time);
        }
        System.out.printf("total   - %d ms\n", totalTime);
    }

    @Test
    void testSignSimpleRsa10Times() throws IOException, GeneralSecurityException {
        final byte[] sourcePdf;
        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf")   ) {
            sourcePdf = StreamUtil.inputStreamToArray(resource);
        }

        String keyId = "alias/SigningExamples-RSA_2048";
        Certificate certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS PDF Signing Test,OU=mkl tests,O=mkl");
        AwsKmsSignature signature = new AwsKmsSignature(keyId);

        int count = 10;
        long totalTime = 0;
        System.out.printf("Signing with RSA %d times\n", count);
        for (int i = 0; i < count; i++) {
            //System.out.printf("run %3d - ", i);
            long time = timer(() -> {
                try (   PdfReader pdfReader = new PdfReader(new ByteArrayInputStream(sourcePdf));
                        OutputStream result = new ByteArrayOutputStream()   ) {
                    PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

                    IExternalDigest externalDigest = new BouncyCastleDigest();
                    pdfSigner.signDetached(externalDigest , signature, new Certificate[] {certificate}, null, null, null, 0, CryptoStandard.CMS);
                }
            });
            totalTime += time;
            //System.out.printf("%d ms\n", time);
        }
        System.out.printf("total   - %d ms\n", totalTime);
    }

    @Test
    void testSignSimpleRsa10TimesInParallel() throws IOException, GeneralSecurityException {
        final byte[] sourcePdf;
        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf")   ) {
            sourcePdf = StreamUtil.inputStreamToArray(resource);
        }

        String keyId = "alias/SigningExamples-RSA_2048";
        Certificate certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS PDF Signing Test,OU=mkl tests,O=mkl");
        AwsKmsSignature signature = new AwsKmsSignature(keyId);

        int count = 10;
        long totalTime = 0;
        System.out.printf("Signing with RSA %d times in parallel\n", count);
        totalTime = timer(() -> {
            Supplier<Long> signTest = () -> {
                return timer (() -> {
                    try (   PdfReader pdfReader = new PdfReader(new ByteArrayInputStream(sourcePdf));
                            OutputStream result = new ByteArrayOutputStream()   ) {
                        PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

                        IExternalDigest externalDigest = new BouncyCastleDigest();
                        pdfSigner.signDetached(externalDigest , signature, new Certificate[] {certificate}, null, null, null, 0, CryptoStandard.CMS);
                    }
                });
            };
            List<CompletableFuture<Long>> completableFutures = new ArrayList<>();
            for (int i = 0; i < count; i++)
                completableFutures.add(CompletableFuture.supplyAsync(signTest));
            CompletableFuture<Void> combined = CompletableFuture.allOf(completableFutures.toArray(new CompletableFuture[count]));
            combined.get();
            //for (int i = 0; i < count; i++) {
            //    System.out.printf("run %3d - %d ms\n", i, completableFutures.get(i).join());
            //}
        });
        System.out.printf("total   - %d ms\n", totalTime);
    }

    @Test
    void testSignSimpleRsa200TimesInParallel() throws IOException, GeneralSecurityException {
        final byte[] sourcePdf;
        try (   InputStream resource = getClass().getResourceAsStream("/circles.pdf")   ) {
            sourcePdf = StreamUtil.inputStreamToArray(resource);
        }

        String keyId = "alias/SigningExamples-RSA_2048";
        Certificate certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS PDF Signing Test,OU=mkl tests,O=mkl");
        AwsKmsSignature signature = new AwsKmsSignature(keyId);

        int count = 200;
        long totalTime = 0;
        System.out.printf("Signing with RSA %d times in parallel\n", count);
        totalTime = timer(() -> {
            Supplier<Long> signTest = () -> {
                return timer (() -> {
                    try (   PdfReader pdfReader = new PdfReader(new ByteArrayInputStream(sourcePdf));
                            OutputStream result = new ByteArrayOutputStream()   ) {
                        PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().useAppendMode());

                        IExternalDigest externalDigest = new BouncyCastleDigest();
                        pdfSigner.signDetached(externalDigest , signature, new Certificate[] {certificate}, null, null, null, 0, CryptoStandard.CMS);
                    }
                });
            };
            List<CompletableFuture<Long>> completableFutures = new ArrayList<>();
            for (int i = 0; i < count; i++)
                completableFutures.add(CompletableFuture.supplyAsync(signTest));
            CompletableFuture<Void> combined = CompletableFuture.allOf(completableFutures.toArray(new CompletableFuture[count]));
            combined.get();
            //for (int i = 0; i < count; i++) {
            //    System.out.printf("run %3d - %d ms\n", i, completableFutures.get(i).join());
            //}
        });
        System.out.printf("total   - %d ms\n", totalTime);
    }

    long timer(TestWithException test) {
        long start = System.currentTimeMillis();
        try {
            test.run();
        } catch (Exception e) {
            System.err.printf("\n!!! Exception in timed test: %s\n", e.getMessage());
        }
        long end = System.currentTimeMillis();
        return end - start;
    }

    @FunctionalInterface
    interface TestWithException {
        void run() throws Exception;
    }
}
