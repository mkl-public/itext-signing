using iText.Kernel.Pdf;
using iText.Signatures;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using static iText.Signatures.PdfSigner;

namespace itext.signing.aws_kms_Net
{
    public class TestSignSimple
    {
        [Test]
        public void testSignSimpleRsa()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";

            string keyId = "alias/SigningExamples-RSA_2048";
            Func<System.Collections.Generic.List<string>, string> selector = list => list.Find(name => name.StartsWith("RSASSA_PKCS1_V1_5"));
            AwsKmsSignature signature = new AwsKmsSignature(keyId, selector);
            System.Security.Cryptography.X509Certificates.X509Certificate2 certificate2 = CertificateUtils.generateSelfSignedCertificate(
                keyId,
                "CN=AWS KMS PDF Signing Test RSA,OU=mkl tests,O=mkl",
                selector
            );
            X509Certificate certificate = new X509Certificate(X509CertificateStructure.GetInstance(certificate2.RawData));

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-aws-kms-signed-simple-RSA.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                pdfSigner.SignDetached(signature, new X509Certificate[] { certificate }, null, null, null, 0, CryptoStandard.CMS);
            }
        }

        [Test]
        public void testSignSimpleEcdsa()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";

            string keyId = "alias/SigningExamples-ECC_NIST_P256";
            Func<System.Collections.Generic.List<string>, string> selector = list => list.Find(name => name.StartsWith("ECDSA_SHA_256"));
            AwsKmsSignature signature = new AwsKmsSignature(keyId, selector);
            System.Security.Cryptography.X509Certificates.X509Certificate2 certificate2 = CertificateUtils.generateSelfSignedCertificate(
                keyId,
                "CN=AWS KMS PDF Signing Test ECDSA,OU=mkl tests,O=mkl",
                selector
            );
            X509Certificate certificate = new X509Certificate(X509CertificateStructure.GetInstance(certificate2.RawData));

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-aws-kms-signed-simple-ECDSA.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                pdfSigner.SignDetached(signature, new X509Certificate[] { certificate }, null, null, null, 0, CryptoStandard.CMS);
            }
        }
    }
}