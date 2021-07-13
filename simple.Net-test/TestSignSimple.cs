using iText.Kernel.Pdf;
using iText.Signatures;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using SystemCertificates = System.Security.Cryptography.X509Certificates;

namespace itext.signing.simple_Net
{
    class TestSignSimple
    {
        [Test]
        public void testSignSimpleRsa()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            string storePass = "test1234";
            string storeAlias = "RSAkey";

            SystemCertificates.X509Certificate2 certificate = new SystemCertificates.X509Certificate2(storePath, storePass);
            Assert.AreEqual(storeAlias.ToLower(), certificate.FriendlyName?.ToLower(), "Unexpected key alias; overhaul PKCS12 loading.");

            X509Certificate bcCertificate = new X509Certificate(X509CertificateStructure.GetInstance(certificate.RawData));
            X509Certificate[] chain = { bcCertificate };

            X509Certificate2Signature signature = new X509Certificate2Signature(certificate, "SHA384");

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-RSA-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());
                ITSAClient tsaClient = null;

                pdfSigner.SignDetached(signature, chain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CMS);
            }
        }
    }
}
