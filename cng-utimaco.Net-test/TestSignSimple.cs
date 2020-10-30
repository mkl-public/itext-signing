﻿using iText.Kernel.Pdf;
using iText.Signatures;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static iText.Signatures.PdfSigner;

namespace itext.signing.cng_utimaco_Net
{
    class TestSignSimple
    {
        [SetUp]
        public void Init()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser, OpenFlags.ReadWrite))
            {
                X509Certificate2Collection certificates = store.Certificates;
                X509Certificate2Collection signingcertificates = certificates.Find(X509FindType.FindBySubjectName, "Utimaco CNG Signing Test", false);
                if (signingcertificates.Count == 0)
                {
                    CngProvider provider = new CngProvider("Utimaco CryptoServer Key Storage Provider");
                    CngKey key = CngKey.Open("DEMOecdsa", provider);
                    ECDsaCng ecdsaKey = new ECDsaCng(key);
                    CertificateRequest request = new CertificateRequest("CN = Utimaco CNG Signing Test", ecdsaKey, HashAlgorithmName.SHA512);
                    X509Certificate2 certificate = request.CreateSelfSigned(System.DateTimeOffset.Now, System.DateTimeOffset.Now.AddYears(2));
                    certificate.FriendlyName = "Utimaco CNG Signing Test";
                    System.Console.WriteLine("Utimaco CNG Signing Test Certificate generated:\n****\n{0}\n****", certificate);
                    store.Add(certificate);
                }
            }
        }

        [Test]
        public void TestCngSignSimple()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";

            X509Certificate2 certificate;
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser, OpenFlags.ReadOnly))
            {
                X509Certificate2Collection certificates = store.Certificates;
                X509Certificate2Collection signingcertificates = certificates.Find(X509FindType.FindBySubjectName, "Utimaco CNG Signing Test", false);
                certificate = signingcertificates[0];
            }

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-pkcs11-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());
                X509Certificate2ECDsaSignature signature = new X509Certificate2ECDsaSignature(certificate);

                pdfSigner.SignDetached(signature, signature.GetChain(), null, null, null, 0, CryptoStandard.CMS);
            }
            
        }

    }

    class X509Certificate2ECDsaSignature : IExternalSignature
    {
        public X509Certificate2ECDsaSignature(X509Certificate2 certificate)
        {
            this.certificate = certificate;
        }

        public Org.BouncyCastle.X509.X509Certificate[] GetChain()
        {
            var bcCertificate = new Org.BouncyCastle.X509.X509Certificate(Org.BouncyCastle.Asn1.X509.X509CertificateStructure.GetInstance(certificate.RawData));
            return new Org.BouncyCastle.X509.X509Certificate[] { bcCertificate };
        }

        public string GetEncryptionAlgorithm()
        {
            return "ECDSA";
        }

        public string GetHashAlgorithm()
        {
            return "SHA512";
        }

        public byte[] Sign(byte[] message)
        {
            using (ECDsa ecdsa = certificate.GetECDsaPrivateKey())
            {
                return ecdsa.SignData(message, HashAlgorithmName.SHA512);
            }
        }

        X509Certificate2 certificate;
    }
}
