﻿using iText.Kernel.Pdf;
using iText.Signatures;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;
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

            SystemCertificates.X509Certificate2Collection pkcs12 = new SystemCertificates.X509Certificate2Collection();
            pkcs12.Import(storePath, storePass, SystemCertificates.X509KeyStorageFlags.DefaultKeySet);
            SystemCertificates.X509Certificate2 certificate = null;
            foreach (SystemCertificates.X509Certificate2 aCertificate in pkcs12)
            {
                if (storeAlias.Equals(aCertificate.FriendlyName, StringComparison.InvariantCultureIgnoreCase))
                {
                    certificate = aCertificate;
                    break;
                }
            }
            Assert.NotNull(certificate, "Key with alias {0} not found.", storeAlias);

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

        [Test]
        public void testSignSimpleDsa()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            string storePass = "test1234";
            string storeAlias = "DSAkey";

            SystemCertificates.X509Certificate2Collection pkcs12 = new SystemCertificates.X509Certificate2Collection();
            pkcs12.Import(storePath, storePass, SystemCertificates.X509KeyStorageFlags.DefaultKeySet);
            SystemCertificates.X509Certificate2 certificate = null;
            foreach (SystemCertificates.X509Certificate2 aCertificate in pkcs12)
            {
                if (storeAlias.Equals(aCertificate.FriendlyName, StringComparison.InvariantCultureIgnoreCase))
                {
                    certificate = aCertificate;
                    break;
                }
            }
            Assert.NotNull(certificate, "Key with alias {0} not found.", storeAlias);

            X509Certificate bcCertificate = new X509Certificate(X509CertificateStructure.GetInstance(certificate.RawData));
            X509Certificate[] chain = { bcCertificate };

            X509Certificate2Signature signature = new X509Certificate2Signature(certificate, "SHA-1");

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-DSA-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());
                ITSAClient tsaClient = null;

                pdfSigner.SignDetached(signature, chain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CMS);
            }
        }

        [Test]
        public void testSignSimpleECDsa()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            string storePass = "test1234";
            string storeAlias = "ECDSAkey";

            SystemCertificates.X509Certificate2Collection pkcs12 = new SystemCertificates.X509Certificate2Collection();
            pkcs12.Import(storePath, storePass, SystemCertificates.X509KeyStorageFlags.DefaultKeySet);
            SystemCertificates.X509Certificate2 certificate = null;
            foreach (SystemCertificates.X509Certificate2 aCertificate in pkcs12)
            {
                if (storeAlias.Equals(aCertificate.FriendlyName, StringComparison.InvariantCultureIgnoreCase))
                {
                    certificate = aCertificate;
                    break;
                }
            }
            Assert.NotNull(certificate, "Key with alias {0} not found.", storeAlias);

            X509Certificate bcCertificate = new X509Certificate(X509CertificateStructure.GetInstance(certificate.RawData));
            X509Certificate[] chain = { bcCertificate };

            X509Certificate2Signature signature = new X509Certificate2Signature(certificate, "SHA512");

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-ECDSA-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());
                ITSAClient tsaClient = null;

                pdfSigner.SignDetached(signature, chain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CMS);
            }
        }

        [Test]
        public void testSignSimpleContainerRsa()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            string storePass = "test1234";
            string storeAlias = "RSAkey";

            SystemCertificates.X509Certificate2Collection pkcs12 = new SystemCertificates.X509Certificate2Collection();
            pkcs12.Import(storePath, storePass, SystemCertificates.X509KeyStorageFlags.DefaultKeySet);
            SystemCertificates.X509Certificate2 certificate = null;
            foreach (SystemCertificates.X509Certificate2 aCertificate in pkcs12)
            {
                if (storeAlias.Equals(aCertificate.FriendlyName, StringComparison.InvariantCultureIgnoreCase))
                {
                    certificate = aCertificate;
                    break;
                }
            }
            Assert.NotNull(certificate, "Key with alias {0} not found.", storeAlias);

            X509Certificate2SignatureContainer signature = new X509Certificate2SignatureContainer(certificate);

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-RSA-signed-simple-container.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                pdfSigner.SignExternalContainer(signature, 8192);
            }
        }

        [Test]
        public void testSignSimpleContainerRsaSha512()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            string storePass = "test1234";
            string storeAlias = "RSAkey";

            SystemCertificates.X509Certificate2Collection pkcs12 = new SystemCertificates.X509Certificate2Collection();
            pkcs12.Import(storePath, storePass, SystemCertificates.X509KeyStorageFlags.DefaultKeySet);
            SystemCertificates.X509Certificate2 certificate = null;
            foreach (SystemCertificates.X509Certificate2 aCertificate in pkcs12)
            {
                if (storeAlias.Equals(aCertificate.FriendlyName, StringComparison.InvariantCultureIgnoreCase))
                {
                    certificate = aCertificate;
                    break;
                }
            }
            Assert.NotNull(certificate, "Key with alias {0} not found.", storeAlias);

            X509Certificate2SignatureContainer signature = new X509Certificate2SignatureContainer(certificate, signer => {
                signer.DigestAlgorithm = Oid.FromFriendlyName("SHA512", OidGroup.HashAlgorithm);
            });

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-RSA-signed-simple-container-SHA512.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                pdfSigner.SignExternalContainer(signature, 8192);
            }
        }

        [Test]
        public void testSignSimpleContainerECDsa()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            string storePass = "test1234";
            string storeAlias = "ECDSAkey";

            SystemCertificates.X509Certificate2Collection pkcs12 = new SystemCertificates.X509Certificate2Collection();
            pkcs12.Import(storePath, storePass, SystemCertificates.X509KeyStorageFlags.DefaultKeySet);
            SystemCertificates.X509Certificate2 certificate = null;
            foreach (SystemCertificates.X509Certificate2 aCertificate in pkcs12)
            {
                if (storeAlias.Equals(aCertificate.FriendlyName, StringComparison.InvariantCultureIgnoreCase))
                {
                    certificate = aCertificate;
                    break;
                }
            }
            Assert.NotNull(certificate, "Key with alias {0} not found.", storeAlias);

            X509Certificate2SignatureContainer signature = new X509Certificate2SignatureContainer(certificate, signer => {
                signer.DigestAlgorithm = Oid.FromFriendlyName("SHA512", OidGroup.HashAlgorithm);
            });

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-ECDSA-signed-simple-container.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                pdfSigner.SignExternalContainer(signature, 8192);
            }
        }

    }
}
