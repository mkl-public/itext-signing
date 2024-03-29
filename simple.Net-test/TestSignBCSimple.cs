﻿using iText.Kernel.Pdf;
using iText.Signatures;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System.IO;

namespace itext.signing.simple_Net
{
    class TestSignBCSimple
    {
        [Test]
        public void testSignSimpleRsa()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            char[] storePass = "test1234".ToCharArray();
            string storeAlias = "RSAkey";

            Pkcs12Store pkcs12 = new Pkcs12Store(new FileStream(storePath, FileMode.Open, FileAccess.Read), storePass);
            AsymmetricKeyParameter key = pkcs12.GetKey(storeAlias).Key;
            X509CertificateEntry[] chainEntries = pkcs12.GetCertificateChain(storeAlias);
            X509Certificate[] chain = new X509Certificate[chainEntries.Length];
            for (int i = 0; i < chainEntries.Length; i++)
                chain[i] = chainEntries[i].Certificate;
            PrivateKeySignature signature = new PrivateKeySignature(key, "SHA384");

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-RSA-BC-signed-simple.pdf"))
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
            char[] storePass = "test1234".ToCharArray();
            string storeAlias = "DSAkey";

            Pkcs12Store pkcs12 = new Pkcs12Store(new FileStream(storePath, FileMode.Open, FileAccess.Read), storePass);
            AsymmetricKeyParameter key = pkcs12.GetKey(storeAlias).Key;
            X509CertificateEntry[] chainEntries = pkcs12.GetCertificateChain(storeAlias);
            X509Certificate[] chain = new X509Certificate[chainEntries.Length];
            for (int i = 0; i < chainEntries.Length; i++)
                chain[i] = chainEntries[i].Certificate;
            PrivateKeySignature signature = new PrivateKeySignature(key, "SHA1");

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-DSA-BC-signed-simple.pdf"))
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
            char[] storePass = "test1234".ToCharArray();
            string storeAlias = "ECDSAkey";

            Pkcs12Store pkcs12 = new Pkcs12Store(new FileStream(storePath, FileMode.Open, FileAccess.Read), storePass);
            AsymmetricKeyParameter key = pkcs12.GetKey(storeAlias).Key;
            X509CertificateEntry[] chainEntries = pkcs12.GetCertificateChain(storeAlias);
            X509Certificate[] chain = new X509Certificate[chainEntries.Length];
            for (int i = 0; i < chainEntries.Length; i++)
                chain[i] = chainEntries[i].Certificate;
            PrivateKeySignature signature = new PrivateKeySignature(key, "SHA512");

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-ECDSA-BC-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());
                ITSAClient tsaClient = null;

                pdfSigner.SignDetached(signature, chain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CMS);
            }
        }

        [Test]
        public void testSignSimpleRsaSsaPss()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            char[] storePass = "test1234".ToCharArray();
            string storeAlias = "RSAkey";

            Pkcs12Store pkcs12 = new Pkcs12Store(new FileStream(storePath, FileMode.Open, FileAccess.Read), storePass);
            AsymmetricKeyParameter key = pkcs12.GetKey(storeAlias).Key;
            X509CertificateEntry[] chainEntries = pkcs12.GetCertificateChain(storeAlias);
            X509Certificate[] chain = new X509Certificate[chainEntries.Length];
            for (int i = 0; i < chainEntries.Length; i++)
                chain[i] = chainEntries[i].Certificate;
            PrivateKeySignatureContainer signature = new PrivateKeySignatureContainer(key, chain, "SHA384withRSAandMGF1");

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-RSASSAPSS-BC-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                pdfSigner.SignExternalContainer(signature, 8192);
            }
        }

        [Test]
        public void testSignSimpleDsaSha256()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";
            string storePath = @"..\..\..\..\simple\keystore\test1234.p12";
            char[] storePass = "test1234".ToCharArray();
            string storeAlias = "DSAkey";

            Pkcs12Store pkcs12 = new Pkcs12Store(new FileStream(storePath, FileMode.Open, FileAccess.Read), storePass);
            AsymmetricKeyParameter key = pkcs12.GetKey(storeAlias).Key;
            X509CertificateEntry[] chainEntries = pkcs12.GetCertificateChain(storeAlias);
            X509Certificate[] chain = new X509Certificate[chainEntries.Length];
            for (int i = 0; i < chainEntries.Length; i++)
                chain[i] = chainEntries[i].Certificate;
            PrivateKeySignatureContainer signature = new PrivateKeySignatureContainer(key, chain, "SHA256withDSA");

            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-DSASHA256-BC-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                pdfSigner.SignExternalContainer(signature, 8192);
            }
        }
    }
}
