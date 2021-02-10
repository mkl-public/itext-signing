﻿using iText.Kernel.Pdf;
using iText.Signatures;
using NUnit.Framework;
using System;
using System.IO;
using static iText.Signatures.PdfSigner;

namespace itext.signing.pkcs11_Net
{
    class TestSignSimple
    {
        [Test]
        public void TestPkcs11SignSimple()
        {
            string testFileName = @"..\..\..\resources\circles.pdf";

            using (Pkcs11Signature signature = new Pkcs11Signature(@"c:\Program Files\Entrust\SigningClient\P11SigningClient64.dll", 1).Select(null, "CN=Entrust Limited,OU=ECS,O=Entrust Limited,L=Kanata,ST=Ontario,C=CA", "1234").SetHashAlgorithm("SHA256"))
            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-pkcs11-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());
                ITSAClient tsaClient = new TSAClientBouncyCastle("http://timestamp.entrust.net/TSS/RFC3161sha2TS");

                pdfSigner.SignDetached(signature, signature.GetChain(), null, null, tsaClient, 0, CryptoStandard.CMS);
            }
        }
    }
}
