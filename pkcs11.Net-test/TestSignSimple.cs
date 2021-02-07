using iText.Kernel.Pdf;
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

            using (Pkcs11Signature signature = new Pkcs11Signature(@"PKCS11LIBRARY", 1).Select("KEYALIAS", "CERTLABEL", "1234").SetHashAlgorithm("SHA256"))
            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-pkcs11-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());
                ITSAClient tsaClient = null;

                pdfSigner.SignDetached(signature, signature.GetChain(), null, null, tsaClient, 0, CryptoStandard.CMS);
            }
        }
    }
}
