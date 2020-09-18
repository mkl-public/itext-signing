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

            using (Pkcs11Signature signature = new Pkcs11Signature(@"d:\Program Files\SoftHSM2\lib\softhsm2-x64.dll", 171137967).Select(null, "5678").SetHashAlgorithm("SHA256"))
            using (PdfReader pdfReader = new PdfReader(testFileName))
            using (FileStream result = File.Create("circles-pkcs11-signed-simple.pdf"))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                pdfSigner.SignDetached(signature, signature.GetChain(), null, null, null, 0, CryptoStandard.CMS);
            }
        }
    }
}
