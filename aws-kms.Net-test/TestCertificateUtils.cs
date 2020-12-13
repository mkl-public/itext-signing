using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace itext.signing.aws_kms_Net
{
    class TestCertificateUtils
    {
        [Test]
        public void testSignSimpleRsa()
        {
            string keyId = "alias/SigningExamples-RSA_2048";
            X509Certificate2 certificate = CertificateUtils.generateSelfSignedCertificate(keyId, "CN=AWS KMS Certificate Test,OU=mkl tests,O=mkl", list => list[0]);
            Console.WriteLine(certificate);
            File.WriteAllBytes("AWS KMS Certificate Test.cer", certificate.GetRawCertData());
        }
    }
}
