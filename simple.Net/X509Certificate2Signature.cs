using iText.Signatures;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace itext.signing.simple_Net
{
    /// <summary>
    /// Creates a signature using a X509Certificate2. It supports smartcards without 
    /// exportable private keys.
    /// </summary>
    public class X509Certificate2Signature : IExternalSignature
    {
        /// <summary>
        /// The certificate with the private key
        /// </summary>
        private X509Certificate2 certificate;
        /** The hash algorithm. */
        private string hashAlgorithm;
        /** The encryption algorithm (obtained from the private key) */
        private string encryptionAlgorithm;

        /// <summary>
        /// Creates a signature using a X509Certificate2. It supports smartcards without 
        /// exportable private keys.
        /// </summary>
        /// <param name="certificate">The certificate with the private key</param>
        /// <param name="hashAlgorithm">The hash algorithm for the signature. As the Windows CAPI is used
        /// to do the signature the only hash guaranteed to exist is SHA-1</param>
        public X509Certificate2Signature(X509Certificate2 certificate, string hashAlgorithm)
        {
            if (!certificate.HasPrivateKey)
                throw new ArgumentException("No private key.");
            this.certificate = certificate;
            this.hashAlgorithm = DigestAlgorithms.GetDigest(DigestAlgorithms.GetAllowedDigest(hashAlgorithm));
            if (certificate.PrivateKey is RSA)
                encryptionAlgorithm = "RSA";
            else if (certificate.PrivateKey is DSA)
                encryptionAlgorithm = "DSA";
            else if (certificate.PrivateKey is ECDsa)
                encryptionAlgorithm = "ECDSA";
            else
                throw new ArgumentException("Unknown encryption algorithm " + certificate.PrivateKey);
        }

        public string GetEncryptionAlgorithm()
        {
            return encryptionAlgorithm;
        }

        public string GetHashAlgorithm()
        {
            return hashAlgorithm;
        }

        public byte[] Sign(byte[] message)
        {
            if (certificate.PrivateKey is RSA rsa)
            {
                return rsa.SignData(message, new HashAlgorithmName(hashAlgorithm), RSASignaturePadding.Pkcs1);
            }
            else if (certificate.PrivateKey is DSA dsa)
            {
                return dsa.SignData(message, new HashAlgorithmName(hashAlgorithm));
            }
            else
            {
                ECDsa ecdsa = (ECDsa)certificate.PrivateKey;
                return ecdsa.SignData(message, new HashAlgorithmName(hashAlgorithm));
            }
        }
    }
}
