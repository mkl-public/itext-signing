### Generating The Test Key Material

A PKCS#12 store with a keys and associated self-signed certificates has been generated in the `keystore` folder using these commands:

    keytool -genkey -alias RSAkey -keystore test1234.p12 -storetype PKCS12 -keyalg RSA -storepass test1234 -validity 3560 -keysize 2048 -dname "CN=mkl simple tests, OU=tests, O=mkl"
    keytool -genkey -alias DSAkey -keystore test1234.p12 -storetype PKCS12 -keyalg DSA -sigalg SHA1withDSA -storepass test1234 -validity 3560 -keysize 1024 -dname "CN=mkl simple tests DSA, OU=tests, O=mkl"
    keytool -genkey -alias ECDSAkey -keystore test1234.p12 -storetype PKCS12 -keyalg EC -storepass test1234 -validity 3560 -keysize 521 -dname "CN=mkl simple tests ECDSA, OU=tests, O=mkl"

Beware: For DSA the week parameters have been chosen for reasons:

* According to the [Acrobat DC Digital Signatures Guide](https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/standards.html) Adobe Acrobat only supports DSA with SHA1.
* Microsoft .Net security APIs partially turn out to only support DSA with key sizes up to 1024 bits.