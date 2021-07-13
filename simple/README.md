### Generating The Test Key Material

A PKCS#12 store with a RSA key and an associated self-signed certificate has been generated in the `keystore` folder using this command:

    keytool -genkey -alias RSAkey -keystore test1234.p12 -storetype PKCS12 -keyalg RSA -storepass test1234 -validity 3560 -keysize 2048 -dname "CN=mkl simple tests, OU=tests, O=mkl"