# The Utimaco HSM Used

For the tests the [Utimaco Simulator](https://hsm.utimaco.com/products-hardware-security-modules/hsm-simulators/securityserver-simulator/) is used.

The Utimaco JCE provider jar is included in the `lib` subfolder.

Using the Utimaco Administration Tools a _cryptographic user_ `JCE` with `CXI_GROUP=JCE` and HMAC password `5678` has been created.

For the Utimaco JCE driver to address the correct device, group, and user, a configuration file is required during initialization which must be located in the user's home, named <tt>CryptoServer.cfg</tt> and look like this:

    Device = 3001@127.0.0.1
    DefaultUser = JCE
    KeyGroup = JCE

A RSA keypair and a self-signed certificate then have been generated in that group using (on a single line)

    keytool.exe -providerpath lib\CryptoServerJCE.jar -providerclass CryptoServerJCE.CryptoServerProvider
                -providername CryptoServer -keystore NONE -storetype CryptoServer
                -genkeypair -alias RSAkey -keyalg RSA
                -dname "CN=mkl PKCS11 test, OU=tests, O=mkl"

The same password has been used for the new key as for the keystore, i.e. the password of the implied user `JCE`: `5678`.