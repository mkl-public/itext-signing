# The PKCS#11 device used

For the tests [SoftHSM2](https://www.opendnssec.org/softhsm/) is used as device addressed via PKCS#11.

On Windows it has been installed using the [SoftHSM2 installer for MS Windows](https://github.com/disig/SoftHSM2-for-Windows) provided by [Disig a.s.](https://www.disig.sk/)

Using `softhsm2-util --init-token` a token has been initialized with SO PIN `1234` and User PIN `5678`. The automatically generated slot number is `171137967`.

A matching PKCS#11 configuration file has been created as <tt>pkcs11.cfg</tt>:

    name = 171137967
    library = d:\Program Files\SoftHSM2\lib\softhsm2-x64.dll
    slot = 171137967

A RSA keypair and a self-signed certificate then have been generated in that slot using (on a single line)

    keytool.exe -providerClass sun.security.pkcs11.SunPKCS11 -providerArg pkcs11.cfg
                -keystore NONE -storetype PKCS11 -genkeypair -alias RSAkey -keyalg RSA
                -dname "CN=mkl PKCS11 test, OU=tests, O=mkl"

