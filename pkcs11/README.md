# The PKCS#11 Devices Used

## SoftHSM

For the tests [SoftHSM2](https://www.opendnssec.org/softhsm/) is used as device addressed via PKCS#11.

On Windows it has been installed using the [SoftHSM2 installer for MS Windows](https://github.com/disig/SoftHSM2-for-Windows) provided by [Disig a.s.](https://www.disig.sk/)

Using `softhsm2-util --init-token` a token has been initialized with SO PIN `1234` and User PIN `5678`. The automatically generated slot number is `171137967`.

A matching PKCS#11 configuration file has been created as <tt>pkcs11-softhsm-windows.cfg</tt>:

    name = 171137967
    library = d:\Program Files\SoftHSM2\lib\softhsm2-x64.dll
    slot = 171137967

A RSA keypair and a self-signed certificate then have been generated in that slot using (on a single line)

    keytool.exe -providerClass sun.security.pkcs11.SunPKCS11 -providerArg pkcs11-softhsm-windows.cfg
                -keystore NONE -storetype PKCS11 -genkeypair -alias RSAkey -keyalg RSA
                -dname "CN=mkl PKCS11 test, OU=tests, O=mkl"

On Linux it has been installed from the Ubuntu apt package softhsm.

The token initialized here got the automatically generated slot number `925991530`. Consequentially, the matching PKCS#11 configuration file created as <tt>pkcs11-softhsm-linux.cfg</tt> looks like this:

    name = 925991530
    library = /lib/softhsm/libsofthsm2.so
    slot = 925991530

Here also a RSA keypair and a self-signed certificate have been generated in that slot using the same command as above, merely with <tt>pkcs11-softhsm-linux.cfg</tt> instead of <tt>pkcs11-softhsm-windows.cfg</tt>.

## Utimaco Simulator

Another PKCS#11 device used is the [Utimaco Simulator](https://hsm.utimaco.com/products-hardware-security-modules/hsm-simulators/securityserver-simulator/). For the Utimaco PKCS#11 driver to address the correct device, a configuration file is required which must be named <tt>cs_pkcs11_R2.cfg</tt> and look like this:

    [Global]
    # Select the log level (NONE...TRACE)
    Logging = 1
    # Specifies the path where the logfile shall be created.
    Logpath = C:/temp/cs_pkcs11_R2.log
    # Defines the maximum size of the logfile. If the maximum is reached,
    # old entries will be overwritten. Can be defined as value
    # in bytes or as formatted text. E.g. value of ‘1000’ means logsize
    # is 1000 bytes whereas value of ‘1000kb’ means 1000 kilobytes.
    # Allowed formats are ‘kb’, ‘mb’ and ‘gb’.
    Logsize = 10mb
    [CryptoServer]
    # Device address to connect a CryptoServer device
    Device = 3001@127.0.0.1

The full path and name of this file should be given in the environment variable <tt>CS_PKCS11_R2_CFG</tt>. If it is not, it is searched in certain default locations.

Using the Utimaco Administration Tools in the slot 0 a token has been initialized with SO PIN `1234` and User PIN `5678`. Consequentially, the matching PKCS#11 configuration file created as <tt>pkcs11-utimaco.cfg</tt> looks like this:

    name = Utimaco
    library = d:\Program Files\Utimaco\CryptoServer\Lib\cs_pkcs11_R2.dll
    slot = 0

Here also a RSA keypair and a self-signed certificate have been generated in that slot using the same command as above, merely with <tt>pkcs11-utimaco.cfg</tt> instead of <tt>pkcs11-softhsm-*.cfg</tt>.

## Belgian ID cards

Yet another PKCS#11 device used are Belgian ID cards in ACS zetes card readers. The cards have been initialized for testing with the PIN `1234`.

The matching PKCS#11 configuration file created as <tt>pkcs11-beid.cfg</tt> looks like this:

    name = BeID
    library = "c:/Program Files (x86)/Belgium Identity Card/FireFox Plugin Manifests/beid_ff_pkcs11_64.dll"
    slot = 0

# Selecting a PKCS#11 Device

The PKCS#11 device used by a generic test can be controlled via an environment variable, <tt>PKCS11_CONFIG</tt> which can either be set to the path and name of a PKCS#11 configuration file or one of the fixed values <tt>SOFTHSM</tt> and <tt>UTIMACO</tt>. An alias (if required) can be selected in the environment variable <tt>PKCS11_ALIAS</tt>. The PIN used for signing can be selected using the environment variable <tt>PKCS11_PIN</tt> and defaults to <tt>5678</tt>.