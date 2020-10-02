package mkl.itext.signing.pkcs11;

public class TestEnvironment {
    public static String getPkcs11Config() {
        boolean msWindowsOs = System.getProperty("os.name").toLowerCase().contains("win");
        String envValue = System.getenv("PKCS11_CONFIG");
        if (envValue == null || envValue.length() == 0)
            envValue = SOFTHSM_CONFIG;

        String config = null;
        switch (envValue) {
        case SOFTHSM_CONFIG:
        case SOFTHSM2_CONFIG:
            config = msWindowsOs ?
                    "--name = 171137967\n"
                    + "library = d:/Program Files/SoftHSM2/lib/softhsm2-x64.dll\n"
                    + "slot = 171137967\n"
                    :
                    "--name = 925991530\n"
                    + "library = /lib/softhsm/libsofthsm2.so\n"
                    + "slot = 925991530";
            break;
        case UTIMACO_CONFIG:
            config = "--name = Utimaco\n"
                    + "library = d:/Program Files/Utimaco/CryptoServer/Lib/cs_pkcs11_R2.dll\n"
                    + "slot = 0\n";
            break;
        default:
            config = envValue;
        }

        System.out.printf("Test configuration:\n***\n%s\n***\n", config);
        return config;
    }

    public static final String SOFTHSM_CONFIG = "SOFTHSM";
    public static final String SOFTHSM2_CONFIG = "SOFTHSM2";
    public static final String UTIMACO_CONFIG = "UTIMACO";
}
