package mkl.itext.signing.pkcs11.generic;

/**
 * This utility class retrieves information from the environment
 * to use as seeds to configure PKCS11 test cases. The variables
 * in question are
 * <ul>
 * <li><b>PKCS11_CONFIG</b> holding the PKCS11 driver
 * configuration (either the path and name of a configuration file,
 * or the configuration itself, prefixed by <code>"--"</code>, or
 * one of the magic values {@value #SOFTHSM_CONFIG}, {@value
 * #SOFTHSM2_CONFIG}, and {@value #UTIMACO_CONFIG} which are
 * replaced by hard-coded configurations matching the original
 * developing machine), defaulting to {@value #SOFTHSM_CONFIG};
 * <li><b>PKCS11_ALIAS</b> holding the alias by which to select a
 * key and certificate, defaulting to <code>null</code>; and
 * <li><b>PKCS11_PIN</b> holding a PIN value for key access and
 * signing, defaulting to <code>"5678"</code>; to actually use no
 * PIN use the magic value <code>"NULL"</code>.
 * </ul>
 * 
 * @author mkl
 */
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

    public static String getPkcs11Alias() {
        String envValue = System.getenv("PKCS11_ALIAS");
        if (envValue == null || envValue.length() == 0)
            return null;
        return envValue;
    }

    public static char[] getPkcs11Pin() {
        String envValue = System.getenv("PKCS11_PIN");
        if (envValue == null || envValue.length() == 0)
            envValue = "5678";
        else if ("NULL".equals(envValue))
            return null;
        return envValue.toCharArray();
    }

    public static final String SOFTHSM_CONFIG = "SOFTHSM";
    public static final String SOFTHSM2_CONFIG = "SOFTHSM2";
    public static final String UTIMACO_CONFIG = "UTIMACO";
}
