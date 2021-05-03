/**
 * <p>
 * The tests in this package make use of the base tests
 * and set variables to access a D-Trust card via the
 * Nexus Personal PKCS#11 driver as configured and
 * initialized on the original development machine.
 * The values are easy to identify and exchange,
 * though.
 * </p>
 * <p>
 * Due to shortcomings of the SunPKCS11 security provider,
 * the working test needed to utilize the IAIK PKCS11
 * security provider instead.
 * </p>
 */
package mkl.itext.signing.pkcs11.dtrust;