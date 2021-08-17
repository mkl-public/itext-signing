package mkl.itext.signing.jce.utimaco;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.itextpdf.io.source.ByteArrayOutputStream;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.signatures.IExternalSignatureContainer;

import CryptoServerJCE.CryptoServerProvider;

/**
 * @author mkl
 */
public class UtimacoJceSignatureContainer implements IExternalSignatureContainer {
    final PdfName subfilter;

    /** The alias. */
    String alias;

    /** The private key object. */
    PrivateKey pk;

    /** The certificate chain. */
    Certificate[] chain;

    /** The algorithm identifier */
    AlgorithmIdentifier algorithmIdentifier;

    /** The BC content signer for the given key */
    ContentSigner contentSigner;

    /** The security provider */
    final CryptoServerProvider provider;

    public UtimacoJceSignatureContainer(CryptoServerProvider utimacoProvider, PdfName subfilter) {
        this.subfilter = subfilter;
        this.provider = utimacoProvider;
    }

    public UtimacoJceSignatureContainer select(String alias, char[] pin) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, pin);

        boolean found = false;
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String thisAlias = aliases.nextElement();
            if (alias == null || alias.equals(thisAlias)) {
                PrivateKey thisPk = (PrivateKey) ks.getKey(thisAlias, pin);
                if (thisPk == null)
                    continue;
                Certificate[] thisChain = ks.getCertificateChain(thisAlias);
                if (thisChain == null)
                    continue;

                found = true;
                pk = thisPk;
                chain = thisChain;
                this.alias = thisAlias;
                break;
            }
        }

        if (!found) {
            pk = null;
            chain = null;
            this.alias = null;
        }

        return this;
    }

    public UtimacoJceSignatureContainer with(String algorithm, AlgorithmParameterSpec paramSpec) {
        if (paramSpec instanceof PSSParameterSpec) {
            PSSParameterSpec pssSpec = (PSSParameterSpec)paramSpec;

            algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, createPSSParams(pssSpec));
        } else {
            algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        }

        contentSigner = new ContentSigner() {
            private ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            @Override
            public byte[] getSignature() {
                try {
                    Signature sig = Signature.getInstance(algorithm, provider);
                    sig.initSign(pk);
                    if (paramSpec != null)
                        sig.setParameter(paramSpec);
                    sig.update(outputStream.toByteArray());
                    return sig.sign();
                } catch (Exception e) {
                    if (e instanceof RuntimeException)
                        throw (RuntimeException)e;
                    throw new RuntimeException(e);
                } finally {
                    outputStream.reset();
                }
            }

            @Override
            public OutputStream getOutputStream() {
                return outputStream;
            }

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return algorithmIdentifier;
            }
        };

        return this;
    }

    @Override
    public byte[] sign(InputStream data) throws GeneralSecurityException {
        try {
            CMSTypedData msg = new CMSTypedDataInputStream(data);

            X509CertificateHolder signCert = new X509CertificateHolder(chain[0].getEncoded());

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                            .build(contentSigner, signCert));

            gen.addCertificates(new JcaCertStore(Arrays.asList(chain)));

            CMSSignedData sigData = gen.generate(msg, false);
            return sigData.getEncoded();
        } catch (IOException | OperatorCreationException | CMSException e) {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    public void modifySigningDictionary(PdfDictionary signDic) {
        signDic.put(PdfName.Filter, new PdfName("MKLx_GENERIC_SIGNER"));
        signDic.put(PdfName.SubFilter, subfilter);
    }

    class CMSTypedDataInputStream implements CMSTypedData {
        InputStream in;

        public CMSTypedDataInputStream(InputStream is) {
            in = is;
        }

        @Override
        public ASN1ObjectIdentifier getContentType() {
            return PKCSObjectIdentifiers.data;
        }

        @Override
        public Object getContent() {
            return in;
        }

        @Override
        public void write(OutputStream out) throws IOException,
                CMSException {
            byte[] buffer = new byte[8 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            in.close();
        }
    }

    private static RSASSAPSSparams createPSSParams(PSSParameterSpec pssSpec)
    {
        DigestAlgorithmIdentifierFinder digFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier digId = digFinder.find(pssSpec.getDigestAlgorithm());
        if (digId.getParameters() == null) {
            digId = new AlgorithmIdentifier(digId.getAlgorithm(), DERNull.INSTANCE);
        }
        AlgorithmIdentifier mgfDig = digFinder.find(((MGF1ParameterSpec)pssSpec.getMGFParameters()).getDigestAlgorithm());
        if (mgfDig.getParameters() == null) {
            mgfDig = new AlgorithmIdentifier(mgfDig.getAlgorithm(), DERNull.INSTANCE);
        }

        return new RSASSAPSSparams(
            digId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, mgfDig),
            new ASN1Integer(pssSpec.getSaltLength()),
            new ASN1Integer(pssSpec.getTrailerField()));
    }
}
