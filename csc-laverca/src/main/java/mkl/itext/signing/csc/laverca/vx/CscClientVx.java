package mkl.itext.signing.csc.laverca.vx;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import com.squareup.okhttp.Credentials;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;

import fi.methics.laverca.csc.CscClient;
import fi.methics.laverca.csc.CscException;
import fi.methics.laverca.csc.json.auth.CscLoginReq;
import fi.methics.laverca.csc.json.auth.CscLoginResp;
import fi.methics.laverca.csc.json.auth.CscRevokeReq;
import fi.methics.laverca.csc.json.auth.CscRevokeResp;
import fi.methics.laverca.csc.json.credentials.CscCredentialsAuthorizeReq;
import fi.methics.laverca.csc.json.credentials.CscCredentialsAuthorizeResp;
import fi.methics.laverca.csc.json.credentials.CscCredentialsInfoReq;
import fi.methics.laverca.csc.json.credentials.CscCredentialsInfoResp;
import fi.methics.laverca.csc.json.credentials.CscCredentialsListReq;
import fi.methics.laverca.csc.json.credentials.CscCredentialsListResp;
import fi.methics.laverca.csc.json.info.CscInfoReq;
import fi.methics.laverca.csc.json.info.CscInfoResp;
import fi.methics.laverca.csc.json.signatures.CscSignHashReq;
import fi.methics.laverca.csc.json.signatures.CscSignHashResp;
import fi.methics.laverca.csc.util.AllTrustingHostnameVerifier;
import fi.methics.laverca.csc.util.AllTrustingTrustManager;

/**
 * This is a copy of the Laverca {@link CscClient} class in which the URL
 * version identifier has been made dynamic.
 * 
 * @author mkl
 */
public class CscClientVx {

    public static final String RSA_WITH_SHA1   = "1.2.840.113549.1.1.5";
    public static final String RSA_WITH_SHA224 = "1.2.840.113549.1.1.14";
    public static final String RSA_WITH_SHA256 = "1.2.840.113549.1.1.11";
    public static final String RSA_WITH_SHA384 = "1.2.840.113549.1.1.12";
    public static final String RSA_WITH_SHA512 = "1.2.840.113549.1.1.13";

    private String version;
    private String baseurl;
    private String username;
    private String password;

    private OkHttpClient client;

    private String access_token;
    private String refresh_token;
    private CscCredentialsAuthorizeResp authorize;
    private boolean isScal2 = false;

    protected CscClientVx(String baseurl,
                        String version,
                        String username, 
                        String password,
                        boolean trustall) {
        this.baseurl  = baseurl;
        this.version = version;
        this.username = username;
        this.password = password;

        this.client = new OkHttpClient();
        this.client.setConnectTimeout(60, TimeUnit.SECONDS);
        this.client.setReadTimeout(60,    TimeUnit.SECONDS);
        this.client.setWriteTimeout(60,   TimeUnit.SECONDS);

        if (trustall) {
            try {
                SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, new TrustManager[] { new AllTrustingTrustManager() }, new java.security.SecureRandom());
                this.client.setSslSocketFactory(sslContext.getSocketFactory());
                this.client.setHostnameVerifier(new AllTrustingHostnameVerifier());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Login with HTTP Basic credentials
     * @return Login response
     */
    public CscLoginResp authLogin() {
        CscLoginReq req = new CscLoginReq();
        req.rememberMe = true;

        try {
            String url = this.baseurl+"/csc/" + version + "/auth/login";
            Request  request  = new Request.Builder().url(url)
                                                     .post(req.toRequestBody())
                                                     .header("Authorization", Credentials.basic(this.username, this.password))
                                                     .build();

            Response response = client.newCall(request).execute();
            CscLoginResp loginresp = CscLoginResp.fromResponse(response, CscLoginResp.class);

            this.access_token  = loginresp.access_token;
            this.refresh_token = loginresp.refresh_token;

            return loginresp; 
        } catch (IOException e) {
            e.printStackTrace();
            throw new CscException(e);
        } catch (CscException e) {
            throw e;
        }
    }

    /**
     * Use refresh_token to refresh login
     * @return Login response
     */
    public CscLoginResp refreshLogin() {
        CscLoginReq req = new CscLoginReq();
        req.rememberMe     = true;
        req.refresh_token = this.refresh_token;

        try {
            String url = this.baseurl+"/csc/" + version + "/auth/login";
            Request  request  = new Request.Builder().url(url)
                                                     .post(req.toRequestBody())
                                                     .build();

            Response response = client.newCall(request).execute();
            CscLoginResp loginresp = CscLoginResp.fromResponse(response, CscLoginResp.class);

            this.access_token  = loginresp.access_token;
            this.refresh_token = loginresp.refresh_token;

            return loginresp; 
        } catch (IOException e) {
            e.printStackTrace();
            throw new CscException(e);
        } catch (CscException e) {
            throw e;
        }
    }

    /**
     * Revoke current login
     * @return Revoke response
     */
    public CscRevokeResp authRevoke() {
        if (this.access_token == null) {
            throw CscException.createNotLoggedInException();
        }

        CscRevokeReq req = new CscRevokeReq();
        req.token = this.access_token;
        req.token_type_hint = "access_token";

        try {
            String url = this.baseurl+"/csc/" + version + "/auth/revoke";
            Request  request  = new Request.Builder().url(url)
                                                     .post(req.toRequestBody())
                                                     .header("Authorization", "Bearer " + this.access_token)
                                                     .build();

            Response response = client.newCall(request).execute();
            CscRevokeResp loginresp = CscRevokeResp.fromResponse(response, CscRevokeResp.class);

            this.access_token = null;

            return loginresp; 
        } catch (IOException e) {
            e.printStackTrace();
            throw new CscException(e);
        } catch (CscException e) {
            throw e;
        }
    }

    /**
     * Explicitly authorize signature in SCAL1 mode.
     * 
     * <p>This can optionally called before {@link #signHash(String, List, String)}.
     * If no valid authorize response is found, signHash automatically calls this again.
     * 
     * @param credentialid Credential ID to authorize
     * @return Authorize response
     */
    public CscCredentialsAuthorizeResp authorize(String credentialid) {
        if (this.isScal2) {
            throw CscException.createMissingParamException("hash");
        }
        return this.authorize(credentialid, null);
    }

    /**
     * Explicitly authorize signature in SCAL2 mode.
     * 
     * <p>This can optionally called before {@link #signHash(String, List, String)}.
     * If no valid authorize response is found, signHash automatically calls this again.
     * 
     * @param credentialid Credential ID to authorize
     * @return Authorize response
     */
    public CscCredentialsAuthorizeResp authorize(String credentialid, List<String> hash) {
        if (this.access_token == null) {
            throw CscException.createNotLoggedInException();
        }
        CscCredentialsAuthorizeReq req = new CscCredentialsAuthorizeReq();
        req.credentialID  = credentialid;
        req.numSignatures = hash != null ? hash.size() : 1;
        req.hash          = hash;

        try {
            String url = this.baseurl+"/csc/" + version + "/credentials/authorize";
            Request  request  = new Request.Builder().url(url)
                                                     .post(req.toRequestBody())
                                                     .header("Authorization", "Bearer " + this.access_token)
                                                     .build();

            Response response = client.newCall(request).execute();
            CscCredentialsAuthorizeResp authorize = CscCredentialsAuthorizeResp.fromResponse(response, CscCredentialsAuthorizeResp.class);
            this.authorize = authorize;
            return authorize;
        } catch (IOException e) {
            e.printStackTrace();
            throw new CscException(e);
        } catch (CscException e) {
            throw e;
        }
    }

    /**
     * Get details of a credential
     * @param credentialid Credential ID
     * @return Credential info JSON
     */
    public CscCredentialsInfoResp getCredentialInfo(String credentialid) {
        if (this.access_token == null) {
            throw CscException.createNotLoggedInException();
        }
        CscCredentialsInfoReq req = new CscCredentialsInfoReq();
        req.credentialID = credentialid;

        try {
            String url = this.baseurl+"/csc/" + version + "/credentials/info";
            Request  request  = new Request.Builder().url(url)
                                                     .post(req.toRequestBody())
                                                     .header("Authorization", "Bearer " + this.access_token)
                                                     .build();

            Response response = client.newCall(request).execute();
            CscCredentialsInfoResp info = CscCredentialsInfoResp.fromResponse(response, CscCredentialsInfoResp.class);
            if ("2".equals(info.SCAL)) {
                this.isScal2 = true;
            }
            return info;
        } catch (IOException e) {
            e.printStackTrace();
            throw new CscException(e);
        } catch (CscException e) {
            throw e;
        }
    }

    /**
     * Get information about the target CSC server
     * <p>Calls /csc/vX/info API
     * @param lang Language which the info should be returned in (if possible)
     * @return CSC info response JSON
     * @throws CscException
     */
    public CscInfoResp getInfo(String lang) throws CscException {
        CscInfoReq req = new CscInfoReq();
        req.lang = lang;

        try {
            String url = this.baseurl+"/csc/" + version + "/info";
            Request  request  = new Request.Builder().url(url).post(req.toRequestBody()).build();
            Response response = client.newCall(request).execute();
            
            return CscInfoResp.fromResponse(response, CscInfoResp.class);
        } catch (IOException e) {
            e.printStackTrace();
            throw new CscException(e);
        } catch (CscException e) {
            throw e;
        }
    }

    /**
     * List client credentials
     * @return Credential list JSON
     */
    public CscCredentialsListResp listCredentials() {
        if (this.access_token == null) {
            throw CscException.createNotLoggedInException();
        }
        CscCredentialsListReq req = new CscCredentialsListReq();
        req.maxResults = 20;

        try {
            String url = this.baseurl+"/csc/" + version + "/credentials/list";
            Request  request  = new Request.Builder().url(url)
                                                     .post(req.toRequestBody())
                                                     .header("Authorization", "Bearer " + this.access_token)
                                                     .build();

            Response response = client.newCall(request).execute();
            return CscCredentialsListResp.fromResponse(response, CscCredentialsListResp.class);
        } catch (CscException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
            throw new CscException(e);
        }
    }

    /**
     * Sign a list of hashes
     * 
     * @param credentialid Credential ID to authorize
     * @param authorize Authorize response with Signature Activation Data
     * @param hash      Hashes to sign
     * @param signAlgo  Signature Algorithm (Use e.g. {@link CscClient#RSA_WITH_SHA256})
     * @param hashAlgo  Signature hash algorithm. Optional.
     * @return Authorize response
     */
    public CscSignHashResp signHash(String credentialid, CscCredentialsAuthorizeResp authorize, List<String> hash, String signAlgo, String hashAlgo) {
        if (this.access_token == null) {
            throw CscException.createNotLoggedInException();
        }
        CscSignHashReq req = new CscSignHashReq();
        req.credentialID = credentialid;
        req.hash         = hash;
        req.signAlgo     = signAlgo;
        req.hashAlgo     = hashAlgo;
        req.SAD          = authorize.SAD;

        try {
            String url = this.baseurl+"/csc/" + version + "/signatures/signHash";
            Request  request  = new Request.Builder().url(url)
                                                     .post(req.toRequestBody())
                                                     .header("Authorization", "Bearer " + this.access_token)
                                                     .build();

            Response response = client.newCall(request).execute();
            return CscSignHashResp.fromResponse(response, CscSignHashResp.class);
        } catch (IOException e) {
            e.printStackTrace();
            throw new CscException(e);
        } catch (CscException e) {
            throw e;
        }
    }

    /**
     * Sign a list of hashes
     * 
     * @param credentialid Credential ID to authorize
     * @param authorize Authorize response with Signature Activation Data
     * @param hash     Hash to sign
     * @param signAlgo Signature Algorithm (Use e.g. {@link CscClient#RSA_WITH_SHA256})
     * @param hashAlgo  Signature hash algorithm. Optional.
     * @return Authorize response
     */
    public CscSignHashResp signHash(String credentialid, List<String> hash, String signAlgo, String hashAlgo) {
        if (this.authorize == null || this.authorize.isExpired()) {
            this.authorize(credentialid, hash);
        }
        return this.signHash(credentialid, this.authorize, hash, signAlgo, hashAlgo);
    }

    /**
     * Sign a list of hashes
     * 
     * @param credentialid Credential ID to authorize
     * @param authorize Authorize response with Signature Activation Data
     * @param hash     Hash to sign
     * @param signAlgo Signature Algorithm (Use e.g. {@link CscClient#RSA_WITH_SHA256})
     * @return Authorize response
     */
    public CscSignHashResp signHash(String credentialid, List<String> hash, String signAlgo) {
        return this.signHash(credentialid, hash, signAlgo, null);
    }


    public static class Builder {

        private String baseurl;
        private String version = "v1";
        private String username;
        private String password;
        private boolean trustall;

        public CscClientVx build() {
            return new CscClientVx(this.baseurl, this.version, this.username, this.password, this.trustall);
        }

        public Builder withBaseUrl(String baseurl) {
            this.baseurl = baseurl;
            return this;
        }

        public Builder withVersion(String version) {
            this.version = version;
            return this;
        }

        public Builder withPassword(String password) {
            this.password = password;
            return this;
        }

        public Builder withTrustInsecureConnections(boolean trust) {
            this.trustall = trust;
            return this;
        }

        public Builder withUsername(String username) {
            this.username = username;
            return this;
        }
    }
}
