package com.filemanager.CloudApplication.authentication;


import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String issuer;
    private String audience;

    /**
     * Access token lifetime in seconds.
     */
    private long accessTokenExpiration;

    /**
     * Refresh token lifetime in seconds.
     * <p>
     * We currently won't put the refresh token
     * inside JWT. This is used by RefreshTokenService.
     */
    private long refreshTokenExpiration;

    /**
     * Base64 encoded RSA private key.
     */
    private String privateKey;

    /**
     * Base64 encoded RSA public key.
     */
    private String publicKey;

    public String getIssuer() {

        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public void setAccessTokenExpiration(long accessTokenExpiration) {
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }

    public void setRefreshTokenExpiration(long refreshTokenExpiration) {
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }
}