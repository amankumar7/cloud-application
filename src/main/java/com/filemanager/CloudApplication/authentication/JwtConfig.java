package com.filemanager.CloudApplication.authentication;

import com.nimbusds.jose.JOSEException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JwtConfig {

    @Bean
    public RSAKey rsaKey(JwtProperties properties) {

        try {

            PrivateKey privateKey = loadPrivateKey(properties.getPrivateKey());

            PublicKey publicKey = loadPublicKey(properties.getPublicKey());

            return new RSAKey.Builder((RSAPublicKey) publicKey)
                    .privateKey(privateKey)
                    .keyID("cloud-auth-key-1")
                    .build();

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Unable to load RSA JWT keys",
                    e
            );
        }
    }

    @Bean
    public JwtEncoder jwtEncoder(RSAKey rsaKey) {

        JWKSet jwkSet = new JWKSet(rsaKey);

        ImmutableJWKSet<com.nimbusds.jose.proc.SecurityContext>
                jwkSource = new ImmutableJWKSet<>(jwkSet);

        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {

        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    /**
     * Reads the PRIVATE KEY from the file path.
     */
    private PrivateKey loadPrivateKey(String filePath)
            throws Exception {

        if (filePath == null || filePath.isBlank()) {
            throw new IllegalStateException(
                    "JWT private key file path is not configured"
            );
        }

        Path path = Path.of(filePath);

        if (!Files.exists(path)) {
            throw new IllegalStateException(
                    "JWT private key file does not exist: "
                            + filePath
            );
        }

        String key = Files.readString(
                path,
                StandardCharsets.UTF_8
        );

        key = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        // Decode Base64
        byte[] decoded = Base64.getDecoder().decode(key);

        // PKCS#8
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Reads the PUBLIC KEY from the file path.
     */
    private PublicKey loadPublicKey(String filePath)
            throws Exception {

        if (filePath == null || filePath.isBlank()) {
            throw new IllegalStateException(
                    "JWT public key file path is not configured"
            );
        }

        Path path = Path.of(filePath);

        if (!Files.exists(path)) {
            throw new IllegalStateException(
                    "JWT public key file does not exist: "
                            + filePath
            );
        }

        // Read PEM file
        String key = Files.readString(
                path,
                StandardCharsets.UTF_8
        );

        // Remove PEM headers/footer
        key = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");

        // Decode Base64
        byte[] decoded = Base64.getDecoder().decode(key);

        // X.509 public key
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(keySpec);
    }

}
