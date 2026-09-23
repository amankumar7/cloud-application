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

            PrivateKey privateKey =
                    loadPrivateKey(properties.getPrivateKey());

            PublicKey publicKey =
                    loadPublicKey(properties.getPublicKey());

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
                jwkSource =
                new ImmutableJWKSet<>(jwkSet);

        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {

        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey())
                .build();
    }

    private PrivateKey loadPrivateKey(String key)
            throws Exception {

        String normalizedKey =
                key
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s+", "");

        byte[] keyBytes =
                Base64.getDecoder().decode(normalizedKey);

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory keyFactory =
                KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(spec);
    }

    private PublicKey loadPublicKey(String key)
            throws Exception {

        String normalizedKey =
                key
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s+", "");

        byte[] keyBytes =
                Base64.getDecoder().decode(normalizedKey);

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);

        KeyFactory keyFactory =
                KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(spec);
    }
}
