package com.filemanager.CloudApplication.authentication;


import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final JwtProperties jwtProperties;

    public JwtService(
            JwtEncoder jwtEncoder,
            JwtDecoder jwtDecoder,
            JwtProperties jwtProperties) {

        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.jwtProperties = jwtProperties;
    }

    public String generateAccessToken(
            UUID userId,
            String username,
            String email,
            List<String> roles) {

        Instant now = Instant.now();
        Instant expiresAt =
                now.plusSeconds(
                        jwtProperties.getAccessTokenExpiration()
                );

        String jti = UUID.randomUUID().toString();

        JwtClaimsSet claims =
                JwtClaimsSet.builder()
                        .issuer(jwtProperties.getIssuer())
                        .audience(
                                List.of(
                                        jwtProperties.getAudience()
                                )
                        )
                        .subject(
                                userId.toString()
                        )
                        .id(jti)
                        .issuedAt(now)
                        .expiresAt(expiresAt)
                        .claim("username", username)
                        .claim("email", email)
                        .claim("roles", roles)
                        .build();

        return jwtEncoder
                .encode(
                        JwtEncoderParameters.from(claims)
                )
                .getTokenValue();
    }

    public Jwt validateToken(String token) {
        return jwtDecoder.decode(token);
    }

    public UUID getUserId(Jwt jwt) {
        return UUID.fromString( jwt.getSubject() );
    }

    public String getUsername(Jwt jwt) {
        return jwt.getClaimAsString("username");
    }

    public String getEmail(Jwt jwt) {
        return jwt.getClaimAsString("email");
    }


    public List<String> getRoles(Jwt jwt) {
        return jwt.getClaimAsStringList("roles");
    }

    public String getTokenId(Jwt jwt) {
        return jwt.getId();
    }
}
