package com.filemanager.CloudApplication.authentication;

import com.filemanager.CloudApplication.entity.RefreshToken;
import com.filemanager.CloudApplication.entity.User;
import com.filemanager.CloudApplication.exception.InvalidRefreshTokenException;
import com.filemanager.CloudApplication.exception.RefreshTokenReuseException;
import com.filemanager.CloudApplication.repository.RefreshTokenRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private final JwtProperties jwtProperties;

    /*
     * One SecureRandom instance for the entire service.
     */
    private final SecureRandom secureRandom;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            JwtProperties jwtProperties) {

        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtProperties = jwtProperties;
        this.secureRandom = new SecureRandom();
    }


    // ============================================================
    // CREATE REFRESH TOKEN
    // ============================================================

    /**
     * Creates a new refresh token for a login/session.
     *
     * The raw token is returned only once.
     *
     * PostgreSQL stores only the SHA-256 hash.
     */
    @Transactional
    public RefreshTokenResult createRefreshToken(
            User user,
            String ipAddress,
            String userAgent,
            String deviceName) {

        String rawToken = generateSecureToken();

        UUID tokenFamilyId = UUID.randomUUID();

        RefreshToken refreshToken =
                buildRefreshToken(
                        user,
                        rawToken,
                        tokenFamilyId,
                        ipAddress,
                        userAgent,
                        deviceName
                );

        refreshTokenRepository.save(refreshToken);

        return new RefreshTokenResult(
                rawToken,
                refreshToken
        );
    }


    // ============================================================
    // ROTATE REFRESH TOKEN
    // ============================================================

    /**
     * Rotates a refresh token.
     *
     * Example:
     *
     * RT1 -> RT2
     *
     * RT1:
     *   revoked = true
     *
     * RT2:
     *   active
     *
     * If RT1 is used again, it means token reuse was detected.
     *
     * In that case the complete token family is revoked.
     */
    @Transactional
    public RefreshTokenResult rotateRefreshToken(
            String rawToken,
            String ipAddress,
            String userAgent,
            String deviceName) {

        if (rawToken == null
                || rawToken.isBlank()) {

            throw new InvalidRefreshTokenException(
                    "Invalid refresh token"
            );
        }


        /*
         * Hash the raw token.
         */

        String tokenHash = hashToken(rawToken);

        /*
         * SELECT ... FOR UPDATE
         *
         * This prevents two concurrent requests from
         * rotating the same refresh token simultaneously.
         */
        RefreshToken oldToken =
                refreshTokenRepository
                        .findByTokenHashForUpdate(
                                tokenHash
                        )
                        .orElseThrow(() ->
                                new InvalidRefreshTokenException(
                                        "Invalid refresh token"
                                ));


        // ========================================================
        // REUSE DETECTION
        // ========================================================

        /*
         * If the token was already revoked, somebody is trying
         * to use an old refresh token.
         *
         * Revoke the entire token family.
         */
        if (oldToken.isRevoked()) {

            refreshTokenRepository
                    .revokeTokenFamily(
                            oldToken.getTokenFamilyId(),
                            Instant.now()
                    );

            throw new RefreshTokenReuseException(
                    "Refresh token reuse detected"
            );
        }


        // ========================================================
        // EXPIRATION CHECK
        // ========================================================

        if (oldToken.isExpired()) {

            oldToken.setRevokedAt( Instant.now() );
            refreshTokenRepository.save( oldToken );

            throw new InvalidRefreshTokenException("Refresh token expired");
        }


        // ========================================================
        // USER CHECK
        // ========================================================

        User user = oldToken.getUser();

        /*
         * User was deleted.
         */
        if (user.getDeletedAt() != null) {

            oldToken.setRevokedAt( Instant.now() );
            refreshTokenRepository.save(oldToken);

            throw new InvalidRefreshTokenException(
                    "User account is not available"
            );
        }


        /*
         * User disabled.
         */
        if (!user.isEnabled()) {

            oldToken.setRevokedAt(Instant.now());
            refreshTokenRepository.save(oldToken);

            throw new InvalidRefreshTokenException(
                    "User account is not available"
            );
        }


        /*
         * User account permanently locked.
         */
        if (!user.isAccountNonLocked()) {

            oldToken.setRevokedAt(Instant.now());
            refreshTokenRepository.save(oldToken);

            throw new InvalidRefreshTokenException(
                    "User account is not available"
            );
        }


        // ========================================================
        // CREATE NEW REFRESH TOKEN
        // ========================================================

        String newRawToken = generateSecureToken();


        /*
         * IMPORTANT:
         *
         * New token uses the SAME token family.
         *
         * This allows us to detect reuse of an old token.
         */
        RefreshToken newToken =
                buildRefreshToken(
                        user,
                        newRawToken,
                        oldToken.getTokenFamilyId(),
                        ipAddress,
                        userAgent,
                        deviceName
                );


        // ========================================================
        // REVOKE OLD TOKEN
        // ========================================================

        Instant now = Instant.now();
        oldToken.setRevokedAt(now);
        oldToken.setUsedAt(now);
        oldToken.setReplacedBy(newToken);


        // ========================================================
        // SAVE
        // ========================================================

        /*
         * Save the new token first.
         */
        refreshTokenRepository.save(newToken);


        /*
         * Then mark old token as revoked.
         */
        refreshTokenRepository.save(oldToken);


        // ========================================================
        // RETURN
        // ========================================================

        return new RefreshTokenResult(
                newRawToken,
                newToken
        );
    }


    // ============================================================
    // REVOKE SINGLE TOKEN
    // ============================================================

    /**
     * Revokes one refresh token.
     *
     * Used during logout.
     */
    @Transactional
    public User revokeRefreshToken(String rawRefreshToken) {

        /*
         * Logout should be idempotent.
         *
         * If no refresh token is supplied, simply return null.
         */
        if (rawRefreshToken == null ||
                rawRefreshToken.isBlank()) {

            return null;
        }

        String tokenHash = hashToken(rawRefreshToken);

        /*
         * Find the refresh token.
         *
         * We don't throw an exception when the token
         * doesn't exist because logout should be idempotent.
         */
        Optional<RefreshToken> tokenOptional =
                refreshTokenRepository.findByTokenHash(tokenHash);

        if (tokenOptional.isEmpty()) {
            return null;
        }

        RefreshToken refreshToken = tokenOptional.get();

        /*
         * Get the user before modifying the token.
         */
        User user = refreshToken.getUser();

        /*
         * If already revoked, logout is still successful.
         */
        if (refreshToken.isRevoked()) {
            return user;
        }

        /*
         * Revoke this refresh token.
         */
        refreshToken.setRevokedAt(Instant.now());
        refreshTokenRepository.save(refreshToken);

        return user;
    }


    // ============================================================
    // REVOKE ALL USER TOKENS
    // ============================================================

    /**
     * Revokes all active refresh tokens for a user.
     *
     * Useful for:
     *
     * - Logout all devices
     * - Password change
     * - Password reset
     * - Security incident
     */
    @Transactional
    public int revokeAllUserTokens(
            UUID userId) {

        return refreshTokenRepository
                .revokeAllUserTokens(
                        userId,
                        Instant.now()
                );
    }


    // ============================================================
    // REVOKE TOKEN FAMILY
    // ============================================================

    /**
     * Revokes every token belonging to a token family.
     *
     * Used when refresh-token reuse is detected.
     */
    @Transactional
    public int revokeEntireFamily(
            UUID tokenFamilyId) {

        return refreshTokenRepository
                .revokeTokenFamily(
                        tokenFamilyId,
                        Instant.now()
                );
    }


    // ============================================================
    // GENERATE SECURE TOKEN
    // ============================================================

    /**
     * Generates 64 cryptographically secure random bytes.
     *
     * 64 bytes = 512 bits of randomness.
     */
    private String generateSecureToken() {

        byte[] bytes =
                new byte[64];

        secureRandom.nextBytes(bytes);

        return Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }


    // ============================================================
    // HASH TOKEN
    // ============================================================

    /**
     * SHA-256 hash of the refresh token.
     *
     * PostgreSQL stores only this hash.
     */
    public String hashToken(
            String token) {

        try {

            MessageDigest digest =
                    MessageDigest.getInstance(
                            "SHA-256"
                    );

            byte[] hash =
                    digest.digest(
                            token.getBytes(
                                    StandardCharsets.UTF_8
                            )
                    );

            return Base64
                    .getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash);

        } catch (NoSuchAlgorithmException ex) {

            /*
             * SHA-256 is required by every standard
             * Java implementation.
             */
            throw new IllegalStateException(
                    "SHA-256 algorithm unavailable",
                    ex
            );
        }
    }


    // ============================================================
    // BUILD REFRESH TOKEN ENTITY
    // ============================================================

    private RefreshToken buildRefreshToken(
            User user,
            String rawToken,
            UUID tokenFamilyId,
            String ipAddress,
            String userAgent,
            String deviceName) {

        RefreshToken token =
                new RefreshToken();


        token.setUser(user);


        /*
         * Store ONLY hash.
         */
        token.setTokenHash(
                hashToken(rawToken)
        );


        /*
         * Same family during rotation.
         */
        token.setTokenFamilyId(
                tokenFamilyId
        );


        /*
         * Token expiration is configured through:
         *
         * jwt.refresh-token-expiration
         */
        token.setExpiresAt(
                Instant.now()
                        .plusSeconds(
                                jwtProperties
                                        .getRefreshTokenExpiration()
                        )
        );


        token.setCreatedAt(
                Instant.now()
        );


        token.setIpAddress(
                ipAddress
        );


        token.setUserAgent(
                userAgent
        );


        token.setDeviceName(
                deviceName
        );


        return token;
    }


    // ============================================================
    // RESULT
    // ============================================================

    /**
     * Result returned by create/rotate operations.
     *
     * rawToken:
     *     Sent to browser as HttpOnly cookie.
     *
     * refreshToken:
     *     Database entity.
     */
    public record RefreshTokenResult(
            String rawToken,
            RefreshToken refreshToken
    ) {
    }
}