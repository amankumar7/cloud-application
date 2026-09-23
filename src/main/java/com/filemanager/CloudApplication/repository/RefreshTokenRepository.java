package com.filemanager.CloudApplication.repository;

import com.filemanager.CloudApplication.entity.RefreshToken;
import com.filemanager.CloudApplication.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.filemanager.CloudApplication.entity.RefreshToken;
import com.filemanager.CloudApplication.entity.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        SELECT r
        FROM RefreshToken r
        WHERE r.tokenHash = :tokenHash
    """)
    Optional<RefreshToken> findByTokenHashForUpdate(
            @Param("tokenHash") String tokenHash
    );

    List<RefreshToken> findByUserAndRevokedAtIsNull(User user);

    List<RefreshToken> findByUserIdAndRevokedAtIsNull(UUID userId);

    List<RefreshToken> findByTokenFamilyId(UUID tokenFamilyId);

    Optional<RefreshToken> findByIdAndUserId(
            UUID id,
            UUID userId
    );

    @Modifying
    @Query("""
        UPDATE RefreshToken r
        SET r.revokedAt = :revokedAt
        WHERE r.user.id = :userId
          AND r.revokedAt IS NULL
    """)
    int revokeAllUserTokens(
            @Param("userId") UUID userId,
            @Param("revokedAt") Instant revokedAt
    );

    @Modifying
    @Query("""
        UPDATE RefreshToken r
        SET r.revokedAt = :revokedAt
        WHERE r.tokenFamilyId = :familyId
          AND r.revokedAt IS NULL
    """)
    int revokeTokenFamily(
            @Param("familyId") UUID familyId,
            @Param("revokedAt") Instant revokedAt
    );

    @Modifying
    @Query("""
        DELETE FROM RefreshToken r
        WHERE r.expiresAt < :now
    """)
    int deleteExpiredTokens(@Param("now") Instant now);
}