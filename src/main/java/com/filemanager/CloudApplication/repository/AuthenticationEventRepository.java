package com.filemanager.CloudApplication.repository;

import com.filemanager.CloudApplication.entity.AuthenticationEvent;
import com.filemanager.CloudApplication.entity.AuthenticationEventType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;
public interface AuthenticationEventRepository
        extends JpaRepository<AuthenticationEvent, UUID> {

    List<AuthenticationEvent> findByUserIdOrderByCreatedAtDesc(
            UUID userId,
            Pageable pageable
    );

    List<AuthenticationEvent> findByUserIdAndEventTypeOrderByCreatedAtDesc(
            UUID userId,
            AuthenticationEventType eventType,
            Pageable pageable
    );
}
