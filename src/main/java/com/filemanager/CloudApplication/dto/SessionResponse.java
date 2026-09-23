package com.filemanager.CloudApplication.dto;

import java.time.Instant;
import java.util.UUID;

public record SessionResponse(UUID sessionId,
                              String deviceName,
                              String ipAddress,
                              Instant createdAt,
                              Instant expiresAt) {
}
