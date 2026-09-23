package com.filemanager.CloudApplication.dto;

import java.util.List;
import java.util.UUID;

public record AuthResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        UUID userId,
        String username,
        String email,
        List<String> roles
) {
}
