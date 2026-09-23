package com.filemanager.CloudApplication.dto;

public record LoginRequest(
        String email,
        String password
) {
}
