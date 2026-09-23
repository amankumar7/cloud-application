package com.filemanager.CloudApplication.dto;

public record RefreshResponse(  String accessToken,
                                String tokenType,
                                long expiresIn) {
}
