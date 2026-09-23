package com.filemanager.CloudApplication.dto;



public record RegisterRequest(
        String username,
        String email,
        String password
) {
}
