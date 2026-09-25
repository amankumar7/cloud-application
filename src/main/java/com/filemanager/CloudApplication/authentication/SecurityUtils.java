package com.filemanager.CloudApplication.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.UUID;

public final class SecurityUtils {

    private SecurityUtils() {
    }

    public static Authentication getAuthentication() {

        return SecurityContextHolder
                .getContext()
                .getAuthentication();
    }

    public static UUID getCurrentUserId() {

        Authentication authentication = getAuthentication();

        if (authentication == null ||
                !authentication.isAuthenticated()) {

            throw new IllegalStateException("No authenticated user");

        }

        return UUID.fromString(authentication.getName());
    }

    public static Jwt getCurrentJwt() {

        Authentication authentication = getAuthentication();

        if (authentication == null) {
            throw new IllegalStateException(
                    "No authenticated user"
            );
        }

        return (Jwt) authentication.getDetails();
    }
}
