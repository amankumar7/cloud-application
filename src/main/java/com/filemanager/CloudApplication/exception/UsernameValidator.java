package com.filemanager.CloudApplication.exception;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class UsernameValidator {

    private static final Pattern USERNAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9._-]+$");

    public void validate(String username) {

        if (username == null || username.isBlank()) {
            throw new ValidationException(
                    "Username is required"
            );
        }

        username = username.trim();

        if (username.length() < 3 || username.length() > 50) {
            throw new ValidationException(
                    "Username must be between 3 and 50 characters"
            );
        }

        if (!USERNAME_PATTERN.matcher(username).matches()) {
            throw new ValidationException(
                    "Username can contain only letters, numbers, '.', '_' and '-'"
            );
        }
    }
}
