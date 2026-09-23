package com.filemanager.CloudApplication.exception;

import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class EmailValidator {

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile(
                    "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$"
            );

    public void validate(String email) {

        if (email == null || email.isBlank()) {
            throw new ValidationException(
                    "Email is required"
            );
        }

        email = email.trim();

        if (email.length() > 255) {
            throw new ValidationException(
                    "Email cannot exceed 255 characters"
            );
        }

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new ValidationException(
                    "Invalid email format"
            );
        }
    }
}
