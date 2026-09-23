package com.filemanager.CloudApplication.exception;

import org.springframework.stereotype.Component;

@Component
public class PasswordValidator {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 128;

    public void validate(String password) {

        if (password == null || password.isBlank()) {
            throw new ValidationException(
                    "Password is required"
            );
        }

        if (password.length() < MIN_LENGTH) {
            throw new ValidationException(
                    "Password must contain at least "
                            + MIN_LENGTH + " characters"
            );
        }

        if (password.length() > MAX_LENGTH) {
            throw new ValidationException(
                    "Password cannot exceed "
                            + MAX_LENGTH + " characters"
            );
        }

        if (password.chars().noneMatch(Character::isUpperCase)) {
            throw new ValidationException(
                    "Password must contain an uppercase letter"
            );
        }

        if (password.chars().noneMatch(Character::isLowerCase)) {
            throw new ValidationException(
                    "Password must contain a lowercase letter"
            );
        }

        if (password.chars().noneMatch(Character::isDigit)) {
            throw new ValidationException(
                    "Password must contain a number"
            );
        }
    }
}
