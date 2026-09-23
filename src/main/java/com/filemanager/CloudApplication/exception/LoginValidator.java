package com.filemanager.CloudApplication.exception;

import com.filemanager.CloudApplication.dto.LoginRequest;
import org.springframework.stereotype.Component;

@Component
public class LoginValidator {

    private final EmailValidator emailValidator;

    public LoginValidator(EmailValidator emailValidator) {
        this.emailValidator = emailValidator;
    }

    public void validate(LoginRequest request) {

        if (request == null) {
            throw new ValidationException(
                    "Login request is required"
            );
        }

        emailValidator.validate(request.email());

        if (request.password() == null ||
                request.password().isBlank()) {

            throw new ValidationException(
                    "Password is required"
            );
        }
    }
}

