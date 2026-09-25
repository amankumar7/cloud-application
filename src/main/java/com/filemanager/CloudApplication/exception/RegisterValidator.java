package com.filemanager.CloudApplication.exception;

import com.filemanager.CloudApplication.dto.RegisterRequest;
import org.springframework.stereotype.Component;

@Component
public class RegisterValidator {

    private final EmailValidator emailValidator;
    private final PasswordValidator passwordValidator;
    private final UsernameValidator usernameValidator;

    public RegisterValidator(
            EmailValidator emailValidator,
            PasswordValidator passwordValidator,
            UsernameValidator usernameValidator) {

        this.emailValidator = emailValidator;
        this.passwordValidator = passwordValidator;
        this.usernameValidator = usernameValidator;
    }

    public void validate(RegisterRequest request) {

        if (request == null) {
            throw new ValidationException(
                    "Registration request is required"
            );
        }

        usernameValidator.validate(request.username());
        emailValidator.validate(request.email());
        passwordValidator.validate(request.password());
    }
}
