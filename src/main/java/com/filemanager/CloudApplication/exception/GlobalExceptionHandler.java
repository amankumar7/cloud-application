package com.filemanager.CloudApplication.exception;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // ============================================================
    // VALIDATION EXCEPTION
    // ============================================================

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
            ValidationException ex,
            HttpServletRequest request) {

        ErrorResponse response =
                new ErrorResponse(
                        Instant.now(),
                        HttpStatus.BAD_REQUEST.value(),
                        "Bad Request",
                        ex.getMessage(),
                        request.getRequestURI(),
                        ex.getErrors()
                );

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(response);
    }


    // ============================================================
    // BAD CREDENTIALS
    // ============================================================

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
            BadCredentialsException ex,
            HttpServletRequest request) {

        /*
         * Don't expose whether:
         *
         * - email exists
         * - password was wrong
         * - account exists
         */
        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.UNAUTHORIZED,
                        "Unauthorized",
                        "Invalid credentials",
                        request
                );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(response);
    }


    // ============================================================
    // ACCOUNT LOCKED
    // ============================================================

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ErrorResponse> handleLockedException(
            LockedException ex,
            HttpServletRequest request) {

        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.LOCKED,
                        "Account Locked",
                        "Account is temporarily locked",
                        request
                );

        return ResponseEntity
                .status(HttpStatus.LOCKED)
                .body(response);
    }


    // ============================================================
    // INVALID REFRESH TOKEN
    // ============================================================

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRefreshToken(
            InvalidRefreshTokenException ex,
            HttpServletRequest request) {

        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.UNAUTHORIZED,
                        "Unauthorized",
                        "Invalid or expired refresh token",
                        request
                );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(response);
    }


    // ============================================================
    // REFRESH TOKEN REUSE
    // ============================================================

    @ExceptionHandler(RefreshTokenReuseException.class)
    public ResponseEntity<ErrorResponse> handleRefreshTokenReuse(
            RefreshTokenReuseException ex,
            HttpServletRequest request) {

        /*
         * Don't expose internal token-family details.
         */
        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.UNAUTHORIZED,
                        "Unauthorized",
                        "Session expired. Please login again.",
                        request
                );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(response);
    }


    // ============================================================
    // ACCESS DENIED
    // ============================================================

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex,
            HttpServletRequest request) {

        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.FORBIDDEN,
                        "Forbidden",
                        "You do not have permission to access this resource",
                        request
                );

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(response);
    }


    // ============================================================
    // AUTHENTICATION EXCEPTION
    // ============================================================

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex,
            HttpServletRequest request) {

        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.UNAUTHORIZED,
                        "Unauthorized",
                        "Authentication required",
                        request
                );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(response);
    }


    // ============================================================
    // ILLEGAL ARGUMENT
    // ============================================================

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
            IllegalArgumentException ex,
            HttpServletRequest request) {

        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.BAD_REQUEST,
                        "Bad Request",
                        ex.getMessage(),
                        request
                );

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(response);
    }


    // ============================================================
    // USER NOT FOUND
    // ============================================================

    @ExceptionHandler(
            org.springframework.security.core.userdetails
                    .UsernameNotFoundException.class
    )
    public ResponseEntity<ErrorResponse> handleUserNotFound(
            org.springframework.security.core.userdetails
                    .UsernameNotFoundException ex,
            HttpServletRequest request) {

        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.NOT_FOUND,
                        "Not Found",
                        "User not found",
                        request
                );

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(response);
    }


    // ============================================================
    // GENERIC EXCEPTION
    // ============================================================

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex,
            HttpServletRequest request) {

        /*
         * Don't return ex.getMessage() to the client.
         *
         * Internal database/security details should never
         * be exposed.
         */
        ErrorResponse response =
                createErrorResponse(
                        HttpStatus.INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        "An unexpected error occurred",
                        request
                );

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(response);
    }


    // ============================================================
    // ERROR RESPONSE HELPER
    // ============================================================

    private ErrorResponse createErrorResponse(
            HttpStatus status,
            String error,
            String message,
            HttpServletRequest request) {

        return new ErrorResponse(
                Instant.now(),
                status.value(),
                error,
                message,
                request.getRequestURI(),
                Collections.emptyMap()
        );
    }
}
