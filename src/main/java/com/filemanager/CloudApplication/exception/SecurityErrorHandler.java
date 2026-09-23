package com.filemanager.CloudApplication.exception;

import com.filemanager.CloudApplication.exception.ErrorResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;

@Component
public class SecurityErrorHandler
        implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    public SecurityErrorHandler(
            ObjectMapper objectMapper) {

        this.objectMapper = objectMapper;
    }


    // ============================================================
    // 401 - UNAUTHENTICATED
    // ============================================================

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException)
            throws IOException {

        ErrorResponse errorResponse =
                new ErrorResponse(
                        Instant.now(),
                        HttpStatus.UNAUTHORIZED.value(),
                        "Unauthorized",
                        "Authentication required",
                        request.getRequestURI(),
                        Collections.emptyMap()
                );

        writeResponse(
                response,
                HttpStatus.UNAUTHORIZED,
                errorResponse
        );
    }


    // ============================================================
    // 403 - FORBIDDEN
    // ============================================================

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException)
            throws IOException {

        ErrorResponse errorResponse =
                new ErrorResponse(
                        Instant.now(),
                        HttpStatus.FORBIDDEN.value(),
                        "Forbidden",
                        "You do not have permission to access this resource",
                        request.getRequestURI(),
                        Collections.emptyMap()
                );

        writeResponse(
                response,
                HttpStatus.FORBIDDEN,
                errorResponse
        );
    }


    // ============================================================
    // WRITE JSON RESPONSE
    // ============================================================

    private void writeResponse(
            HttpServletResponse response,
            HttpStatus status,
            ErrorResponse errorResponse)
            throws IOException {

        response.setStatus(
                status.value()
        );

        response.setContentType(
                MediaType.APPLICATION_JSON_VALUE
        );

        response.setCharacterEncoding(
                "UTF-8"
        );

        objectMapper.writeValue(
                response.getWriter(),
                errorResponse
        );
    }
}
