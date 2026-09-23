package com.filemanager.CloudApplication.controller;


import com.filemanager.CloudApplication.authentication.AuthService;
import com.filemanager.CloudApplication.authentication.SecurityUtils;
import com.filemanager.CloudApplication.dto.AuthResponse;
import com.filemanager.CloudApplication.dto.LoginRequest;
import com.filemanager.CloudApplication.dto.LogoutResponse;
import com.filemanager.CloudApplication.dto.RegisterRequest;
import com.filemanager.CloudApplication.dto.UserResponse;
import com.filemanager.CloudApplication.entity.User;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String REFRESH_TOKEN_COOKIE =
            "refresh_token";

    private static final long ACCESS_TOKEN_EXPIRATION =
            900L;

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Register a new user.
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @RequestBody RegisterRequest request) {

        User user =
                authService.register(request);

        UserResponse response =
                new UserResponse(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        getRoleNames(user)
                );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    /**
     * Login.
     *
     * Access token -> JSON response
     * Refresh token -> HttpOnly cookie
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String ipAddress =
                extractClientIp(httpRequest);

        String userAgent =
                httpRequest.getHeader("User-Agent");

        String deviceName =
                extractDeviceName(userAgent);

        AuthService.AuthResult result =
                authService.login(
                        request,
                        ipAddress,
                        userAgent,
                        deviceName
                );

        ResponseCookie refreshCookie =
                createRefreshTokenCookie(
                        result.refreshToken()
                );

        httpResponse.addHeader(
                "Set-Cookie",
                refreshCookie.toString()
        );

        AuthResponse response =
                new AuthResponse(
                        result.accessToken(),
                        "Bearer",
                        ACCESS_TOKEN_EXPIRATION,
                        result.user().getId(),
                        result.user().getUsername(),
                        result.user().getEmail(),
                        getRoleNames(result.user())
                );

        return ResponseEntity.ok(response);
    }

    /**
     * Logout.
     *
     * The actual refresh-token revocation will be implemented
     * in RefreshTokenService.
     */
    @PostMapping("/logout")
    public ResponseEntity<LogoutResponse> logout(
            HttpServletResponse response) {

        ResponseCookie deleteCookie =
                ResponseCookie
                        .from(
                                REFRESH_TOKEN_COOKIE,
                                ""
                        )
                        .httpOnly(true)
                        .secure(true)
                        .sameSite("Strict")
                        .path("/api/auth")
                        .maxAge(0)
                        .build();

        response.addHeader(
                "Set-Cookie",
                deleteCookie.toString()
        );

        return ResponseEntity.ok(
                new LogoutResponse(
                        "Logged out successfully"
                )
        );
    }

    /**
     * Get currently authenticated user.
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> me() {

        UUID userId =
                SecurityUtils.getCurrentUserId();

        return ResponseEntity.ok(
                new UserResponse(
                        userId,
                        null,
                        null,
                        List.of()
                )
        );
    }

    private ResponseCookie createRefreshTokenCookie(
            String refreshToken) {

        return ResponseCookie
                .from(
                        REFRESH_TOKEN_COOKIE,
                        refreshToken
                )
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/api/auth")
                .maxAge(7 * 24 * 60 * 60)
                .build();
    }

    private List<String> getRoleNames(User user) {

        return user.getRoles()
                .stream()
                .map(role -> role.getName())
                .toList();
    }

    private String extractClientIp(
            HttpServletRequest request) {

        /*
         * IMPORTANT:
         *
         * Only trust X-Forwarded-For when your application
         * is behind a trusted proxy/load balancer that
         * overwrites this header.
         */

        String forwarded =
                request.getHeader("X-Forwarded-For");

        if (forwarded != null &&
                !forwarded.isBlank()) {

            return forwarded
                    .split(",")[0]
                    .trim();
        }

        return request.getRemoteAddr();
    }

    private String extractDeviceName(
            String userAgent) {

        if (userAgent == null ||
                userAgent.isBlank()) {

            return "Unknown";
        }

        if (userAgent.contains("Android")) {
            return "Android";
        }

        if (userAgent.contains("iPhone")) {
            return "iPhone";
        }

        if (userAgent.contains("Windows")) {
            return "Windows";
        }

        if (userAgent.contains("Macintosh")) {
            return "Mac";
        }

        if (userAgent.contains("Linux")) {
            return "Linux";
        }

        return "Unknown";
    }
}
