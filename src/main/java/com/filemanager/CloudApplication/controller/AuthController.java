package com.filemanager.CloudApplication.controller;

import com.filemanager.CloudApplication.authentication.AuthService;
import com.filemanager.CloudApplication.authentication.JwtProperties;
import com.filemanager.CloudApplication.authentication.SecurityUtils;
import com.filemanager.CloudApplication.dto.AuthResponse;
import com.filemanager.CloudApplication.dto.LoginRequest;
import com.filemanager.CloudApplication.dto.LogoutResponse;
import com.filemanager.CloudApplication.dto.RefreshResponse;
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

import java.time.Duration;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    private final AuthService authService;
    private final JwtProperties jwtProperties;

    public AuthController(
            AuthService authService,
            JwtProperties jwtProperties) {

        this.authService = authService;
        this.jwtProperties = jwtProperties;
    }

    /**
     * Register a new user.
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(
            @RequestBody RegisterRequest request) {

        User user = authService.register(request);

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
     * <p>
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
                        jwtProperties.getAccessTokenExpiration(),
                        result.user().getId(),
                        result.user().getUsername(),
                        result.user().getEmail(),
                        getRoleNames(result.user())
                );

        return ResponseEntity.ok(response);
    }

    /**
     * Refresh access token.
     * <p>
     * Refresh token is read from HttpOnly cookie.
     * <p>
     * Old refresh token is revoked.
     * New refresh token is returned as a new cookie.
     */
    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String refreshToken =
                extractRefreshToken(httpRequest);

        String ipAddress =
                extractClientIp(httpRequest);

        String userAgent =
                httpRequest.getHeader("User-Agent");

        String deviceName =
                extractDeviceName(userAgent);

        AuthService.RefreshAuthResult result =
                authService.refresh(
                        refreshToken,
                        ipAddress,
                        userAgent,
                        deviceName
                );

        /*
         * Refresh token rotation.
         *
         * Replace old cookie with new refresh token.
         */
        ResponseCookie refreshCookie =
                createRefreshTokenCookie(
                        result.refreshToken()
                );

        httpResponse.addHeader(
                "Set-Cookie",
                refreshCookie.toString()
        );

        RefreshResponse response =
                new RefreshResponse(
                        result.accessToken(),
                        "Bearer",
                        jwtProperties.getAccessTokenExpiration()
                );

        return ResponseEntity.ok(response);
    }

    /**
     * Logout.
     * <p>
     * Refresh token is revoked in DB.
     * Cookie is deleted from browser.
     */
    @PostMapping("/logout")
    public ResponseEntity<LogoutResponse> logout(
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        String refreshToken = extractRefreshToken(httpRequest);
        String ipAddress = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        authService.logout(
                refreshToken,
                ipAddress,
                userAgent
        );

        /*
         * Delete refresh-token cookie.
         */
        ResponseCookie deleteCookie =
                ResponseCookie
                        .from(
                                REFRESH_TOKEN_COOKIE,
                                ""
                        )
                        .httpOnly(true)
                        .secure(true)
                        .sameSite("None")
                        .path("/api/auth")
                        .maxAge(Duration.ZERO)
                        .build();

        httpResponse.addHeader(
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

        UUID userId = SecurityUtils.getCurrentUserId();
        User user = authService.getCurrentUser(userId);

        UserResponse response =
                new UserResponse(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        getRoleNames(user)
                );

        return ResponseEntity.ok(response);
    }

    /**
     * Create refresh-token cookie.
     */
    private ResponseCookie createRefreshTokenCookie(
            String refreshToken) {

        return ResponseCookie
                .from(
                        REFRESH_TOKEN_COOKIE,
                        refreshToken
                )
                .httpOnly(true)
              //  .secure(true)
                .secure(false)

                /*
                 * React frontend and API are different sites.
                 *
                 * SameSite=None requires Secure=true.
                 */
                //.sameSite("None")
                .sameSite("Lax")
                .path("/api/auth")

                .maxAge(
                        Duration.ofSeconds(
                                jwtProperties
                                        .getRefreshTokenExpiration()
                        )
                )

                .build();
    }

    /**
     * Extract refresh token from cookie.
     */
    private String extractRefreshToken(
            HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {

            if (REFRESH_TOKEN_COOKIE.equals(cookie.getName())) {

                return cookie.getValue();
            }
        }

        return null;
    }

    /**
     * Convert User roles to String list.
     */
    private List<String> getRoleNames(User user) {

        return user.getRoles()
                .stream()
                .map(role -> role.getName())
                .toList();
    }

    /**
     * Extract client IP.
     * <p>
     * Only trust X-Forwarded-For when the application
     * is behind a trusted proxy/load balancer.
     */
    private String extractClientIp(
            HttpServletRequest request) {

        String forwarded = request.getHeader("X-Forwarded-For");

        if (forwarded != null &&
                !forwarded.isBlank()) {

            return forwarded
                    .split(",")[0]
                    .trim();
        }

        return request.getRemoteAddr();
    }

    /**
     * Basic device detection.
     */
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

        if (userAgent.contains("iPad")) {
            return "iPad";
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