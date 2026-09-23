package com.filemanager.CloudApplication.authentication;

import com.filemanager.CloudApplication.dto.LoginRequest;
import com.filemanager.CloudApplication.dto.RegisterRequest;
import com.filemanager.CloudApplication.entity.*;
import com.filemanager.CloudApplication.exception.LoginValidator;
import com.filemanager.CloudApplication.exception.RefreshTokenReuseException;
import com.filemanager.CloudApplication.exception.RegisterValidator;
import com.filemanager.CloudApplication.repository.AuthenticationEventRepository;
import com.filemanager.CloudApplication.repository.RoleRepository;
import com.filemanager.CloudApplication.repository.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class AuthService {

    private static final String DEFAULT_ROLE = "ROLE_USER";

    /*
     * Account locking configuration
     */
    private static final int MAX_FAILED_LOGIN_ATTEMPTS = 5;

    private static final long LOCK_DURATION_MINUTES = 15;

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;

    private final RefreshTokenService refreshTokenService;

    private final AuthenticationEventRepository authenticationEventRepository;

    private final RegisterValidator registerValidator;

    private final LoginValidator loginValidator;


    /*
     * Constructor injection
     *
     * No Lombok required.
     */
    public AuthService(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            RefreshTokenService refreshTokenService,
            AuthenticationEventRepository authenticationEventRepository,
            RegisterValidator registerValidator,
            LoginValidator loginValidator) {

        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
        this.authenticationEventRepository =
                authenticationEventRepository;
        this.registerValidator = registerValidator;
        this.loginValidator = loginValidator;
    }


    // ============================================================
    // REGISTER
    // ============================================================

    @Transactional
    public User register(RegisterRequest request) {

        /*
         * DTO contains no validation annotations.
         * Validation is handled separately.
         */
        registerValidator.validate(request);

        String username =
                normalizeUsername(request.username());

        String email =
                normalizeEmail(request.email());


        /*
         * Check duplicate username.
         */
        if (userRepository
                .existsByUsernameIgnoreCaseAndDeletedAtIsNull(username)) {

            throw new IllegalArgumentException(
                    "Username is already registered"
            );
        }


        /*
         * Check duplicate email.
         */
        if (userRepository
                .existsByEmailIgnoreCaseAndDeletedAtIsNull(email)) {

            throw new IllegalArgumentException(
                    "Email is already registered"
            );
        }


        /*
         * Get default user role.
         */
        Roles userRole = roleRepository
                .findByName(DEFAULT_ROLE)
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Default role is not configured"
                        )
                );


        /*
         * Create user.
         */
        User user = new User();

        user.setUsername(username);

        user.setEmail(email);

        /*
         * NEVER store plain password.
         */
        user.setPasswordHash(
                passwordEncoder.encode(
                        request.password()
                )
        );

        user.setEnabled(true);

        user.setAccountNonLocked(true);

        user.setAccountNonExpired(true);

        user.setCredentialsNonExpired(true);

        user.setFailedLoginAttempts(0);

        user.setLockedUntil(null);

        user.getRoles().add(userRole);


        try {

            User savedUser =
                    userRepository.save(user);


            /*
             * Audit event.
             */
            saveAuthenticationEvent(
                    savedUser,
                    AuthenticationEventType.REGISTER_SUCCESS,
                    true,
                    null,
                    null,
                    "User registered"
            );

            return savedUser;

        } catch (DataIntegrityViolationException ex) {

            /*
             * Protect against concurrent registration
             * race conditions.
             */
            throw new IllegalArgumentException(
                    "Username or email is already registered"
            );
        }
    }


    // ============================================================
    // LOGIN
    // ============================================================

    @Transactional
    public AuthResult login(
            LoginRequest request,
            String ipAddress,
            String userAgent,
            String deviceName) {

        loginValidator.validate(request);

        String email =
                normalizeEmail(request.email());


        /*
         * Find user first so that we can handle
         * failed-login tracking.
         */
        User user = userRepository
                .findByEmailIgnoreCaseAndDeletedAtIsNull(email)
                .orElse(null);


        /*
         * Don't reveal whether the email exists.
         */
        if (user == null) {

            saveAuthenticationEvent(
                    null,
                    AuthenticationEventType.LOGIN_FAILED,
                    false,
                    ipAddress,
                    userAgent,
                    "Invalid credentials"
            );

            throw new BadCredentialsException(
                    "Invalid credentials"
            );
        }


        /*
         * Check whether account is enabled.
         */
        if (!user.isEnabled()) {

            saveAuthenticationEvent(
                    user,
                    AuthenticationEventType.LOGIN_FAILED,
                    false,
                    ipAddress,
                    userAgent,
                    "Account disabled"
            );

            throw new BadCredentialsException(
                    "Invalid credentials"
            );
        }


        /*
         * Check permanent account lock.
         */
        if (!user.isAccountNonLocked()) {

            saveAuthenticationEvent(
                    user,
                    AuthenticationEventType.LOGIN_FAILED,
                    false,
                    ipAddress,
                    userAgent,
                    "Account locked"
            );

            throw new LockedException(
                    "Account is locked"
            );
        }


        /*
         * Check temporary lock.
         */
        if (isTemporarilyLocked(user)) {

            saveAuthenticationEvent(
                    user,
                    AuthenticationEventType.LOGIN_FAILED,
                    false,
                    ipAddress,
                    userAgent,
                    "Account temporarily locked"
            );

            throw new LockedException(
                    "Account is temporarily locked"
            );
        }


        try {

            /*
             * Authenticate email + password.
             */
            Authentication authentication =
                    authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(
                                    email,
                                    request.password()
                            )
                    );


            /*
             * Successful login.
             */
            resetFailedLoginAttempts(user);

            user.setLastLoginAt(
                    Instant.now()
            );

            userRepository.save(user);


            /*
             * Get roles.
             */
            List<String> roles =
                    getRoleNames(user);


            /*
             * Generate access JWT.
             */
            String accessToken =
                    jwtService.generateAccessToken(
                            user.getId(),
                            user.getUsername(),
                            user.getEmail(),
                            roles
                    );


            /*
             * Generate refresh token.
             *
             * Raw token:
             *   returned to controller
             *
             * Hash:
             *   stored in database
             */
            RefreshTokenService.RefreshTokenResult
                    refreshResult =
                    refreshTokenService.createRefreshToken(
                            user,
                            ipAddress,
                            userAgent,
                            deviceName
                    );


            /*
             * Audit successful login.
             */
            saveAuthenticationEvent(
                    user,
                    AuthenticationEventType.LOGIN_SUCCESS,
                    true,
                    ipAddress,
                    userAgent,
                    "Login successful"
            );


            return new AuthResult(
                    accessToken,
                    refreshResult.rawToken(),
                    user
            );

        } catch (BadCredentialsException ex) {

            /*
             * Wrong password.
             */
            handleFailedLogin(
                    user,
                    ipAddress,
                    userAgent
            );

            /*
             * Generic response.
             */
            throw new BadCredentialsException(
                    "Invalid credentials"
            );

        } catch (LockedException ex) {

            saveAuthenticationEvent(
                    user,
                    AuthenticationEventType.LOGIN_FAILED,
                    false,
                    ipAddress,
                    userAgent,
                    "Account locked"
            );

            throw ex;
        }
    }


    // ============================================================
    // REFRESH TOKEN
    // ============================================================

    @Transactional
    public RefreshAuthResult refresh(
            String rawRefreshToken,
            String ipAddress,
            String userAgent,
            String deviceName) {

        try {

            /*
             * RefreshTokenService performs:
             *
             * 1. Hash token
             * 2. SELECT FOR UPDATE
             * 3. Check revoked
             * 4. Check expired
             * 5. Check user status
             * 6. Rotate token
             */
            RefreshTokenService.RefreshTokenResult result =
                    refreshTokenService.rotateRefreshToken(
                            rawRefreshToken,
                            ipAddress,
                            userAgent,
                            deviceName
                    );


            RefreshToken newRefreshToken =
                    result.refreshToken();


            User user =
                    newRefreshToken.getUser();


            /*
             * Get user's roles.
             */
            List<String> roles =
                    getRoleNames(user);


            /*
             * Generate new access token.
             */
            String accessToken =
                    jwtService.generateAccessToken(
                            user.getId(),
                            user.getUsername(),
                            user.getEmail(),
                            roles
                    );


            /*
             * Audit refresh success.
             */
            saveAuthenticationEvent(
                    user,
                    AuthenticationEventType.REFRESH_SUCCESS,
                    true,
                    ipAddress,
                    userAgent,
                    "Refresh token rotated"
            );


            return new RefreshAuthResult(
                    accessToken,
                    result.rawToken(),
                    user
            );

        } catch (RefreshTokenReuseException ex) {

            /*
             * RefreshTokenService has already revoked
             * the entire token family.
             */
            saveAuthenticationEvent(
                    null,
                    AuthenticationEventType.REFRESH_TOKEN_REUSE,
                    false,
                    ipAddress,
                    userAgent,
                    "Refresh token reuse detected"
            );

            throw ex;

        } catch (Throwable ex) {

            saveAuthenticationEvent(
                    null,
                    AuthenticationEventType.REFRESH_FAILED,
                    false,
                    ipAddress,
                    userAgent,
                    "Invalid refresh token"
            );

            throw ex;
        }
    }


    // ============================================================
    // LOGOUT
    // ============================================================

    @Transactional
    public void logout(
            String rawRefreshToken,
            String ipAddress,
            String userAgent) {

        /*
         * Logout should be idempotent.
         */
        if (rawRefreshToken == null
                || rawRefreshToken.isBlank()) {

            return;
        }


        /*
         * Revoke refresh token in DB.
         */
        refreshTokenService.revokeRefreshToken(
                rawRefreshToken
        );


        /*
         * Audit event.
         */
        saveAuthenticationEvent(
                null,
                AuthenticationEventType.LOGOUT,
                true,
                ipAddress,
                userAgent,
                "User logged out"
        );
    }


    // ============================================================
    // GET CURRENT USER
    // ============================================================

    @Transactional(readOnly = true)
    public User getCurrentUser(UUID userId) {

        return userRepository
                .findById(userId)
                .filter(
                        user -> user.getDeletedAt() == null
                )
                .orElseThrow(() ->
                        new UsernameNotFoundException(
                                "User not found"
                        )
                );
    }


    // ============================================================
    // FAILED LOGIN HANDLING
    // ============================================================

    private void handleFailedLogin(
            User user,
            String ipAddress,
            String userAgent) {

        int attempts =
                user.getFailedLoginAttempts() + 1;


        user.setFailedLoginAttempts(
                attempts
        );


        /*
         * Lock account after 5 failures.
         */
        if (attempts >= MAX_FAILED_LOGIN_ATTEMPTS) {

            Instant lockedUntil =
                    Instant.now()
                            .plusSeconds(
                                    LOCK_DURATION_MINUTES * 60
                            );


            user.setLockedUntil(
                    lockedUntil
            );


            saveAuthenticationEvent(
                    user,
                    AuthenticationEventType.ACCOUNT_LOCKED,
                    true,
                    ipAddress,
                    userAgent,
                    "Account temporarily locked after "
                            + attempts
                            + " failed login attempts"
            );
        }


        userRepository.save(user);


        /*
         * Audit failed login.
         */
        saveAuthenticationEvent(
                user,
                AuthenticationEventType.LOGIN_FAILED,
                false,
                ipAddress,
                userAgent,
                "Invalid credentials"
        );
    }


    // ============================================================
    // RESET FAILED LOGIN ATTEMPTS
    // ============================================================

    private void resetFailedLoginAttempts(
            User user) {

        user.setFailedLoginAttempts(0);

        user.setLockedUntil(null);
    }


    // ============================================================
    // TEMPORARY LOCK CHECK
    // ============================================================

    private boolean isTemporarilyLocked(
            User user) {

        if (user.getLockedUntil() == null) {
            return false;
        }


        /*
         * Still locked.
         */
        if (user.getLockedUntil()
                .isAfter(Instant.now())) {

            return true;
        }


        /*
         * Lock expired.
         *
         * Automatically unlock.
         */
        user.setLockedUntil(null);

        user.setFailedLoginAttempts(0);

        userRepository.save(user);

        return false;
    }


    // ============================================================
    // GET ROLE NAMES
    // ============================================================

    private List<String> getRoleNames(
            User user) {

        return user.getRoles()
                .stream()
                .map(Roles::getName)
                .sorted()
                .toList();
    }


    // ============================================================
    // NORMALIZE EMAIL
    // ============================================================

    private String normalizeEmail(
            String email) {

        return email
                .trim()
                .toLowerCase(Locale.ROOT);
    }


    // ============================================================
    // NORMALIZE USERNAME
    // ============================================================

    private String normalizeUsername(
            String username) {

        return username.trim();
    }


    // ============================================================
    // AUDIT EVENT
    // ============================================================

    private void saveAuthenticationEvent(
            User user,
            AuthenticationEventType eventType,
            boolean success,
            String ipAddress,
            String userAgent,
            String details) {

        AuthenticationEvent event =
                new AuthenticationEvent();


        event.setUser(user);

        event.setEventType(eventType);

        event.setSuccess(success);

        event.setIpAddress(ipAddress);

        event.setUserAgent(userAgent);

        event.setDetails(details);

        event.setCreatedAt(
                Instant.now()
        );


        authenticationEventRepository.save(
                event
        );
    }


    // ============================================================
    // RESULT OBJECTS
    // ============================================================

    public record AuthResult(
            String accessToken,
            String refreshToken,
            User user
    ) {
    }


    public record RefreshAuthResult(
            String accessToken,
            String refreshToken,
            User user
    ) {
    }
}