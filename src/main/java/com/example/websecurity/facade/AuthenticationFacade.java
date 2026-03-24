package com.example.websecurity.facade;

import com.example.websecurity.api.dto.AuthenticationRequest;
import com.example.websecurity.api.dto.AuthenticationResponse;
import com.example.websecurity.persistence.User;
import com.example.websecurity.security.JwtService;
import com.example.websecurity.service.UserService;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFacade {

    private static final int MAX_FAILED_ATTEMPTS = 3;
    private static final long LOCK_TIME_MS = 30_000;

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserService userService;

    private final PasswordEncoder passwordEncoder;

    private final List<LoginAttempt> loginAttempts = new ArrayList<>();

    @Transactional
    public AuthenticationResponse authenticate(@NotNull AuthenticationRequest request) {
        log.info("Authentication Facade: Authenticating user with request: {}", request);
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = userService.getUserByEmail(request.getEmail());
        var accessToken = jwtService.generateAccessToken(user);
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .build();
    }

    public AuthenticationResponse authenticateVuln(AuthenticationRequest request) {
        String email = request.getEmail();
        LoginAttempt loginAttempt = findLoginAttempt(email);
        if (loginAttempt != null && loginAttempt.lockedUntil > 0) {
            long now = System.currentTimeMillis();
            if (now < loginAttempt.lockedUntil) {
                long secondsLeft = (loginAttempt.lockedUntil - now) / 1000;
                if (secondsLeft < 1) {
                    secondsLeft = 1;
                }
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Login is blocked. Try again in " + secondsLeft + " seconds");
            }
            loginAttempt.failedCount = 0;
            loginAttempt.lockedUntil = 0;
        }

        User user = userService.getUserByEmail(email);
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            if (loginAttempt == null) {
                loginAttempt = new LoginAttempt();
                loginAttempt.email = email;
                loginAttempts.add(loginAttempt);
            }

            loginAttempt.failedCount++;
            if (loginAttempt.failedCount >= MAX_FAILED_ATTEMPTS) {
                loginAttempt.lockedUntil = System.currentTimeMillis() + LOCK_TIME_MS;
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Login is blocked for 30 seconds");
            }
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        if (loginAttempt != null) {
            loginAttempt.failedCount = 0;
            loginAttempt.lockedUntil = 0;
        }
        var accessToken = jwtService.generateAccessToken(user);
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .build();
    }

    private LoginAttempt findLoginAttempt(String email) {
        for (LoginAttempt loginAttempt : loginAttempts) {
            if (loginAttempt.email.equals(email)) {
                return loginAttempt;
            }
        }
        return null;
    }

    private static class LoginAttempt {
        String email;
        int failedCount;
        long lockedUntil;
    }
}
