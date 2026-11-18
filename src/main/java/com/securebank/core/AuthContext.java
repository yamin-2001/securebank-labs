package com.securebank.core;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The caller's identity for the current request.
 *
 * <p>Reads from Spring Security's {@code SecurityContextHolder}, which
 * {@code LabAuthFilter} populates. The user id is carried as the
 * authentication's details (a {@code Long}).
 */
public final class AuthContext {

    private AuthContext() {
    }

    /** The authenticated user's id, or empty if the request is unauthenticated. */
    public static Optional<Long> userId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return Optional.empty();
        }
        Object details = auth.getDetails();
        if (details instanceof Long id) {
            return Optional.of(id);
        }
        return Optional.empty();
    }

    /** The authenticated user's name, or empty. */
    public static Optional<String> username() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return Optional.empty();
        }
        return Optional.ofNullable(auth.getName());
    }

    /** The authenticated user's role, or empty. */
    public static Optional<String> role() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth.getAuthorities().isEmpty()) {
            return Optional.empty();
        }
        String authority = auth.getAuthorities().iterator().next().getAuthority();
        return Optional.of(authority.startsWith("ROLE_") ? authority.substring(5) : authority);
    }
}
