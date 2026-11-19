package com.securebank.labs.a07;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

/**
 * <strong>LAB 17 (A07 — Identification and Authentication Failures): rate
 * limiting on the login endpoint.</strong>
 *
 * <p><strong>FIXED.</strong> Failed logins used to be counted here but
 * nothing ever read the count, so a brute-force loop could guess a weak
 * password in seconds. {@link #applyRateLimit(String)} now refuses the
 * request once the account has spent its budget, and the login endpoint
 * records failures and clears them on success.
 *
 * <p>The counters live in memory. That is fine for a lab; a real deployment
 * needs a shared store so the limit holds across instances.
 */
@Service
public class LoginAttemptService {

    /** How many failed attempts an account gets before it is locked out. */
    public static final int MAX_ATTEMPTS = 5;

    /** How long an account stays locked out, in seconds. */
    public static final long LOCKOUT_SECONDS = 300;

    private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();

    public LoginAttemptService() {
    }

    /**
     * Is this account currently locked out?
     *
     * <p><strong>FIX:</strong> return the real state — the counter for this
     * username, compared against {@link #MAX_ATTEMPTS} and the lockout
     * window.
     */
    public boolean isBlocked(String username) {
        Attempt attempt = attempts.get(key(username));
        if (attempt == null) {
            return false;
        }
        return attempt.failures >= MAX_ATTEMPTS
                && attempt.lastFailureSeconds > now() - LOCKOUT_SECONDS;
    }

    /**
     * Record a failed login attempt.
     *
     * <p><strong>FIX:</strong> increment the counter for this username and
     * stamp the time.
     */
    public void recordFailure(String username) {
        attempts.compute(key(username), (k, existing) -> {
            Attempt attempt = existing == null ? new Attempt() : existing;
            attempt.failures++;
            attempt.lastFailureSeconds = now();
            return attempt;
        });
    }

    /**
     * Record a successful login — clears the counter.
     *
     * <p><strong>FIX:</strong> remove the counter for this username.
     */
    public void recordSuccess(String username) {
        attempts.remove(key(username));
    }

    /** The number of consecutive failures recorded for an account. */
    public int failureCount(String username) {
        Attempt attempt = attempts.get(key(username));
        return attempt == null ? 0 : attempt.failures;
    }

    /**
     * Apply the rate limit.
     *
     * <p>This is the whole fix in one place: the login endpoint calls it
     * before authenticating, and it throws when the account has spent its
     * budget.
     *
     * <p>It only <em>checks</em>. Counting happens on the failure path and
     * clearing happens on the success path, so the counter reflects genuine
     * failures — a user who logs in successfully has not failed, and their
     * budget is restored.
     */
    public void applyRateLimit(String username) {
        if (isBlocked(username)) {
            throw new TooManyAttemptsException(username);
        }
    }

    /** The current time in seconds — the lockout window is measured in these. */
    private long now() {
        return System.currentTimeMillis() / 1000;
    }

    /** The key the attempts are tracked under. */
    private String key(String username) {
        return username == null ? "" : username.toLowerCase();
    }

    /** Thrown when an account has spent its attempt budget. */
    public static class TooManyAttemptsException extends RuntimeException {
        public TooManyAttemptsException(String username) {
            super("Too many failed login attempts for " + username);
        }
    }

    /** Per-account attempt state. */
    private static final class Attempt {
        private int failures;
        private long lastFailureSeconds;
    }
}
