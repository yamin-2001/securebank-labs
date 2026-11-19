package com.securebank.labs.a07;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

/**
 * <strong>LAB 17 (A07 — Identification and Authentication Failures): no rate
 * limiting on the login endpoint.</strong>
 *
 * <p>Failed logins are counted here — but nothing ever reads the count. The
 * service exists so that the lab has a single, obvious fix location: make
 * {@link #applyRateLimit(String)} do its job.
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
     * <p>On the vulnerable build this only <em>checks</em> and never refuses.
     * Counting happens on the failure path and clearing happens on the
     * success path, so the counter reflects genuine failures — a user who
     * logs in successfully has not failed, and their budget is restored.
     *
     * <p><strong>LAB 17 (VULNERABLE):</strong> nothing is counted and nothing
     * is refused.
     */
    public void applyRateLimit(String username) {
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
