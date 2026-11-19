package com.securebank.labs.a01;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * <strong>LAB 3 (A01 — Broken Access Control): SSRF.</strong>
 *
 * <p>The "email me my statement" feature posts the rendered statement to a
 * callback URL supplied by the caller.
 *
 * <p><strong>FIXED:</strong> the callback URL is checked against an
 * allowlist before the request goes out — see {@link #isAllowedCallback(URI)}.
 * Loopback, link-local (the cloud metadata address) and RFC-1918 private
 * ranges are all refused, and redirects are not followed so the allowlist
 * cannot be stepped around with a 302.
 *
 * <p>Better still, do not accept a callback URL from the user at all: the
 * statement should be emailed to the address already on file.
 */
@Service
public class SsrfStatementService {

    private static final Logger log = LoggerFactory.getLogger(SsrfStatementService.class);

    private final HttpClient http;

    public SsrfStatementService() {
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                // Redirects are not followed. An allowlisted host that answers
                // with a 302 to a private address would otherwise walk the
                // request straight past the allowlist.
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * "Send" the statement and report what the callback returned.
     *
     * <p><strong>LAB 3 (FIXED):</strong> the URL is checked against the
     * allowlist before it is fetched.
     */
    public Map<String, Object> sendStatement(Long accountId, String callbackUrl) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("account_id", accountId);

        URI uri;
        try {
            uri = URI.create(callbackUrl == null ? "" : callbackUrl);
        } catch (IllegalArgumentException e) {
            body.put("status", "rejected");
            body.put("error", "callback_url is not a valid URL");
            return body;
        }

        // FIXED: the callback URL is checked against the allowlist before the
        // request goes out.
        if (!isAllowedCallback(uri)) {
            body.put("status", "rejected");
            body.put("error", "callback_url is not on the approved list");
            return body;
        }
        body.put("status", "sent");
        body.put("callback_url", callbackUrl);
        body.putAll(fetch(uri));
        return body;
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>Allowlist check for outbound callback URLs. Rejects loopback,
     * link-local (the cloud metadata address) and RFC-1918 private ranges,
     * and only permits the approved hostnames.
     */
    public boolean isAllowedCallback(URI uri) {
        if (uri == null || uri.getHost() == null) {
            return false;
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            return false;
        }
        String host = uri.getHost().toLowerCase();
        if (!ALLOWED_HOSTS.contains(host)) {
            return false;
        }
        String ip = host;
        if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.")
                || ip.startsWith("169.254.") || ip.startsWith("0.")) {
            return false;
        }
        if (ip.startsWith("172.")) {
            try {
                int second = Integer.parseInt(ip.split("\\.")[1]);
                if (second >= 16 && second <= 31) {
                    return false;
                }
            } catch (NumberFormatException | ArrayIndexOutOfBoundsException ignored) {
                return false;
            }
        }
        return true;
    }

    /** The hosts this feature is allowed to talk to. */
    private static final java.util.Set<String> ALLOWED_HOSTS = java.util.Set.of(
            "statements.securebank.test",
            "mail.securebank.test");

    /** Fetch the URL and return a small summary of the response. */
    private Map<String, Object> fetch(URI uri) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "SecureBank-Statement/1.0")
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            out.put("callback_status", response.statusCode());
            out.put("callback_body", truncate(response.body()));
        } catch (IOException e) {
            out.put("callback_status", 0);
            out.put("callback_error", e.getClass().getSimpleName() + ": " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            out.put("callback_status", 0);
            out.put("callback_error", "interrupted");
        }
        return out;
    }

    private String truncate(String body) {
        if (body == null) {
            return null;
        }
        return body.length() > 4000 ? body.substring(0, 4000) + "...[truncated]" : body;
    }
}
