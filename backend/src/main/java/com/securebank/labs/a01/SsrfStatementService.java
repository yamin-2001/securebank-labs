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
 * callback URL supplied by the caller. The server fetches whatever URL it is
 * given, with no validation at all, and returns the response body.
 *
 * <p>That lets a caller point the server at addresses the caller cannot reach
 * itself: cloud metadata endpoints ({@code 169.254.169.254}), loopback
 * services, or other containers on the internal network.
 */
@Service
public class SsrfStatementService {

    private static final Logger log = LoggerFactory.getLogger(SsrfStatementService.class);

    private final HttpClient http;

    public SsrfStatementService() {
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * "Send" the statement and report what the callback returned.
     *
     * <p><strong>LAB 3 (VULNERABLE):</strong> the URL is fetched as-is.
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

        // The server fetches any URL the caller names.
        body.put("status", "sent");
        body.put("callback_url", callbackUrl);
        body.putAll(fetch(uri));
        return body;
    }

    /**
     * The allowlist check that is not applied.
     *
     * <p>It rejects loopback, link-local (the cloud metadata address) and
     * RFC-1918 private ranges, and only permits the approved hostnames.
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
