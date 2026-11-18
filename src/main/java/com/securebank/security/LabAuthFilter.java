package com.securebank.security;

import java.io.IOException;
import java.util.List;

import com.securebank.core.LabToggles;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates requests from a {@code Bearer} token.
 *
 * <p><strong>LAB 25 (A10 — Mishandling of Exceptional Conditions).</strong>
 * The catch block swallows token-parsing failures and falls through to a
 * default identity of {@code user_id = 1} — which is the admin user. A
 * deliberately malformed token therefore grants admin access.
 *
 * <p>The default identity is the most dangerous possible value: it looks
 * like a defensive fallback but is actually a privilege escalation.
 *
 * <p><strong>FIX:</strong> never fail open. Return 401 on any invalid token.
 */
public class LabAuthFilter extends OncePerRequestFilter {

    private final LabJwtService jwt;
    private final LabToggles labs;

    public LabAuthFilter(LabJwtService jwt, LabToggles labs) {
        this.jwt = jwt;
        this.labs = labs;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        String header = req.getHeader("Authorization");
        Long userId = null;
        String role = null;
        String username = null;

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7).trim();
            try {
                Claims claims = jwt.parse(token);
                userId = claims.get("user_id", Long.class);
                role = claims.get("role", String.class);
                username = claims.get("username", String.class);
            } catch (LabMalformedTokenException e) {
                // A structurally broken token.
                if (labs.isEnabled("failopen")) {
                    // LAB 25 (VULNERABLE): swallow the error and fall through
                    // to the default identity below.
                    //
                    // FIX: delete this branch and return 401 instead —
                    // authentication must always fail CLOSED.
                    userId = null;
                } else {
                    unauthorized(res);
                    return;
                }
            } catch (JwtException | IllegalArgumentException e) {
                // A signature or algorithm failure (e.g. jjwt rejecting
                // alg:none after the Lab 21 fix). These are always 401 —
                // catching them here is what keeps Labs 21 and 25 independent.
                unauthorized(res);
                return;
            }
        }

        // LAB 25: the dangerous default identity. user_id 1 is the admin user.
        // Only reachable while the failopen lab is armed.
        if (userId == null && labs.isEnabled("failopen")
                && header != null && header.startsWith("Bearer ")) {
            userId = 1L;
            role = "admin";
            username = "admin";
        }

        if (userId != null) {
            String effectiveRole = (role == null ? "customer" : role);
            List<SimpleGrantedAuthority> authorities =
                    List.of(new SimpleGrantedAuthority("ROLE_" + effectiveRole.toUpperCase()));
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            auth.setDetails(userId);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(req, res);
    }

    private void unauthorized(HttpServletResponse res) throws IOException {
        SecurityContextHolder.clearContext();
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        res.setContentType("application/json");
        res.getWriter().write("{\"error\":\"Invalid token\"}");
    }
}
