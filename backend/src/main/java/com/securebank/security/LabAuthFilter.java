package com.securebank.security;

import java.io.IOException;
import java.util.List;

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
 * <p><strong>LAB 25 (A10 — Mishandling of Exceptional Conditions).
 * <strong>FIXED.</strong> The filter's job is to establish an identity from
 * a token. It used to be that when it could not, the failure was swallowed
 * and the request continued with a <em>default identity</em> of
 * {@code user_id = 1} — which is the admin user. A deliberately malformed
 * token therefore granted admin access.
 *
 * <p>The default identity was the most dangerous possible value: it looked
 * like a defensive fallback but was actually a privilege escalation. A
 * fallback that assumes "the admin" when you cannot prove who the caller
 * is, is not a fallback at all.
 *
 * <p>The filter now never fails open. If the token cannot be turned into an
 * identity, the request is unauthenticated — 401.
 *
 * <p><strong>How this stays independent of Lab 21:</strong> the fail-open
 * branch is reached when the token was <em>accepted but named no
 * identity</em> — a token whose {@code user_id} claim is absent or null.
 * The parser succeeded, so it does not matter which parser ran: Lab 21's
 * fix (switching to jjwt) leaves this branch exactly as it is, and Lab
 * 25's fix does not change how tokens are parsed.
 */
public class LabAuthFilter extends OncePerRequestFilter {

    private final LabJwtService jwt;

    public LabAuthFilter(LabJwtService jwt) {
        this.jwt = jwt;
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
                // A structurally broken token. This is a parse failure, so it
                // is always 401 — it is not the Lab 25 fail-open path.
                //
                // The exception type exists to keep Lab 21 and Lab 25
                // independent: the hand-rolled parser throws it, and the
                // hand-rolled parser is what Lab 21 fixes. Rejecting it here
                // means fixing Lab 21 does not change Lab 25's behaviour.
                unauthorized(res);
                return;
            } catch (JwtException | IllegalArgumentException e) {
                // A signature or algorithm failure (e.g. jjwt rejecting
                // alg:none after the Lab 21 fix). These are always 401 —
                // catching them here is what keeps Labs 21 and 25 independent.
                unauthorized(res);
                return;
            }
        }

        // LAB 25 (FIXED): a token that was accepted but named no identity is
        // an unauthenticated request, not an admin one.
        //
        // The old code fell back to a default identity of user_id 1 — the
        // admin user — so a token with no user_id claim was silently
        // promoted. A fallback that assumes "the admin" when you cannot
        // prove who the caller is is not a fallback at all; it is a
        // privilege escalation.
        if (userId == null && header != null && header.startsWith("Bearer ")) {
            unauthorized(res);
            return;
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
