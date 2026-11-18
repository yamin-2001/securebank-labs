package com.securebank.security;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security configuration.
 *
 * <p>Spring Security is on the classpath, but several of its protections are
 * deliberately weakened so that the labs remain exploitable. Each weakening
 * is marked and has a corresponding fix:
 *
 * <table>
 *   <caption>Deliberate weakenings</caption>
 *   <tr><th>Protection</th><th>Why it is off</th><th>Lab</th></tr>
 *   <tr><td>CSRF</td><td>bearer-token API; not one of the 25 labs</td><td>—</td></tr>
 *   <tr><td>Default 302 entry point</td><td>replaced with a 401 JSON body</td><td>—</td></tr>
 *   <tr><td>Session fixation protection</td><td>the session id must NOT rotate</td><td>18</td></tr>
 *   <tr><td>{@code /api/admin/**} role check</td><td>the missing role check IS the bug</td><td>2</td></tr>
 * </table>
 *
 * <p>Note on JWT parsing: Spring Security's own JWT support
 * ({@code NimbusJwtDecoder}) rejects {@code alg:none} outright. We do not use
 * it — {@link LabAuthFilter} parses tokens itself so that Lab 21 is
 * reachable. See {@link LabJwtService}.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final LabAuthFilter labAuthFilter;

    public SecurityConfig(LabAuthFilter labAuthFilter) {
        this.labAuthFilter = labAuthFilter;
    }

    /**
     * The main API chain: bearer-token authenticated, stateless.
     */
    @Bean
    public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**", "/uploads/**", "/admin-panel/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/health",
                                "/api/spike/**",
                                // LAB 4: the debug endpoint is reachable
                                // without authentication — that is the point.
                                "/api/debug/**",
                                "/api/auth/login",
                                "/api/auth/login-session",
                                "/api/auth/reset-request",
                                "/api/auth/reset-confirm",
                                // LAB 5: the operations console does its own
                                // credential check (see AdminPanelController).
                                // It is deliberately a separate URL space from
                                // /api/admin/** so that Lab 5 and Lab 2 are
                                // fixed independently.
                                "/admin-panel/**")
                        .permitAll()
                        // LAB 2 (VULNERABLE): authenticated, but NO role check.
                        //
                        // FIX: change `.authenticated()` to `.hasRole("ADMIN")`.
                        // A regular customer can currently read every user in
                        // the system, including hashed passwords.
                        .requestMatchers("/api/admin/**").authenticated()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        // Return a 401 JSON body rather than Spring's default
                        // 302 redirect to a login page — the labs need a
                        // machine-readable status.
                        .authenticationEntryPoint(jsonEntryPoint())
                        .accessDeniedHandler(jsonAccessDeniedHandler()))
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .addFilterBefore(labAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * The session chain for Lab 18 (session fixation).
     *
     * <p>{@code sessionFixation(none())} disables Spring Security's default
     * session-id rotation on login. Without this, the lab would be
     * unexploitable — the framework would already be doing the right thing.
     *
     * <p><strong>FIX (Lab 18):</strong> remove {@code sessionFixation(none())}
     * and rotate the session id explicitly in the controller
     * ({@code request.changeSessionId()} or {@code session.invalidate()}).
     */
    @Bean
    public SecurityFilterChain sessionChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/auth/login-session", "/api/session/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm
                        // LAB 18 (VULNERABLE): the session id is not rotated on login.
                        // FIX: delete this line so the default protection applies.
                        .sessionFixation(fixation -> fixation.none()))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(jsonEntryPoint()))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable());

        return http.build();
    }

    /**
     * The UI chain: static resources, the Lab 6 files, and uploads.
     *
     * <p>These are deliberately public — Lab 6 needs {@code /.env},
     * {@code /.git/config} and {@code /backup.zip} to be downloadable, and
     * Lab 22 needs uploaded files to be fetchable.
     */
    @Bean
    public SecurityFilterChain uiChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/", "/index.html", "/app.js", "/style.css", "/favicon.ico",
                        "/labs.json", "/.env", "/.git/config", "/backup.zip", "/uploads/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(jsonEntryPoint()))
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable());

        return http.build();
    }

    private AuthenticationEntryPoint jsonEntryPoint() {
        return (req, res, ex) -> {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.setContentType("application/json");
            res.getWriter().write("{\"error\":\"Unauthorized\"}");
        };
    }

    private AccessDeniedHandler jsonAccessDeniedHandler() {
        return (req, res, ex) -> {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.setContentType("application/json");
            res.getWriter().write("{\"error\":\"Forbidden\"}");
        };
    }
}
