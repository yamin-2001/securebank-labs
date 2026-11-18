package com.securebank.labs.a02;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * LAB 6 (A02 — Security Misconfiguration): sensitive file exposure.
 *
 * <p>Two of the three lab artefacts are served straight out of the static
 * resource root by Spring's {@code ResourceHttpRequestHandler}:
 * <ul>
 *   <li>{@code GET /.env} — the environment file with cloud credentials</li>
 *   <li>{@code GET /backup.zip} — a database backup</li>
 * </ul>
 *
 * <p>The third, {@code GET /.git/config}, needs this filter. Spring's path
 * matcher refuses to match any path containing a dot-<em>directory</em>
 * segment, so {@code /.git/config} 404s at the dispatcher even though
 * {@code /.env} (a dot-<em>file</em>) is served fine. A filter sees the raw
 * request URI before path matching, so it can serve the file.
 *
 * <p><strong>FIX:</strong> delete this filter, remove {@code .env},
 * {@code .git/} and {@code backup.zip} from {@code src/main/resources/static/},
 * and point {@code spring.web.resources.static-locations} at a dedicated
 * directory that contains nothing sensitive. Never keep secrets in the web
 * root, and never let the build copy a {@code .git} directory into it.
 */
@Configuration
public class SensitiveFileController extends OncePerRequestFilter {

    private static final String GIT_CONFIG_PATH = "/.git/config";

    /**
     * LAB 6 (VULNERABLE): serves the git config verbatim.
     *
     * <p>FIX: delete this filter.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        if (GIT_CONFIG_PATH.equals(req.getRequestURI())) {
            Resource resource = new ClassPathResource("static/.git/config");
            if (resource.exists()) {
                String content = resource.getContentAsString(StandardCharsets.UTF_8);
                res.setStatus(HttpServletResponse.SC_OK);
                res.setContentType("text/plain");
                res.getWriter().write(content);
                return;
            }
            // The file is missing — fall through so the error is diagnosable.
            res.setStatus(HttpServletResponse.SC_NOT_FOUND);
            res.setContentType("text/plain");
            res.getWriter().write("git config not found on classpath");
            return;
        }

        chain.doFilter(req, res);
    }

    /**
     * Register the filter ahead of Spring Security, so the dot-directory path
     * is served even though neither the security matchers nor the dispatcher
     * will match it.
     */
    @Bean
    public FilterRegistrationBean<SensitiveFileController> sensitiveFileFilter() {
        FilterRegistrationBean<SensitiveFileController> registration =
                new FilterRegistrationBean<>(new SensitiveFileController());
        registration.addUrlPatterns("/*");
        registration.setOrder(org.springframework.core.Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
