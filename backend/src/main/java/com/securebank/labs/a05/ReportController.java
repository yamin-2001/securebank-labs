package com.securebank.labs.a05;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.securebank.security.JwtKeys;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 12 (A05 — Injection): SSTI + OS command injection in the report
 * service.</strong>
 *
 * <p>Two independent flaws live in this controller, each in its own method:
 *
 * <ul>
 *   <li>{@link #generate(Map)} — <strong>template injection.</strong> The
 *       caller's template string is handed to the SpEL parser, so it can
 *       read internal configuration
 *       ({@code #root.config['secret']}).</li>
 *   <li>{@link #dateFilter(Map)} — <strong>command injection.</strong> The
 *       date bounds are pasted into a {@code sh -c} command line, so
 *       {@code 2024-01-01' && id && echo '} runs an extra command.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/report")
public class ReportController {

    private final ExpressionParser parser = new SpelExpressionParser();

    public ReportController() {
    }

    /**
     * Render a statement report from a caller-supplied template.
     *
     * <p><strong>LAB 12 (VULNERABLE):</strong> the template is parsed.
     */
    @PostMapping("/generate")
    public Map<String, Object> generate(@RequestBody Map<String, String> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account_id", body.get("account_id"));
        out.put("report", renderTemplateVulnerable(body.get("template")));
        return out;
    }

    /** LAB 12 (VULNERABLE): parse the caller's template. */
    private String renderTemplateVulnerable(String template) {
        if (template == null) {
            return "";
        }
        StandardEvaluationContext context = new StandardEvaluationContext();
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("secretKey", JwtKeys.HARDCODED_SECRET);
        config.put("dbPath", "jdbc:postgresql://localhost:5432/securebank");
        config.put("internalHost", "postgres.internal.svc.cluster.local");
        context.setRootObject(Map.of("Config", config));
        try {
            return parser.parseExpression(template).getValue(context, String.class);
        } catch (RuntimeException e) {
            return "Evaluation failed: " + e.getClass().getSimpleName()
                    + " -- " + e.getMessage();
        }
    }

    /**
     * Filter a report by date range.
     *
     * <p><strong>LAB 12 (VULNERABLE):</strong> the dates are pasted into a
     * shell command.
     */
    @PostMapping("/date-filter")
    public Map<String, Object> dateFilter(@RequestBody Map<String, String> body) {
        String from = body.get("from_date");
        String to = body.get("to_date");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("from_date", from);
        out.put("to_date", to);
        out.put("command_output", runShell(
                "date -d '" + from + "' '+%Y-%m-%d' && date -d '" + to + "' '+%Y-%m-%d'"));
        return out;
    }

    /** LAB 12 (VULNERABLE): run a shell command line. */
    private String runShell(String commandLine) {
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", commandLine);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            String output = read(process);
            process.waitFor(10, TimeUnit.SECONDS);
            return output.trim();
        } catch (IOException | InterruptedException e) {
            return "command failed: " + e.getMessage();
        }
    }

    private String read(Process process) throws IOException {
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        }
        return String.join("\n", lines);
    }
}
