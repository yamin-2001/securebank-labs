package com.securebank.labs.a05;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.securebank.core.LabToggles;
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
 * <p>Two independent flaws live in this controller, each in its own method,
 * so their fixes stay independent:
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
 *
 * <p><strong>FIX (template):</strong> render from a fixed template with
 * dynamic data only. The intended end state is
 * {@link #generateFixed(Map)} — the expression is a constant and the
 * account id is a variable.
 *
 * <p><strong>FIX (command):</strong> parse and validate the dates, and pass
 * values as separate arguments instead of building a shell command line.
 * The intended end state is {@link #dateFilterFixed(Map)}.
 */
@RestController
@RequestMapping("/api/report")
public class ReportController {

    private final LabToggles labs;
    private final ExpressionParser parser = new SpelExpressionParser();

    public ReportController(LabToggles labs) {
        this.labs = labs;
    }

    /**
     * Render a statement report from a caller-supplied template.
     *
     * <p><strong>LAB 12 (VULNERABLE):</strong> the template is parsed.
     *
     * <p><strong>FIX:</strong> use {@link #generateFixed(Map)}.
     */
    @PostMapping("/generate")
    public Map<String, Object> generate(@RequestBody Map<String, String> body) {
        if (labs.isEnabled("ssti")) {
            // LAB 12 (VULNERABLE): the caller's template is parsed as an
            // expression, so it can read internal configuration.
            //
            // FIX: use generateFixed(body) below.
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("account_id", body.get("account_id"));
            out.put("report", renderTemplateVulnerable(body.get("template")));
            return out;
        }

        // ---- FIX (the intended final state) ----
        return generateFixed(body);
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>The template is a constant. Only the account id varies, and it is
     * bound as a variable.
     */
    private Map<String, Object> generateFixed(Map<String, String> body) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("accountId", body.get("account_id"));
        String report = parser.parseExpression(
                        "'Statement for account ' + #accountId + ' — balance 4200.00 GBP'")
                .getValue(context, String.class);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("account_id", body.get("account_id"));
        out.put("report", report);
        return out;
    }

    /** LAB 12 (VULNERABLE): parse the caller's template. FIX: delete this. */
    private String renderTemplateVulnerable(String template) {
        if (template == null) {
            return "";
        }
        StandardEvaluationContext context = new StandardEvaluationContext();
        Map<String, Object> config = new LinkedHashMap<>();
        // The signing secret is what the template injection reads out of the
        // application's internal configuration.
        config.put("secretKey", JwtKeys.secret(labs));
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
     *
     * <p><strong>FIX:</strong> use {@link #dateFilterFixed(Map)}.
     */
    @PostMapping("/date-filter")
    public Map<String, Object> dateFilter(@RequestBody Map<String, String> body) {
        String from = body.get("from_date");
        String to = body.get("to_date");

        if (labs.isEnabled("cmdinject")) {
            // LAB 12 (VULNERABLE): the dates are concatenated into a shell
            // command line, so a quote breaks out of the date argument.
            //
            // FIX: use dateFilterFixed(body) below.
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("from_date", from);
            out.put("to_date", to);
            out.put("command_output", runShell(
                    "date -d '" + from + "' '+%Y-%m-%d' && date -d '" + to + "' '+%Y-%m-%d'"));
            return out;
        }

        // ---- FIX (the intended final state) ----
        return dateFilterFixed(body);
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>The dates are parsed as dates and passed to the command as separate
     * arguments. No shell is involved, so a quote in the input is just a
     * quote.
     */
    private Map<String, Object> dateFilterFixed(Map<String, String> body) {
        String from = body.get("from_date");
        String to = body.get("to_date");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("from_date", from);
        out.put("to_date", to);

        LocalDate fromDate = parseDate(from);
        LocalDate toDate = parseDate(to);
        if (fromDate == null || toDate == null) {
            out.put("error", "from_date and to_date must be valid ISO dates (yyyy-MM-dd)");
            return out;
        }
        if (fromDate.isAfter(toDate)) {
            out.put("error", "from_date must not be after to_date");
            return out;
        }

        // Separate arguments, no shell.
        out.put("command_output", runCommand(
                List.of("date", "-d", from, "+%Y-%m-%d")));
        return out;
    }

    private LocalDate parseDate(String value) {
        if (value == null) {
            return null;
        }
        try {
            return LocalDate.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** LAB 12 (VULNERABLE): run a shell command line. FIX: delete this. */
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

    /** FIX: run a command with separate arguments, no shell. */
    private String runCommand(List<String> command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
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
