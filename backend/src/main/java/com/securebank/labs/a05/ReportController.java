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
 * <p><strong>FIXED.</strong> Two independent flaws used to live in this
 * controller, each in its own method, so their fixes stay independent:
 *
 * <ul>
 *   <li>{@link #generate(Map)} — <strong>template injection.</strong> The
 *       caller's template string used to be handed to the SpEL parser, so it
 *       could read internal configuration
 *       ({@code #root.config['secret']}). The template is a constant now
 *       and the account id is bound as a variable.</li>
 *   <li>{@link #dateFilter(Map)} — <strong>command injection.</strong> The
 *       date bounds used to be pasted into a {@code sh -c} command line, so
 *       {@code 2024-01-01' && id && echo '} ran an extra command. The dates
 *       are parsed as dates now and passed as separate arguments, with no
 *       shell involved.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/report")
public class ReportController {

    private final ExpressionParser parser = new SpelExpressionParser();

    public ReportController() {
    }

    /**
     * Render a statement report.
     *
     * <p><strong>LAB 12 (FIXED):</strong> the template is a constant. Only
     * the account id varies, and it is bound as a variable, so a template
     * of {@code #root.config['secret']} is printed literally instead of
     * reaching into the application's internals.
     */
    @PostMapping("/generate")
    public Map<String, Object> generate(@RequestBody Map<String, String> body) {
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

    /**
     * Filter a report by date range.
     *
     * <p><strong>LAB 12 (FIXED):</strong> the dates are parsed as dates and
     * passed to the command as separate arguments. No shell is involved, so
     * a quote in the input is just a quote.
     */
    @PostMapping("/date-filter")
    public Map<String, Object> dateFilter(@RequestBody Map<String, String> body) {
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

    /** Run a command with separate arguments, no shell. */
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
