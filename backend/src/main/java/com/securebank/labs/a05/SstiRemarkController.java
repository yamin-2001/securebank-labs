package com.securebank.labs.a05;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <strong>LAB 11 (A05 — Injection): SpEL template injection.</strong>
 *
 * <p><strong>FIXED.</strong> The transaction remark used to be rendered by
 * handing the user's text straight to the SpEL expression parser. The user's
 * text <em>was</em> the expression, so it was evaluated as code:
 *
 * <ul>
 *   <li>{@code 7*7} evaluated to {@code 49}</li>
 *   <li>{@code T(java.lang.Runtime).getRuntime().exec("id")} executed a
 *       command</li>
 * </ul>
 *
 * <p>This was the Spring equivalent of Jinja2's
 * {@code render_template_string(f"...")} — the mistake is the same one:
 * <em>data</em> was interpolated into a <em>template</em> before parsing.
 *
 * <p>The template is a constant now, and the user's text is a
 * <em>variable</em>: the expression is the literal {@code "#remark"} and the
 * remark is bound with {@code ctx.setVariable("remark", remark)}.
 */
@RestController
@RequestMapping("/api/transfers")
public class SstiRemarkController {

    private final ExpressionParser parser = new SpelExpressionParser();

    public SstiRemarkController() {
    }

    /**
     * Render a transaction remark.
     *
     * <p><strong>LAB 11 (FIXED):</strong> the remark is bound as data, not
     * parsed as an expression. A remark of {@code 7*7} is printed as the
     * literal text {@code 7*7}, not evaluated to {@code 49}.
     */
    @PostMapping("/{id}/remark")
    public Map<String, Object> remark(@PathVariable Long id, @RequestBody Map<String, String> body) {
        String remark = body.get("remark");

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("transfer_id", id);
        response.put("rendered", renderFixed(remark));
        return response;
    }

    /**
     * The expression is a constant; the remark is bound as data.
     */
    private String renderFixed(String remark) {
        if (remark == null) {
            return "";
        }
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setVariable("remark", remark);
        return parser.parseExpression("#remark").getValue(context, String.class);
    }
}
