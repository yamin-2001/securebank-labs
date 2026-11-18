package com.securebank.labs.a05;

import java.util.LinkedHashMap;
import java.util.Map;

import com.securebank.core.LabToggles;
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
 * <p>The transaction remark is rendered by handing the user's text straight
 * to the SpEL expression parser. The user's text <em>is</em> the expression,
 * so it is evaluated as code:
 *
 * <ul>
 *   <li>{@code 7*7} evaluates to {@code 49}</li>
 *   <li>{@code T(java.lang.Runtime).getRuntime().exec("id")} executes a
 *       command</li>
 * </ul>
 *
 * <p>This is the Spring equivalent of Jinja2's
 * {@code render_template_string(f"...")} — the mistake is the same one:
 * <em>data</em> was interpolated into a <em>template</em> before parsing.
 *
 * <p><strong>FIX:</strong> the template must be a constant and the user's
 * text must be a <em>variable</em>. The intended end state is
 * {@link #renderFixed(String)}: the expression is the literal
 * {@code "#remark"} and the remark is bound with
 * {@code ctx.setVariable("remark", remark)}.
 */
@RestController
@RequestMapping("/api/transfers")
public class SstiRemarkController {

    private final LabToggles labs;
    private final ExpressionParser parser = new SpelExpressionParser();

    public SstiRemarkController(LabToggles labs) {
        this.labs = labs;
    }

    /**
     * Render a transaction remark.
     *
     * <p><strong>LAB 11 (VULNERABLE):</strong> the remark is parsed as an
     * expression.
     *
     * <p><strong>FIX:</strong> delete the vulnerable branch and call
     * {@link #renderFixed(String)}.
     */
    @PostMapping("/{id}/remark")
    public Map<String, Object> remark(@PathVariable Long id, @RequestBody Map<String, String> body) {
        String remark = body.get("remark");

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("transfer_id", id);

        if (labs.isEnabled("ssti")) {
            // LAB 11 (VULNERABLE): the user's text is the expression.
            //
            // FIX: use renderFixed(remark) below.
            response.put("rendered", renderVulnerable(remark));
            return response;
        }

        // ---- FIX (the intended final state) ----
        response.put("rendered", renderFixed(remark));
        return response;
    }

    /**
     * LAB 11 (VULNERABLE): parse the caller's text as an expression.
     *
     * <p>FIX: delete this method.
     */
    private String renderVulnerable(String remark) {
        if (remark == null) {
            return "";
        }
        try {
            return parser.parseExpression(remark)
                    .getValue(new StandardEvaluationContext(), String.class);
        } catch (RuntimeException e) {
            // A failed evaluation still confirms the parser ran the text.
            return "Evaluation failed: " + e.getClass().getSimpleName()
                    + " -- " + e.getMessage();
        }
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>The expression is a constant; the remark is bound as data. A remark
     * of {@code 7*7} is now printed as the literal text {@code 7*7}, not
     * evaluated to {@code 49}.
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
