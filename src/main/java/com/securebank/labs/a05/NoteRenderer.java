package com.securebank.labs.a05;

import com.securebank.core.LabToggles;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

/**
 * <strong>LAB 13 (A05 — Injection): stored XSS in transaction notes.</strong>
 *
 * <p>A transaction note is stored raw and rendered as raw HTML. The browser
 * therefore executes whatever markup the note contains — the classic stored
 * XSS. Every user who views the transfers page runs the payload.
 *
 * <p>This renderer is deliberately the <em>single</em> place the note is
 * turned into HTML. Both the React UI's {@code dangerouslySetInnerHTML}
 * render path and the {@code GET /api/transfers?format=html} endpoint go
 * through it, so the browser and the verification script can never disagree
 * about whether a build is vulnerable.
 *
 * <p><strong>FIX:</strong> delete the vulnerable branch. The fixed renderer
 * escapes the note, so {@code <img src=x onerror=...>} is rendered as
 * visible text instead of as an element. On the React side the equivalent
 * fix is to render the note as plain text — but escaping here is what makes
 * the fix verifiable over plain HTTP.
 *
 * <p>Escaping is the server-side fix. It is the right one for this lab
 * because the note is stored in the database and rendered for many users:
 * sanitising at write time cannot help notes that were already stored.
 */
@Component
public class NoteRenderer {

    private final LabToggles labs;

    public NoteRenderer(LabToggles labs) {
        this.labs = labs;
    }

    /**
     * Render a transaction note as HTML.
     *
     * <p><strong>LAB 13 (VULNERABLE):</strong> the note is interpolated raw.
     *
     * <p><strong>FIX:</strong> delete this branch and use
     * {@link #renderFixed(String)}.
     */
    public String render(String note) {
        if (labs.isEnabled("xss")) {
            // LAB 13 (VULNERABLE): raw interpolation. The note becomes markup.
            //
            // FIX: use renderFixed(note) below.
            return "<div class=\"txn-note\">" + (note == null ? "" : note) + "</div>";
        }

        // ---- FIX (the intended final state) ----
        return renderFixed(note);
    }

    /**
     * ---- FIX (the intended final state) ----
     *
     * <p>The note is HTML-escaped before it is put into the document, so a
     * payload is displayed as text and never becomes an element.
     */
    public String renderFixed(String note) {
        String escaped = HtmlUtils.htmlEscape(note == null ? "" : note);
        return "<div class=\"txn-note\">" + escaped + "</div>";
    }
}
