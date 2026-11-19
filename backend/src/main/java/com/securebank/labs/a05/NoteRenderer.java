package com.securebank.labs.a05;

import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

/**
 * <strong>LAB 13 (A05 — Injection): stored XSS in transaction notes.</strong>
 *
 * <p><strong>FIXED.</strong> A transaction note used to be stored raw and
 * rendered as raw HTML, so the browser executed whatever markup the note
 * contained — the classic stored XSS. Every user who viewed the transfers
 * page ran the payload.
 *
 * <p>This renderer is deliberately the <em>single</em> place the note is
 * turned into HTML. Both the React UI's render path and the
 * {@code GET /api/transfers?format=html} endpoint go through it, so the
 * browser and the verification script can never disagree about whether a
 * build is vulnerable.
 *
 * <p>The note is HTML-escaped before it is put into the document, so
 * {@code <img src=x onerror=...>} is rendered as visible text instead of as
 * an element. The React side renders the note as plain text for the same
 * reason.
 *
 * <p>Escaping is the server-side fix. It is the right one for this lab
 * because the note is stored in the database and rendered for many users:
 * sanitising at write time cannot help notes that were already stored.
 */
@Component
public class NoteRenderer {

    /**
     * Render a transaction note as HTML.
     *
     * <p><strong>LAB 13 (FIXED):</strong> the note is HTML-escaped before it
     * is put into the document, so a payload is displayed as text and never
     * becomes an element.
     */
    public String render(String note) {
        String escaped = HtmlUtils.htmlEscape(note == null ? "" : note);
        return "<div class=\"txn-note\">" + escaped + "</div>";
    }
}
