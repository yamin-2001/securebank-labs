package com.securebank.labs.a05;

import org.springframework.stereotype.Component;

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
 */
@Component
public class NoteRenderer {

    public NoteRenderer() {
    }

    /**
     * Render a transaction note as HTML.
     *
     * <p><strong>LAB 13 (VULNERABLE):</strong> the note is interpolated raw.
     */
    public String render(String note) {
        return "<div class=\"txn-note\">" + (note == null ? "" : note) + "</div>";
    }
}
