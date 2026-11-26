package com.securebank.labs.a08;

import java.io.Serializable;

/**
 * The payload type behind <strong>LAB 20 (A08 — Software and Data Integrity
 * Failures)</strong>.
 *
 * <p>On the vulnerable build this class is a deserialization gadget: its
 * {@code readObject} runs a command, which is the shape of every gadget
 * chain — minus the third-party library that usually supplies one.
 *
 * <p>When a server calls {@code ObjectInputStream.readObject()} on bytes it
 * did not produce and did not validate, the bytes get to choose which class
 * to instantiate and what to do while it is being constructed. That is the
 * whole of A08: <em>deserialization of untrusted data is remote code
 * execution</em>, and it does not matter that the class is "harmless" —
 * {@code readObject} runs before any validation the application does.
 *
 * <p><strong>FIXED:</strong> the gadget is gone. The class is still
 * serializable — it has to be, so the harness can build a payload of this
 * type and prove the server no longer executes it — but it has no
 * {@code readObject} hook and nothing runs a command. Deserializing it
 * produces an inert object.
 *
 * <p>The other half of the fix lives at the call site: the server no longer
 * hands uploaded bytes to {@code ObjectInputStream} at all. See
 * {@link IntegrityController#importAccount}. The two correct answers for that
 * end are:
 * <ul>
 *   <li>accept a structured format (JSON, protobuf, CSV) that carries data
 *       only — data cannot become code;</li>
 *   <li>if a binary format is genuinely needed, allowlist the classes the
 *       stream is permitted to contain with
 *       {@code ObjectInputFilter}, and never let the stream name the
 *       classes itself.</li>
 * </ul>
 */
public class ImportPayload implements Serializable {

    private static final long serialVersionUID = 1L;

    /** The command this payload would have run on the vulnerable build. */
    private String command;

    /** The marker file the command created, so the harness could prove it ran. */
    private String marker;

    public ImportPayload() {
    }

    public ImportPayload(String command, String marker) {
        this.command = command;
        this.marker = marker;
    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public String getMarker() {
        return marker;
    }

    public void setMarker(String marker) {
        this.marker = marker;
    }
}
