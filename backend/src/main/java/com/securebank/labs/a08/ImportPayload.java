package com.securebank.labs.a08;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * The gadget behind <strong>LAB 20 (A08 — Software and Data Integrity
 * Failures)</strong>.
 *
 * <p>This class is <em>not</em> a business object. It exists to be a
 * serializable class whose {@code readObject} runs a command — the shape of
 * every deserialization gadget chain, minus the third-party library that
 * usually supplies one.
 *
 * <p>When a server calls {@code ObjectInputStream.readObject()} on bytes it
 * did not produce and did not validate, the bytes get to choose which class
 * to instantiate and what to do while it is being constructed. That is the
 * whole of A08: <em>deserialization of untrusted data is remote code
 * execution</em>, and it does not matter that the class is "harmless" —
 * {@code readObject} runs before any validation the application does.
 *
 * <p>Real-world gadget chains reach this effect through classes already on
 * the classpath (Apache Commons Collections, Spring, etc.). Here the class
 * is in the application, which makes the mechanism obvious rather than
 * obscure — the lesson is the same.
 *
 * <p><strong>FIX:</strong> do not deserialize untrusted bytes. See
 * {@link IntegrityController#importAccount}. The two correct answers are:
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

    /** The command to run when the payload is deserialized. */
    private String command;

    /** The marker file the command creates, so the harness can prove it ran. */
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

    /**
     * LAB 20 (VULNERABLE): the gadget.
     *
     * <p>{@code readObject} is called by {@code ObjectInputStream} while it
     * reconstitutes the object. There is no way for the calling application
     * to intercept it — the object is already being built by the time any
     * application code gets a chance to look at it.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        runCommand();
    }

    private void runCommand() {
        if (command == null || command.isBlank()) {
            return;
        }
        try {
            // The marker is written by the command itself, so the harness can
            // check for the file rather than trusting the response body.
            ProcessBuilder builder = new ProcessBuilder("sh", "-c", command);
            builder.redirectErrorStream(true);
            builder.start().waitFor();
        } catch (IOException e) {
            // A gadget that fails is still a gadget — the point is that the
            // server ran a command it was told to run.
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
