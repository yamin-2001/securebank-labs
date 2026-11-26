package com.securebank.labs.a08;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

/**
 * Data-import and file-upload endpoints.
 *
 * <p>Home to two labs, each with its own fix location:
 * <ul>
 *   <li><strong>LAB 20 (FIXED)</strong> (A08) — unsafe deserialization. The
 *       uploaded bytes used to be handed to {@code ObjectInputStream}; see
 *       {@link #importAccount}.</li>
 *   <li><strong>LAB 22 (FIXED)</strong> (A08) — unrestricted file upload. The
 *       original filename used to be preserved and the file served from the
 *       web root; see {@link #kycUpload}.</li>
 * </ul>
 *
 * <p>They share a controller because they share a theme — <em>the server
 * trusts the client's bytes</em> — but they are fixed independently, and the
 * two toggles are separate.
 */
@RestController
@RequestMapping("/api/integrity")
public class IntegrityController {

    /**
     * Where the uploaded KYC documents land.
     *
     * <p><strong>LAB 22 (FIXED):</strong> this is outside the static
     * resource root, so the uploaded file is never served back over HTTP
     * with a content type the browser infers from its name.
     */
    private static final Path UPLOAD_DIR = Paths.get("var", "kyc");

    public IntegrityController() {
    }

    /**
     * Import an account from an uploaded file.
     *
     * <p><strong>LAB 20 (FIXED):</strong> the bytes used to be deserialized
     * with {@code ObjectInputStream}. The stream names the classes it
     * instantiates, so an attacker who could upload bytes chose what got
     * constructed — and {@code readObject} runs during construction, before
     * any validation the application could perform.
     *
     * <p>The import is now data-only: the bytes are parsed as JSON, so they
     * can describe an account but they cannot name a class, and nothing in
     * the file can become code.
     */
    @PostMapping("/import-account")
    public ResponseEntity<Map<String, Object>> importAccount(@RequestParam("file") MultipartFile file) {
        try {
            String body = new String(file.getBytes(), java.nio.charset.StandardCharsets.UTF_8);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("message", "Account imported");
            out.put("mode", "safe-json");
            out.put("bytes", body.length());
            return ResponseEntity.ok(out);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Could not read the import file"));
        }
    }

    /**
     * Upload a KYC document.
     *
     * <p><strong>LAB 22 (FIXED):</strong> the file used to keep its original
     * name and extension and be written into the web root, so it was served
     * back as whatever the browser thought it was. A {@code .html} upload
     * became stored XSS delivered by the server itself; a {@code .jsp} or
     * {@code .svg} upload was worse.
     *
     * <p>Now the stored name is a UUID the server generated, the original
     * name is kept only as metadata, the bytes go to a directory outside the
     * web root, and the extension is fixed — so an uploaded {@code .html}
     * file can never be served back as HTML from the site's own origin.
     */
    @PostMapping("/kyc-upload")
    public ResponseEntity<Map<String, Object>> kycUpload(@RequestParam("file") MultipartFile file) {
        String stored = UUID.randomUUID() + ".bin";
        Path target = UPLOAD_DIR.resolve(stored);
        try {
            Files.createDirectories(UPLOAD_DIR);
            Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Could not store the upload"));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("message", "Upload stored");
        out.put("stored_as", stored);
        out.put("location", "/kyc/" + stored);
        return ResponseEntity.ok(out);
    }

    /**
     * Read an uploaded file's bytes back.
     *
     * <p><strong>LAB 22 (FIXED):</strong> the response always carries a
     * fixed content type and {@code Content-Disposition: attachment}, so the
     * browser downloads the file instead of rendering it in the site's
     * origin. The name is only ever the server-generated one.
     */
    @GetMapping("/uploads/{name}")
    public ResponseEntity<byte[]> fetchUpload(@PathVariable String name) {
        Path target = UPLOAD_DIR.resolve(name).normalize();
        if (!target.startsWith(UPLOAD_DIR) || !Files.isRegularFile(target)) {
            return ResponseEntity.notFound().build();
        }
        try {
            byte[] bytes = Files.readAllBytes(target);
            return ResponseEntity.ok()
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Disposition", "attachment; filename=\"" + target.getFileName() + "\"")
                    .body(bytes);
        } catch (IOException e) {
            return ResponseEntity.notFound().build();
        }
    }
}
