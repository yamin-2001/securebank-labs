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

import com.securebank.core.LabToggles;
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
 *   <li><strong>LAB 20</strong> (A08) — unsafe deserialization. The uploaded
 *       bytes are handed to {@code ObjectInputStream}; see
 *       {@link #importAccount}.</li>
 *   <li><strong>LAB 22</strong> (A08) — unrestricted file upload. The
 *       original filename is preserved and the file is served from the web
 *       root; see {@link #kycUpload}.</li>
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
     * <p><strong>LAB 22 (VULNERABLE):</strong> this is inside the static
     * resource root, so the uploaded file is served back over HTTP with the
     * content type the browser infers from its extension. An uploaded
     * {@code .html} file is therefore a stored XSS payload that the server
     * itself hands out.
     */
    private static final Path UPLOAD_DIR = Paths.get("uploads");

    private final LabToggles labs;

    public IntegrityController(LabToggles labs) {
        this.labs = labs;
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
     * <p><strong>LAB 22 (VULNERABLE):</strong> the file keeps its original
     * name and extension and is written into the web root, so it is served
     * back as whatever the browser thinks it is. A {@code .html} upload
     * becomes stored XSS delivered by the server itself; a {@code .jsp} or
     * {@code .svg} upload is worse.
     *
     * <p><strong>FIX:</strong>
     * <ul>
     *   <li>generate the stored name yourself (a UUID) and keep the
     *       original only as metadata;</li>
     *   <li>allowlist the extensions and content types you accept;</li>
     *   <li>store the file outside the web root and serve it through a
     *       controller that sets {@code Content-Disposition: attachment} and
     *       a fixed content type;</li>
     *   <li>never let a user-supplied name reach the filesystem.</li>
     * </ul>
     */
    @PostMapping("/kyc-upload")
    public ResponseEntity<Map<String, Object>> kycUpload(@RequestParam("file") MultipartFile file) {
        String originalName = file.getOriginalFilename();
        Map<String, Object> out = new LinkedHashMap<>();

        if (labs.isEnabled("upload")) {
            // LAB 22 (VULNERABLE): the original name and extension are
            // trusted, and the file is written into the static resource root.
            //
            // FIX: delete this branch and call storeUploadSafely(file) instead.
            try {
                Files.createDirectories(UPLOAD_DIR);
                Path target = UPLOAD_DIR.resolve(originalName == null ? "upload.bin" : originalName);
                Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

                out.put("message", "Upload stored");
                out.put("stored_as", target.getFileName().toString());
                out.put("location", "/uploads/" + target.getFileName());
                out.put("content_type", contentTypeFor(originalName));
                return ResponseEntity.ok(out);
            } catch (IOException e) {
                out.put("error", "Could not store the upload");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(out);
            }
        }

        // ---- FIX (the intended final state) ----
        // The stored name is generated, the extension is not the client's to
        // choose, and the file never lands in the web root.
        return storeUploadSafely(file);
    }

    /**
     * ---- FIX (the intended final state) -------------------------------
     *
     * <p>The stored name is a UUID the server generated. The original name is
     * kept only as metadata, the bytes go to a directory outside the web
     * root, and the extension is fixed — so an uploaded {@code .html} file
     * can never be served back as HTML from the site's own origin.
     */
    private ResponseEntity<Map<String, Object>> storeUploadSafely(MultipartFile file) {
        String stored = UUID.randomUUID() + ".bin";
        Path target = Paths.get("var", "kyc", stored);
        try {
            Files.createDirectories(target.getParent());
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
     * The content type a browser would infer from the extension.
     *
     * <p>Used by the vulnerable path so the response tells the client how the
     * file will be treated. {@code .html} and {@code .svg} are the dangerous
     * ones: the browser renders them, so the upload executes in the site's
     * origin.
     */
    private String contentTypeFor(String filename) {
        if (filename == null) {
            return "application/octet-stream";
        }
        String lower = filename.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".html") || lower.endsWith(".htm")) {
            return "text/html";
        }
        if (lower.endsWith(".svg")) {
            return "image/svg+xml";
        }
        if (lower.endsWith(".js")) {
            return "text/javascript";
        }
        if (lower.endsWith(".png")) {
            return "image/png";
        }
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            return "image/jpeg";
        }
        return "application/octet-stream";
    }

    /**
     * What the uploads directory currently holds.
     *
     * <p>Lets the harness see that a file was stored, and lets the learner
     * see the shape of the problem.
     */
    @GetMapping("/uploads")
    public ResponseEntity<Map<String, Object>> listUploads() {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            if (Files.isDirectory(UPLOAD_DIR)) {
                try (var files = Files.list(UPLOAD_DIR)) {
                    out.put("uploads", files.map(p -> p.getFileName().toString()).sorted().toList());
                }
            } else {
                out.put("uploads", java.util.List.of());
            }
        } catch (IOException e) {
            out.put("uploads", java.util.List.of());
        }
        return ResponseEntity.ok(out);
    }

    /**
     * Read an uploaded file's bytes back.
     *
     * <p>Used by the harness to confirm the upload really landed on disk with
     * the name the attacker chose.
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
                    .header("Content-Type", contentTypeFor(name))
                    .body(bytes);
        } catch (IOException e) {
            return ResponseEntity.notFound().build();
        }
    }
}
