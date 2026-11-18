# Phase 0 Spike — Findings

The technical unknowns from the plan, resolved by building rather than assuming.
Every item below was verified against the running application.

## Resolved

| # | Question | Answer |
|---|---|---|
| Q1 | Does Spring serve `static/.git/config`? | **No.** Spring 7's path matcher refuses any path with a dot-*directory* segment. `/.env` (dot-file) serves fine; `/.gitignore` and `/.git/config` 404. Solved with a `OncePerRequestFilter` that sees the raw request URI before path matching. |
| Q1b | Does Maven copy a `.git` directory into the build? | **No** — dot-directories are excluded by default. `.env` copied, `.git/` did not. Added an explicit `<resource>` entry in `pom.xml` to re-include it. |
| Q2 | Does an unauthenticated request get 401 JSON or a 302 redirect? | **401 JSON** — confirmed via `curl -i`. A custom `AuthenticationEntryPoint` replaces Spring's default `LoginUrlAuthenticationEntryPoint`. |
| Q3 | Does Jackson 3 deserialise a `@RequestBody` DTO? | **Yes** — `tools.jackson.databind`, no `throws` clause needed; `JacksonException` is unchecked. |
| Q4 | Can jjwt emit or accept an `alg:none` token? | **No, to both.** `JwtBuilder` exposes only `signWith(...)`; `parseSignedClaims` rejects unsecured tokens with `UnsupportedJwtException`. Lab 21 therefore needs a hand-rolled parser; jjwt becomes the *fixed* reference parser. |
| Q5 | Does `SpelExpressionParser` evaluate user input? | **Yes — RCE confirmed.** `T(java.lang.Runtime).getRuntime().exec("id")` executed a process on the server. |

## Surprises worth remembering

### SpEL does not accept `#{...}` in `parseExpression()`
`#{...}` is *template* syntax, valid in `@Value` and config contexts only. In
`parseExpression()` the input is a bare expression. The exploit payload is
`7*7` / `T(java.lang.Runtime)...`, **not** `#{7*7}`.

### jjwt refuses to sign with a short secret
`Keys.hmacShaKeyFor("secret".getBytes())` throws `WeakKeyException` — HMAC
keys must be ≥256 bits (RFC 7518 §3.2). Lab 8's hardcoded secret is therefore
`hardcoded-jwt-secret-do-not-ship-2024` (32 bytes): still hardcoded, still
publicly readable, still in version control — which is the entire lesson —
but long enough for jjwt to operate.

### `@ConfigurationProperties` did not bind a `Map<String, Boolean>` from flat `lab.*` keys
Both `lab.idor.enabled=true` (nested) and `lab.idor=true` (flat) were visible
to `Environment.getProperty(...)` but left a `Map<String, Boolean>` field
empty. `@ConfigurationPropertiesScan` also did not register the bean (it is
absent from `/actuator/beans`); switching to `@EnableConfigurationProperties`
registered it but the map was still empty.

**Resolution:** `LabToggles` reads the `Environment` directly —
`env.getProperty("lab." + labId, "false")`. Explicit, and it sidesteps the
binder entirely. The YAML is flat (`lab.idor: true`).

### `server.error.include-stacktrace=always` had no effect
The property bound correctly, but the default `BasicErrorController` response
still contained no stack trace.

**Resolution:** an explicit `@RestControllerAdvice` (`core/ApiExceptionHandler`)
builds the verbose body directly — exception class, message, and stack trace.
This is also what makes Lab 24's isolated handler natural, since it needs its
own `@ExceptionHandler` to stay independent of Lab 23.

### Boot 4 API drift confirmed
- `io.jsonwebtoken.security.SigningKey` does not exist → `io.jsonwebtoken.security.Keys`
- `Jwts.claims()` returns a `ClaimsBuilder` → `Jwts.claims(Map)` returns `Claims`
- `@GetMapping.produces` is `String[]`, not `MediaType`
- `DefaultErrorAttributes` moved to `org.springframework.boot.webmvc.error`
- `spring-boot-starter-json` → `spring-boot-starter-jackson`

## Design consequences carried into Phase 1

1. **Lab toggles** are read from `Environment`, not bound properties.
2. **Lab 6** needs a filter (not a controller) for `/.git/config`, plus a
   `<resource>` entry in `pom.xml`.
3. **Labs 4, 23, 24** use explicit `@ExceptionHandler` methods, not the
   framework's error page.
4. **Lab 21** uses a hand-rolled parser; **Labs 8 and 21** share one secret
   constant that must be ≥32 bytes.
5. The API chain returns **401 JSON**, never a redirect — every verification
   module depends on this.
