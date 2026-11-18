"""The "why" behind each lab's fix.

Kept separate from `gen_solutions.py` so the prose can be as long as it
needs to be without burying the generator's logic.

Every explanation here describes the fix that `isolation_matrix.py`
actually applies and verifies.
"""

WHY = {
    1: """The account is fetched by id and returned without ever comparing its
owner against the caller. The fix is the missing comparison: load the
account, then check that `account.getOwnerId()` equals the authenticated
principal's id, and refuse with a 403 otherwise.

In production you would also return a 404 rather than a 403 for an account
that is not the caller's, so the endpoint cannot be used to probe which ids
exist.""",
    2: """The matcher only required an authenticated caller. Every logged-in
customer could read every user in the system, password hashes included.

The fix is one line: `.hasRole("ADMIN")`. Spring Security's `hasRole`
prefixes the role with `ROLE_`, so the token's `role` claim must be
`admin` — which is what `LabAuthFilter` puts in the `SecurityContext`.

Nothing in `AdminController` changes. That is the point: the vulnerability
was a *missing* check, so the fix is the *addition* of one.""",
    3: """The callback URL went straight to an HTTP client with no allowlist,
so the server would fetch anything you named — including `localhost`, the
cluster's internal DNS, or a cloud metadata endpoint.

The fix is an allowlist of permitted schemes and hosts, checked before the
request goes out. Resolve the hostname and reject private, loopback and
link-local addresses, because `evil.example.com` can point at `127.0.0.1`.
Disable redirects too, or the allowlist is trivially bypassed with a 302.""",
    4: """Two halves had to go. The exception message embedded the signing
secret and the JDBC URL, and `server.error.include-stacktrace=always` meant
the trace was rendered to the client.

Fix the message so it does not carry secrets, and turn off the global
inclusion (`include-stacktrace`, `include-message` and `include-exception`
all default to `never` in a real deployment).

Note the ordering: the message is the leak, and the stack trace is only the
delivery mechanism. Removing the trace hides the symptom; fixing the
message removes the secret.""",
    5: """Two halves again. The controller compared the submitted password
against a literal `admin`, and the seeded hash in `data.sql` was
`md5("admin")` — so as long as that row was unchanged, the default
credentials still worked.

Fix both: look the user up by username and compare the submitted password
against the *stored hash*, and rotate the admin's stored hash so there is no
default credential left to find. The second half is easy to miss, and the
harness will tell you: the lab does not flip to FIXED until the seed
changes too.""",
    6: """The files were in the served static root, so Spring handed them to
anyone who asked.

The fix is to take them off the web root — into a directory that is not
mapped to a URL, or into a secret manager. Turning off
`server.error.include-stacktrace` is not enough: a file that is on the web
root is public whether or not anything links to it.

`.git/config` is worth a second look. It is usually the *first* thing an
attacker fetches, because it names the remote and the branch.""",
    7: """MD5 is fast and unsalted, so the whole table falls to a rainbow
table in seconds, and two users with the same password have the same hash —
which tells you which users share a password.

The fix is a slow, salted hash: bcrypt, scrypt or Argon2. The salt is
per-user and stored alongside the hash, so identical passwords produce
different hashes and a precomputed table is worthless.

`PasswordHasher.matches()` accepts both formats so you can migrate the seed
row by row: the MD5 rows keep working until you replace them.""",
    8: """A secret that is in the source tree is a secret that is in every
clone, every CI log and every stack trace — Lab 4 hands it out for free.

The fix is to read it from configuration or the environment, with real
entropy (at least 256 bits of random bytes for HS256), and to stop logging
it at startup. Rotating it invalidates every token in flight, which is
expected after a secret leak.

Do not commit the new secret either — a placeholder that fails fast at boot
is better than a real one in git.""",
    9: """PII should be masked before it leaves the process, and it should
not be written to the log. A log file is usually readable by more people
than the database is, and it is copied around more freely.

Mask what the endpoint does not need: the last four digits of a card
number, a partial postcode, a truncated national ID. Keep the full value
only where the business genuinely needs it.""",
    10: """Concatenating the username into the SQL string lets the input
change the query. `admin' --` comments out the password predicate, so the
admin row comes back with no password check at all.

The fix is a parameterized query: `users.findByUsername(username)`. The
driver handles the quoting, so the input is data and can never be syntax.

Watch out for the second-order version of this bug: the fix has to cover
*every* query that touches a user-supplied value, not just the one the
exploit used. The search endpoint has its own copy of the mistake.""",
    11: """The fix is the standard idiom: the template is a constant and the
user input arrives as a variable.

```java
StandardEvaluationContext ctx = new StandardEvaluationContext();
ctx.setVariable("remark", remark);
String out = parser.parseExpression("#remark").getValue(ctx, String.class);
```

The user's text is now a *value* in the context, never a piece of the
expression, so `#{7*7}` in it evaluates to the literal text `#{7*7}`.

Note that `SimpleEvaluationContext` is also an option, and a better one: it
disables type references and method resolution, so even if a template were
attacker-controlled, `T(java.lang.Runtime)` would not resolve.""",
    12: """Two methods, two independent fixes.

For the template, the same idiom as Lab 11: a constant expression, the
input bound as a variable.

For the shell, never build a command line by concatenating strings. Pass
the arguments as a list, so no shell is involved:

```java
new ProcessBuilder("date", "-d", from).start();
```

With a list, the argument is one argument — there is no shell to break out
of, so a quote in the date is just a character in a date. If you genuinely
need a shell, the rule is: never let user input reach the command line at
all, and never use `sh -c` with interpolated data.""",
    13: """One renderer serves both the API and the React app, so escaping it
here fixes both and the two can never disagree.

The fix is to escape the note before it becomes markup:

```java
return "<div class=\\"txn-note\\">" + HtmlUtils.htmlEscape(note) + "</div>";
```

The important part is *where*: escape at the point of output, not at the
point of input. Escaping on the way in is wrong — the stored value is then
escaped for one context and displayed in another, and a second round trip
double-escapes it.

The React side (`dangerouslySetInnerHTML`) is a second sink for the same
value. Escaping server-side covers both, because the server is what
produces the string the browser injects.""",
    14: """The amount must be validated before the arithmetic runs, not
after. Two rules:

- the amount must be **positive** — a negative debit is a credit;
- the amount must not **exceed the balance** — or you can overdraw.

Both checks belong at the top of the method, before any balance is
touched. Checking after the transfer has been applied is too late: the
money has already moved.

Use `BigDecimal` for money, never `double`. `BigDecimal.compareTo` is the
right comparison — `equals` compares scale too, so `10.0` is not `equals`
to `10.00`.""",
    15: """A role change is a privileged operation. It belongs on an
admin-only endpoint, never on a self-service profile update.

The fix is to bind to a dedicated DTO that has only the fields a customer
owns — `email` and `full_name` — and to read nothing else from the request
body. The entity is then populated from the DTO, so a field that is not in
the DTO cannot be set at all.

This is the general shape of the fix for mass assignment: the public API
surface and the persistence model should not be the same shape.""",
    16: """Return one message and one response time for both cases, so the
endpoint cannot be used to tell registered usernames from unregistered
ones.

Two messages is the obvious half. The subtler half is timing: looking a
user up and hashing the password takes far longer than finding nobody, so
an attacker can still enumerate by response time even when the messages
match. The fix is to run a dummy password check when the user does not
exist, so both paths cost the same.""",
    17: """Three edits, all part of the same fix: refuse once the budget is
gone, count a failure, and clear the counter on success.

The counting has to be on the *failure* path and the clearing on the
*success* path. If you count attempts instead of failures, a user who
logs in successfully still burns their budget — which is both wrong and
an easy way to lock a real customer out of their own account.

The counters live in memory here. A real deployment needs a shared store
(Redis, the database) so the limit holds across instances; otherwise
attacking one instance resets it.""",
    18: """Spring Security already rotates the session id on login — the lab
disables it with `sessionFixation(none())`. Deleting that line restores the
protection.

If you are not using Spring Security's authentication flow, rotate it
yourself: invalidate the old session and create a new one. Either way, the
new id must be the only one that works — the old id has to stop
authenticating immediately, not just be replaced in the cookie.

The verification checks that second half specifically: the planted id is
replayed after login and must be refused.""",
    19: """The token has to be unpredictable, single-use, and expiring.

- **Unpredictable**: `SecureRandom` bytes, base64url encoded. Never a hash
  of something the attacker knows.
- **Single-use**: mark it used when it is redeemed, and refuse a replay.
- **Expiring**: store an expiry and check it. A reset token that never
  expires is a permanent credential.

Also: never send the token to the address the request claims. That turns
the endpoint from "an attacker can request a reset" into "an attacker can
take over any account".""",
    20: """Do not deserialize untrusted bytes. The safest fix is to accept
JSON instead of a serialized object.

If the format has to stay, install an `ObjectInputFilter` that allowlists
the classes you expect, and reject everything else. That still leaves a
gadget-chain risk within the allowed classes, so allowlist as narrowly as
possible.

In production you would also run the deserialization inside a sandbox —
Java's native serialization was removed from the JDK for exactly this
reason.""",
    21: """Use a parser that pins the algorithm and verifies the signature.
jjwt's `parseSignedClaims` rejects `alg:none` and every algorithm other
than HS256, which is exactly what the hand-rolled parser failed to do.

The bug was not "the signature check was weak" — it was that **the parser
never looked at the `alg` header at all**, so the attacker chose how the
token would be verified. A token that says `alg:none` says "do not verify
me", and the parser obliged.

Never write your own JWT parser. The format is simple enough to be
tempting and the failure modes are subtle.""",
    22: """The stored name has to be one you generated, and the served
content type has to be one you chose.

- Generate the stored name yourself (a UUID) and drop the original
  extension, or map it to a fixed extension. The client's filename is
  attacker-controlled input.
- Serve uploads from **outside** the web root, or from a path that is not
  statically mapped.
- Serve the content as `application/octet-stream`, or `Content-Disposition:
  attachment`. `text/html` turns a stored file into stored XSS in the
  bank's own origin.

The verification checks both halves: the file must not keep your name, and
it must not come back as HTML.""",
    23: """Catch the parse failure and return a clean 400. Turn off the
global stack-trace inclusion (`server.error.include-stacktrace=never`).

This lab has its own `@ExceptionHandler`, so it is independent of Lab 24 —
fixing one does not touch the other. That separation is deliberate: the
two labs teach different lessons (a verbose error page versus a leaky
error message).

Also validate the input at the boundary. If `id` is a number, parse it as
a number and reject a non-number with a clear message; do not let an
`Integer.parseInt` exception become the error response.""",
    24: """Handle `HttpMessageNotReadableException` yourself and return a
generic message. The exception's own message names the DTO's package, class
and every field — a free map of the application's internals.

This lab has its own `@ExceptionHandler`, so it is independent of Lab 23:
fixing one does not change the other.

The general rule: an exception message is attacker-visible. Say what went
wrong in terms the caller can act on, and keep the detail in your logs,
where it belongs.""",
    25: """The filter must fail closed. A token that names no identity is a
401, not a default principal.

The bug was a **default identity**: when the filter could not establish who
the caller was, it carried on with `user_id = 1`, which happens to be the
admin. Anything that fails to identify the caller must stop the request.

This is the same shape as Lab 21, and the two are independent by design:
Lab 21's fix changes the *parser*, Lab 25's changes the *filter*. Fixing
one leaves the other exactly as it was.

The trigger here is "the token was accepted but named no identity" — a
service token, or a token for a user that has been deleted. A token that
fails to parse is a different case, and that one was always a 401.""",
}
