# securebank-labs

A deliberately vulnerable banking application with **25 OWASP Top 10 labs**,
built so you can practise finding and fixing them.

Spring Boot 4 + PostgreSQL on the backend, React 18 + Tailwind on the
frontend, Python for the verification harness.

```
frontend/  React 18 + Tailwind + Vite   →  http://localhost:5173
backend/   Spring Boot 4 + PostgreSQL    →  http://localhost:8080
verify/    the harness                    →  python3 verify/run.py
solutions/ the fix reference              →  solutions/SOLUTIONS.md
```

> **This application is intentionally vulnerable.** It exists to be exploited
> and then fixed. Do not deploy it, do not put real data in it, and do not
> point it at anything you care about. The database, the JWT secret and the
> seeded accounts are all lab fixtures.

---

## Start here

**[`WALKTHROUGH.md`](WALKTHROUGH.md) is the guide.** It walks through all 25
labs in order — what each vulnerability is, where in the code it lives, the
exploit steps to reproduce it, what you should see when it works, why it
matters, and a hint for the fix.

This README covers the mechanics: how to build it, how to run it, and how
to check your work.

---

## The one rule

> **A lab is fixed by changing code, and by nothing else.**

There are no flags to flip. Each lab's vulnerability lives in one method,
on one code path, and that path is the only path — the vulnerable code is
the shipped code, with no switch next to it. **Fixing a lab means replacing
that code** with the correct version.

That is what lets the harness assert on behaviour instead of on
configuration: the same exploit succeeds before your fix and fails after
it, with nothing but a code change in between.

If you find yourself looking for a switch to flip, you have not fixed
anything.

### Two branches

| Branch | What it is |
| --- | --- |
| `main` | The shipped **vulnerable** app. Every lab is exploitable. |
| `fixed` | The same app with every lab fixed, one small commit per lab. |

`git switch main` to work on the labs; `git switch fixed` to see what a
complete set of fixes looks like. The commits on `fixed` are deliberately
small — `lab-01 fixed`, `lab-02 fixed`, and so on — so you can read one
lab's fix at a time, or cherry-pick a single one.

---

## Quick start

```bash
make up          # postgres in docker on localhost:5432
make run         # the Spring Boot app on :8080   (leave this running)

# in a second shell
make ui-install  # npm install for the frontend
make ui          # the Vite dev server on :5173  (proxying /api to :8080)
```

Open **http://localhost:5173** and sign in.

### Seeded accounts

| Username | Password     | Role     |
|----------|--------------|----------|
| `admin`  | `admin`      | admin    |
| `alice`  | `password123` | customer |
| `bob`    | `qwerty`     | customer |
| `carol`  | `letmein`    | customer |
| `dave`   | `changeme`   | customer |

`admin` / `admin` works everywhere — that is Lab 5.

### Before you touch anything

```bash
make verify
```

All 25 labs must report `VULNERABLE`. If any report `INCONCLUSIVE`, the
harness and the app disagree about something — fix that first, or you will
be chasing a phantom later.

---

## How to work through a lab

1. Read the lab in [`WALKTHROUGH.md`](WALKTHROUGH.md) — what it is, where it
   lives, how to exploit it, and a hint for the fix.
2. Exploit it by hand. The UI is a real banking app, so most labs are
   reachable through the interface, and every one is reachable with `curl`.
3. Fix it. The walkthrough names the exact file and method.
4. Check your work:

   ```bash
   python3 verify/run.py --lab 13 --expect fixed
   ```

5. The **Reset** button in the navbar restores the seeded balances, roles
   and password hashes, so an exploit in one lab does not leak into the
   next.

The **Labs** panel in the app (top right) shows the same metadata as
`--show`, in the browser.

### The harness

```bash
python3 verify/run.py --list              # the catalogue
python3 verify/run.py --show 13           # title, OWASP, endpoints, fix location
python3 verify/run.py --lab 13            # run one check
python3 verify/run.py --all --expect vulnerable
python3 verify/run.py --all --expect fixed
```

`--show` prints a lab's **metadata** — title, OWASP category, severity,
endpoints, and the file and method to fix. The exploit steps and the hint
live in [`WALKTHROUGH.md`](WALKTHROUGH.md).

Every check returns one of three verdicts:

| Verdict | Meaning |
|---|---|
| `VULNERABLE` | the exploit worked — the lab is live and unfixed |
| `FIXED` | the exploit was blocked — you fixed it |
| `INCONCLUSIVE` | something else happened |

`INCONCLUSIVE` never counts as a pass. It means the check could not be
made — the app was down, the endpoint answered with an unexpected status,
or the exploit's side effect was not observed. Read the detail line; it
says what happened.

---

## The 25 labs

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

## The fixes

`solutions/SOLUTIONS.md` has the fix for every lab: the vulnerable code, the
fixed code, and why.

It is **generated** by `scripts/gen_solutions.py` from the same fix table
the isolation test uses, so the documented fix and the tested fix cannot
drift apart.

```bash
make solutions
```

The lab **metadata** — title, OWASP category, severity — has one source of
truth too: `verify/manifest.json`, which is what `verify/run.py --show`
prints. The Labs panel in the running app reads its copy of that metadata
from `frontend/src/labs.json`, which is generated from the same manifest:

```bash
make labs-json        # regenerate frontend/src/labs.json
make check-labs-json  # fail if it has drifted
```

Two labs need more than a one-line change, and the reference says so:

- **Lab 5** needs the code fix *and* the admin's stored hash rotated in
  `data.sql`. The lab does not flip to `FIXED` until both are done.
- **Lab 7** needs the hasher changed *and* the seed rows re-hashed.

And one lab needs a fix in two places:

- **Lab 13** — escaping in `NoteRenderer` fixes the API endpoint and flips
  the check, but the React app injects the raw note with
  `dangerouslySetInnerHTML` and does not use that renderer. Fix
  `TransfersPage.tsx` as well, or the browser stays vulnerable while the
  harness reports `FIXED`.

---

## Is my fix real?

```bash
make matrix
```

This applies each lab's fix **one at a time**, rebuilds, and asserts that
**exactly one** verdict flips. A fix that breaks a different lab is a bug
in the lab design, not in your work — and this is what catches it.

The shipped build passes this for all 24 code-fixable labs. Lab 6 has no
code fix; it is a file move.

When you are done with everything:

```bash
make verify-fixed
```

All 25 must report `FIXED`.

---

## Layout

```
securebank-labs/
├── Makefile
├── WALKTHROUGH.md                  the guide — all 25 labs, start here
├── docker-compose.yml              postgres only, on localhost:5432
│
├── backend/         Spring Boot 4 + Maven (its own dev server on :8080)
│   ├── pom.xml  mvnw  mvnw.cmd     maven wrapper (3.10.0)
│   │
│   ├── src/main/java/com/securebank/
│   │   ├── core/        AuthContext, PasswordHasher, error handling
│   │   ├── domain/      User, Account, Transfer + JPA repositories
│   │   ├── security/    SecurityConfig, LabAuthFilter, LabJwtService, JwtKeys
│   │   ├── labs/        a01/ a02/ a04/ a05/ a06/ a07/ a08/ a10/ — the 25 labs
│   │   └── ui/          HealthController, LabStateController
│   │
│   ├── src/main/resources/
│   │   ├── application.yml             the weakened settings (verbose errors, etc.)
│   │   ├── schema.sql  data.sql        idempotent schema and seed
│   │   └── static/                     the Lab 6 files: .env, git-config-fixture/, backup.zip
│   │
│   └── src/test/java/com/securebank/  seed-integrity and JWT lab tests
│
├── frontend/        React 18 + Tailwind + Vite (its own dev server on :5173)
│
├── verify/          the harness
│   ├── run.py  common.py  manifest.json
│   ├── labs/        lab01_idor.py … lab25_failopen.py
│   └── payloads/    deserialization payload generator, password hasher
│
├── scripts/
│   ├── app.sh                       start/stop/restart the backend
│   ├── isolation_matrix.py          the fix-isolation test
│   ├── gen_solutions.py             generates solutions/SOLUTIONS.md
│   ├── gen_labs_json.py             generates frontend/src/labs.json
│   ├── real_fixes.py                the production-shaped fix, per lab
│   └── why.py                       the explanation, per lab
│
└── solutions/SOLUTIONS.md           the fix reference (generated)
```

---

## Notes on the build

A few decisions that are not obvious from the code:

**There are no toggles.** The vulnerable build is one code path per
method, with no switch beside it. `main` is that build; `fixed` is the
same app with every lab repaired, one small commit per lab.

**The lab metadata has one source of truth.** `verify/manifest.json` holds
each lab's title, OWASP category and severity — it is what `verify/run.py
--show` prints and what `solutions/SOLUTIONS.md` is generated from. The
Labs panel's copy lives in `frontend/src/labs.json` and is generated from
that same manifest by `scripts/gen_labs_json.py`. Run `make labs-json`
after changing the manifest, and `make check-labs-json` to prove the two
have not drifted.

**Spring Security is on the classpath, deliberately weakened.** Its
defaults would neutralise several labs — the `NimbusJwtDecoder` rejects
`alg:none`, the default entry point is a 302, CSRF blocks the POSTs, and
session-fixation protection rotates the id on login. Each weakening is
marked in `SecurityConfig` with the lab it serves and the fix that undoes
it.

**`ddl-auto=validate`.** `schema.sql` owns the schema; Hibernate only
checks it. A mismatch fails fast and loudly instead of silently mangling
the data.

**The seed is self-healing.** `data.sql` runs on every boot and restores
the balances, roles and password hashes. Exploiting a lab mutates the
database; the seed undoes that, so a lab you already fixed does not start
failing again.

**`data.sql` is written by the matrix too.** Labs 5 and 7 change the
seed, so `scripts/isolation_matrix.py` manages that block centrally and
restores it byte-for-byte.

**Jackson 3, not 2.** `tools.jackson.databind.*`; `JacksonException` is
unchecked. There is no `com.fasterxml.jackson` import anywhere.

**Two servers.** The Vite dev server proxies `/api` to `:8080`, so the
browser stays same-origin and there is no CORS configuration.

**The `/uploads/` path is not served in this build.** `SecurityConfig`
matches `/uploads/**` in the API chain (`@Order(2)`) as well as in the UI
chain (`@Order(3)`), and the lower-order chain wins — so the UI chain's
`permitAll` for uploads is unreachable. Requests there answer `401`
without a token and `500` with one, because `uploads/` is also not a static
resource root. Lab 22's bytes are read back through
`GET /api/integrity/uploads/{name}` instead.

**The Lab 6 `.git` fixture is named `git-config-fixture` in the source
tree.** Git treats a nested `.git` directory as a submodule boundary and
silently refuses to track its contents, so a fixture living at
`static/.git/config` would vanish on every fresh clone. The build renames
it on the way in — the `<resource>` block in `backend/pom.xml` maps
`static/git-config-fixture` to `static/.git` — so the served path is
`/.git/config` exactly as the lab intends.

**A pre-push hook guards the branch contract.** `main` ships the vulnerable
build and `fixed` ships the patched one, and it is easy to push either in
the wrong state by accident. `.githooks/pre-push` checks the cheap static
invariants locally — no toggle mechanism on either branch, no `lab:` block
in `application.yml`, no fixed helper leaking onto `main`, and no vulnerable
code path surviving on `fixed`. Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

It refuses the push and says what is wrong. `--no-verify` overrides it.

---

## Troubleshooting

**The app did not start.** `./scripts/app.sh log` shows the reason. The
usual cause is postgres not being up — `make up` waits for it.

**A lab reports `INCONCLUSIVE`.** Read the detail line. Common causes: the
app was not running, or a previous lab's exploit left the database in a
state that changed the answer. The **Reset** button (or
`curl -X POST localhost:8080/api/lab/reset`) fixes the second kind.

**Port 8080 is in use.** `./scripts/app.sh stop` kills whatever is holding
it.

**The frontend shows a blank page.** Check that the backend is up — the
proxy target is `http://localhost:8080`. `curl localhost:5173/api/health`
should answer `{"status":"up"}`.

**`make verify` fails after I fixed a lab.** That is the point of
`--expect vulnerable`: it asserts the *shipped* build is vulnerable. Use
`--expect fixed` for your own build.

**A lab I fixed still reports `VULNERABLE`.** The detail line says what
the exploit observed. If it says the exploit still landed, the vulnerable
code is still being reached — the fix has to replace the vulnerable line
itself, not sit next to it.

**Lab 13 reports `FIXED` but the browser is still exploitable.** Expected
until you also fix `TransfersPage.tsx`. The harness checks the server's
`/api/transfers/html` endpoint; the React page has its own render path.
