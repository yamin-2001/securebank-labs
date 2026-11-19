"""Shared helpers for the SecureBank verification harness.

The harness observes HTTP behaviour only. It never reads application source
and never inspects the application's configuration — a lab counts as fixed only when the
exploit demonstrably stops working.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

try:
    import requests
except ImportError:  # pragma: no cover - dependency check
    sys.exit("The harness needs `requests`. Install it with: pip install requests")


BASE_URL = os.environ.get("SECUREBANK_URL", "http://localhost:8080")

# Seeded credentials (see backend/src/main/resources/data.sql).
CUSTOMERS = {
    "alice": "password123",
    "bob": "qwerty",
    "carol": "letmein",
    "dave": "changeme",
}
# LAB 5 (A02): the admin's password has been rotated away from the shipped
# default, so `admin / admin` no longer authenticates.
ADMIN = ("admin", "S3cure-Admin-Passw0rd!")

TIMEOUT = 10


class Verdict(Enum):
    """The outcome of a single lab check."""

    VULNERABLE = "VULNERABLE"
    FIXED = "FIXED"
    INCONCLUSIVE = "INCONCLUSIVE"

    @property
    def is_pass(self) -> bool:
        return self is not Verdict.INCONCLUSIVE


@dataclass
class Result:
    verdict: Verdict
    detail: str


def ok(verdict: Verdict, detail: str) -> Result:
    return Result(verdict, detail)


class Client:
    """A thin wrapper over ``requests`` with the lab helpers built in."""

    def __init__(self, base_url: str = BASE_URL):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    # ---- raw HTTP -------------------------------------------------------
    def get(self, path: str, token: str | None = None, **kw) -> requests.Response:
        return self._req("GET", path, token=token, **kw)

    def post(self, path: str, token: str | None = None, **kw) -> requests.Response:
        return self._req("POST", path, token=token, **kw)

    def patch(self, path: str, token: str | None = None, **kw) -> requests.Response:
        return self._req("PATCH", path, token=token, **kw)

    def put(self, path: str, token: str | None = None, **kw) -> requests.Response:
        return self._req("PUT", path, token=token, **kw)

    def delete(self, path: str, token: str | None = None, **kw) -> requests.Response:
        return self._req("DELETE", path, token=token, **kw)

    def _req(self, method: str, path: str, token: str | None = None, **kw) -> requests.Response:
        headers = dict(kw.pop("headers", {}) or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        kw.setdefault("timeout", TIMEOUT)
        try:
            return self.session.request(method, self.base + path, headers=headers, **kw)
        except requests.RequestException as exc:
            raise HarnessError(f"{method} {path} failed: {exc}") from exc

    # ---- auth helpers ---------------------------------------------------
    def login(self, username: str, password: str) -> str:
        """Log in and return the bearer token. Raises on failure."""
        r = self.post("/api/auth/login", json={"username": username, "password": password})
        if r.status_code != 200:
            raise HarnessError(
                f"login as {username!r} failed with HTTP {r.status_code}: {r.text[:200]}"
            )
        try:
            return r.json()["token"]
        except (ValueError, KeyError) as exc:
            raise HarnessError(f"login response had no token: {r.text[:200]}") from exc

    def token(self, username: str) -> str:
        """Log in as a seeded customer and return their token."""
        password = CUSTOMERS.get(username)
        if password is None:
            raise HarnessError(f"no seeded password known for {username!r}")
        return self.login(username, password)

    def admin_token(self) -> str:
        return self.login(*ADMIN)

    def reset_state(self) -> bool:
        """Restore the seeded state (balances, roles, password hashes).

        Some exploits mutate the seed in ways that outlive the check that
        made them — a password reset, for instance, leaves the account
        locked out of its seeded credentials. A lab that does that must
        restore the seed afterwards, or the next lab that logs in as that
        account will fail for the wrong reason.
        """
        r = self.post("/api/lab/reset")
        return r.status_code == 200

    # ---- JWT forging ----------------------------------------------------
    @staticmethod
    def b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def forge_jwt(cls, payload: dict[str, Any], alg: str = "none", secret: str = "") -> str:
        """Forge a JWT with an arbitrary algorithm header.

        ``alg="none"`` produces an unsecured token; ``alg="HS256"`` signs the
        token with the given secret (used to show that a leaked secret is
        enough to mint your own admin tokens).
        """
        header = {"alg": alg, "typ": "JWT"}
        segments = [
            cls.b64url(json.dumps(header, separators=(",", ":")).encode()),
            cls.b64url(json.dumps(payload, separators=(",", ":")).encode()),
        ]
        if alg.lower() == "none":
            segments.append("")
        else:
            signing_input = ".".join(segments).encode()
            mac = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            segments.append(cls.b64url(mac))
        return ".".join(segments)


class HarnessError(Exception):
    """Raised when the app is unreachable or returns something unusable."""


def json_body(response: requests.Response) -> Any:
    """Best-effort JSON decode; returns the raw text if it is not JSON."""
    try:
        return response.json()
    except ValueError:
        return response.text


def contains_any(haystack: str, needles: list[str]) -> bool:
    lowered = haystack.lower()
    return any(n.lower() in lowered for n in needles)


def wait_for_app(client: Client, attempts: int = 30, delay: float = 1.0) -> bool:
    """Poll the health endpoint until the app answers, or give up."""
    for _ in range(attempts):
        try:
            r = client.get("/api/health")
            if r.status_code < 500:
                return True
        except HarnessError:
            pass
        time.sleep(delay)
    return False
