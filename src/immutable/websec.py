"""websec.py (B13): the console's front door.

The console runs student code and holds an evidence key on a machine the student uses.
So the only thing allowed to talk to it is its own page, in the same browser session:

  * Host must be a loopback name with our port (defeats DNS rebinding)
  * /api needs the session cookie the console set when it served the page
  * a request that names another Origin, or is cross-site, is refused
  * POST must be JSON (a cross-origin page cannot send that without a preflight we never answer)
  * bodies are capped, and the expensive endpoints are rate limited
  * in exam mode the assessor, witness and tamper-lab endpoints do not exist
"""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie

COOKIE = "im_session"
MAX_BODY = 2 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
EXAM_BLOCKED = ("/api/assessor/", "/api/tamperlab/", "/api/witness/", "/api/receipt/check")
RATE_LIMITED = {                      # path: (burst, refill per second)
    "/api/student/run": (5, 1.0),
    "/api/student/file": (30, 10.0),
    "/api/tamperlab/run": (3, 0.5),
}


class TooLarge(ValueError):
    pass


class Bucket:
    def __init__(self, burst: int, per_s: float):
        self.cap, self.rate = float(burst), per_s
        self.tokens, self.t = float(burst), time.monotonic()
        self._lock = threading.Lock()

    def take(self) -> float:
        """0.0 if allowed, else seconds to wait."""
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.cap, self.tokens + (now - self.t) * self.rate)
            self.t = now
            if self.tokens >= 1:
                self.tokens -= 1
                return 0.0
            return (1 - self.tokens) / self.rate


@dataclass
class Sec:
    token: str
    hosts: frozenset
    public_hosts: frozenset = frozenset()   # bare hostnames served over https behind a proxy
    mode: str = "demo"
    buckets: dict = field(default_factory=dict)

    @classmethod
    def create(cls, host: str, port: int, mode: str = "demo") -> "Sec":
        if mode not in ("demo", "exam"):
            raise ValueError("mode must be demo or exam")
        names = {"127.0.0.1", "localhost", "[::1]"}
        if host not in ("0.0.0.0", "::", ""):
            names.add(host)
        # Hosted deploy: IMMUTABLE_PUBLIC_HOST="my-app.onrender.com" (comma separated).
        pub = frozenset(h.strip().lower() for h in
                        os.environ.get("IMMUTABLE_PUBLIC_HOST", "").split(",") if h.strip())
        return cls(token=secrets.token_urlsafe(32),
                   hosts=frozenset(f"{n}:{port}" for n in names) | pub,
                   public_hosts=pub, mode=mode,
                   buckets={p: Bucket(*v) for p, v in RATE_LIMITED.items()})


def _cookie_ok(header: str, token: str) -> bool:
    try:
        jar = SimpleCookie()
        jar.load(header)
    except CookieError:
        return False
    m = jar.get(COOKIE)
    return m is not None and hmac.compare_digest(m.value.encode(), token.encode())


def check(sec: Sec, method: str, path: str, headers) -> tuple[int, str, int] | None:
    """None if the request may proceed, else (status, message, retry_after_seconds)."""
    if (headers.get("Host") or "").lower() not in sec.hosts:
        return 421, "unexpected Host header", 0
    if not path.startswith("/api/"):
        return None
    if sec.mode == "exam" and path.startswith(EXAM_BLOCKED):
        return 403, "not available in exam mode", 0
    site = headers.get("Sec-Fetch-Site")
    if site not in (None, "same-origin") and not (site == "none" and method == "GET"):
        return 403, "cross-site request refused", 0
    origin = headers.get("Origin")
    ok_origins = {"http://" + h for h in sec.hosts} | {"https://" + h for h in sec.public_hosts}
    if origin is not None and origin.lower() not in ok_origins:
        return 403, "cross-origin request refused", 0
    if method == "POST" and not (headers.get("Content-Type") or "").lower().startswith("application/json"):
        return 415, "JSON requests only", 0
    if not _cookie_ok(headers.get("Cookie") or "", sec.token):
        return 401, "no session: open the console page first", 0
    bucket = sec.buckets.get(path)
    if bucket is not None and method == "POST":
        wait = bucket.take()
        if wait:
            return 429, "too many requests, slow down", max(1, int(wait + 0.999))
    return None


def session_cookie(token: str) -> str:
    secure = "; Secure" if os.environ.get("IMMUTABLE_PUBLIC_HOST") else ""
    return f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict{secure}"


def security_headers(report_only: bool = False) -> dict[str, str]:
    csp = ("default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
           "font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
           "form-action 'none'; frame-ancestors 'none'")
    return {
        ("Content-Security-Policy-Report-Only" if report_only else "Content-Security-Policy"): csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
