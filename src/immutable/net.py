"""net.py (B9): the witness on a wire, with nothing but the standard library.

Plain HTTP on the lab LAN is fine because nothing on it is secret or trusted:
every payload is signed, anchors are signed, and a tampered response is just a bad
anchor the assessor rejects. TLS would add key-distribution work for no gain here.

  POST /v1/batch   body = batch file  -> 200 + anchor file | 4xx {"error","detail"}
  POST /v1/ping    body = ping file   -> 200 {"ok","held_upto","seen_ms"}
  GET  /v1/status                      -> witness report (pseudonymous ids only)

4xx means "this will never succeed, stop retrying". Network errors and 5xx mean
"try again later". The courier relies on exactly that split.

TEACHER BOARD (off unless a token of 16+ characters is set; see docs/TEACHER_BOARD.md)
  GET  /teacher                        -> the board page (no secrets in it)
  GET  /v1/board                       -> every seat's state          (Bearer token)
  GET  /v1/board/seat?session=&ws=     -> one seat's silences, boots  (Bearer token)
The board is read-only. It cannot write to the witness, and it never shows file names,
contents or code: event types and times only.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import canon, websec
from .batch import MAX_BATCH_BYTES
from .board import BoardPolicy, BoardService
from .events import ID_RE
from .witness import Reply, Witness

MIN_TOKEN = 16
_WEB = (Path(__file__).resolve().parent.parent.parent / "web").resolve()
_TEACHER_FILES = {
    "/teacher": "teacher.html", "/teacher.js": "teacher.js", "/teacher-page.js": "teacher-page.js",
    "/teacher.css": "teacher.css", "/safe.js": "safe.js", "/style.css": "style.css",
    "/vendor/fonts.css": "vendor/fonts.css",
}
_FONT = re.compile(r"^/vendor/fonts/[0-9a-f]{12}\.woff2$")
_MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".woff2": "font/woff2"}
_NOCACHE = {"Cache-Control": "no-store"}


class _Throttle:
    """Per-address bad-token counter: 10 failures in a minute lock that address out for it."""

    def __init__(self, limit: int = 10, window_s: float = 60.0):
        self.limit, self.window = limit, window_s
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, who: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(who, []) if now - t < self.window]
            if hits:
                self._hits[who] = hits
            else:
                self._hits.pop(who, None)
            return len(hits) >= self.limit

    def fail(self, who: str) -> None:
        with self._lock:
            if len(self._hits) > 512 and who not in self._hits:
                return                              # bounded memory, whatever a LAN throws at it
            self._hits.setdefault(who, []).append(time.monotonic())


class _Handler(BaseHTTPRequestHandler):
    server_version = "immutable-witness"
    timeout = 10

    def log_message(self, *_a):                      # silence per-request logging
        pass

    def _send(self, status: int, body: bytes, ctype: str = "application/json",
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, status: int, code: str, detail: str, extra: dict | None = None) -> None:
        self._send(status, canon.dumps({"error": code, "detail": detail[:400]}), extra=extra)

    def do_POST(self):
        w: Witness = self.server.witness
        route = {"/v1/batch": w.submit, "/v1/ping": w.ping}.get(self.path)
        if route is None:
            return self._send(404, canon.dumps({"error": "not_found", "detail": self.path[:80]}))
        n = self.headers.get("Content-Length", "")
        if not n.isdigit():
            return self._send(411, canon.dumps({"error": "length_required", "detail": "no length"}))
        if int(n) > MAX_BATCH_BYTES + 1024:
            return self._send(413, canon.dumps({"error": "too_large", "detail": "body too large"}))
        try:
            raw = self.rfile.read(int(n))
            r: Reply = route(raw)
        except Exception:
            return self._send(500, canon.dumps({"error": "internal", "detail": "witness error"}))
        self._send(r.status, r.body)

    def do_GET(self):
        url = urlsplit(self.path)
        path = url.path
        if path == "/v1/status":
            return self._send(200, json.dumps(self.server.witness.report(), sort_keys=True).encode())
        teacher = getattr(self.server, "teacher", None)
        if teacher is not None:                      # board routes exist only when enabled
            if path in ("/v1/board", "/v1/board/seat"):
                return self._board(teacher, path, url.query)
            if path in _TEACHER_FILES or _FONT.match(path):
                return self._asset(path)
        return self._send(404, canon.dumps({"error": "not_found", "detail": path[:80]}))

    # ---------------------------------------------------------------- teacher board
    def _board(self, teacher: BoardService, path: str, query: str) -> None:
        who = self.client_address[0]
        throttle: _Throttle = self.server.throttle
        if throttle.blocked(who):
            return self._fail(429, "slow_down", "too many bad tokens from this address",
                              {"Retry-After": "60"})
        auth = self.headers.get("Authorization") or ""
        given = auth[7:] if auth[:7].lower() == "bearer " else ""
        if not hmac.compare_digest(given.encode(), self.server.teacher_token.encode()):
            throttle.fail(who)
            return self._fail(401, "unauthorized", "teacher token required",
                              {"WWW-Authenticate": "Bearer"})
        try:
            if path == "/v1/board":
                return self._send(200, json.dumps(teacher.snapshot(), sort_keys=True).encode(),
                                  extra=_NOCACHE)
            q = parse_qs(query)
            ses, ws = (q.get("session") or [""])[0], (q.get("ws") or [""])[0]
            if not ID_RE.match(ws) or not ID_RE.match(ses):
                return self._fail(400, "bad_seat", "session and ws must be seat identifiers")
            trail = teacher.seat(ses, ws)
            if trail is None:
                return self._fail(404, "no_history", "no contact history for that seat")
            return self._send(200, json.dumps(trail, sort_keys=True).encode(), extra=_NOCACHE)
        except Exception:
            print("teacher board error", file=sys.stderr)
            return self._fail(500, "internal", "board error")

    def _asset(self, path: str) -> None:
        rel = _TEACHER_FILES.get(path) or path.lstrip("/")
        target = (_WEB / rel).resolve()
        if not (target.is_relative_to(_WEB) and target.is_file() and target.suffix in _MIME):
            return self._fail(404, "not_found", path)
        headers = dict(websec.security_headers())
        headers["Cache-Control"] = "no-cache"
        self._send(200, target.read_bytes(), _MIME[target.suffix], headers)


class WitnessServer:
    def __init__(self, witness: Witness, host: str = "0.0.0.0", port: int = 9443, *,
                 teacher_token: str | None = None, board_policy: BoardPolicy | None = None):
        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.witness = witness
        self.httpd.teacher = None
        self.httpd.teacher_token = ""
        self.httpd.throttle = _Throttle()
        # teacher_token=None -> read IMMUTABLE_TEACHER_TOKEN; teacher_token="" -> board off.
        token = (os.environ.get("IMMUTABLE_TEACHER_TOKEN", "") if teacher_token is None
                 else teacher_token).strip()
        if token:
            if len(token) < MIN_TOKEN:
                # Fail safe: a weak token must never stop the witness from starting an exam.
                print(f"teacher board stays OFF: the token must be at least {MIN_TOKEN} characters",
                      file=sys.stderr)
            else:
                self.httpd.teacher = BoardService(witness, board_policy or BoardPolicy())
                self.httpd.teacher_token = token

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    @property
    def teacher_enabled(self) -> bool:
        return self.httpd.teacher is not None

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class HttpTransport:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base, self.timeout = base_url.rstrip("/"), timeout

    def _post(self, path: str, raw: bytes) -> tuple[int, bytes]:
        req = urllib.request.Request(self.base + path, data=raw, method="POST",
                                     headers={"Content-Type": "application/octet-stream"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:           # a real answer, just not a 200
            return e.code, e.read()

    def submit(self, raw: bytes) -> tuple[int, bytes]:
        return self._post("/v1/batch", raw)

    def ping(self, raw: bytes) -> tuple[int, bytes]:
        return self._post("/v1/ping", raw)


class LocalTransport:
    """In-process transport for the simulator. `available` returning False = outage."""

    def __init__(self, witness: Witness, available=lambda: True):
        self.w, self.available = witness, available

    def _gate(self) -> None:
        if not self.available():
            raise ConnectionError("witness unreachable")

    def submit(self, raw: bytes) -> tuple[int, bytes]:
        self._gate()
        return tuple(self.w.submit(raw))

    def ping(self, raw: bytes) -> tuple[int, bytes]:
        self._gate()
        return tuple(self.w.ping(raw))
