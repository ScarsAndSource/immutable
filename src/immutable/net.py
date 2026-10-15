"""net.py (B9): the witness on a wire, with nothing but the standard library.

Plain HTTP on the lab LAN is fine because nothing on it is secret or trusted:
every payload is signed, anchors are signed, and a tampered response is just a bad
anchor the assessor rejects. TLS would add key-distribution work for no gain here.

  POST /v1/batch   body = batch file  -> 200 + anchor file | 4xx {"error","detail"}
  POST /v1/ping    body = ping file   -> 200 {"ok","held_upto","seen_ms"}
  GET  /v1/status                      -> witness report (pseudonymous ids only)

4xx means "this will never succeed, stop retrying". Network errors and 5xx mean
"try again later". The courier relies on exactly that split.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import canon
from .batch import MAX_BATCH_BYTES
from .witness import Reply, Witness


class _Handler(BaseHTTPRequestHandler):
    server_version = "immutable-witness"
    timeout = 10

    def log_message(self, *_a):                      # silence per-request logging
        pass

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
        if self.path != "/v1/status":
            return self._send(404, canon.dumps({"error": "not_found", "detail": self.path[:80]}))
        import json
        self._send(200, json.dumps(self.server.witness.report(), sort_keys=True).encode())


class WitnessServer:
    def __init__(self, witness: Witness, host: str = "0.0.0.0", port: int = 9443):
        self.httpd = ThreadingHTTPServer((host, port), _Handler)
        self.httpd.daemon_threads = True
        self.httpd.witness = witness

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

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
