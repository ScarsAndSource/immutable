"""courier_v2.py: workstation-side HTTP courier for the v2 server-anchored protocol.

Implements the client half of FORMAT_V2 §8 (API calls) and §9 (sync state machine).

Public API
----------
  Courier(base_url, signer, *, exam_id, session_id, ws_id, server_id, roster)
    .open()          -> {server_ms, deadline_ms, held_upto, held_head, rev}
    .upload_batch(batch_bytes) -> ack_bytes
    .upload_blob(sha256, data) -> None
    .ping(boot_id, boot_ns, last_seq) -> {server_ms, remaining_ms, held_upto}
    .finalize()      -> final_receipt_bytes
    .get_receipt()   -> final_receipt_bytes | None

All calls raise CourierError on permanent 4xx; on 5xx or network errors the caller
(SyncController) handles retry scheduling per the state machine.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from typing import Any

from . import canon, hashing, keys
from .final_receipt import FinalReceiptError, decode, validate
from .roster import Roster

_TIMEOUT = 10  # seconds per HTTP call


class CourierError(Exception):
    """Permanent error: stop retrying (4xx)."""
    def __init__(self, code: str, status: int, detail: str = ""):
        super().__init__(f"{code} (HTTP {status}): {detail}")
        self.code = code
        self.status = status


class CourierTransient(Exception):
    """Transient error: retry later (5xx, network)."""


def _call(
    method: str,
    url: str,
    body: bytes | None = None,
    content_type: str = "application/json",
) -> tuple[int, bytes]:
    """Low-level HTTP call. Returns (status, response_bytes)."""
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", content_type)
        req.add_header("Content-Length", str(len(body)))
    req.add_header("Accept", "*/*")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise CourierTransient(str(e)) from e


def _check_4xx(status: int, body: bytes) -> None:
    """Raise CourierError on permanent failure codes."""
    if status < 400:
        return
    try:
        doc = canon.loads(body)
        code = doc.get("error", f"HTTP_{status}")
        detail = str(doc.get("detail", ""))
    except Exception:
        code, detail = f"HTTP_{status}", body[:200].decode("ascii", errors="replace")
    raise CourierError(code, status, detail)


class CourierV2:
    """HTTP client for the v2 Immutable server (Edge Functions)."""

    def __init__(
        self,
        base_url: str,
        signer: keys.Signer,
        *,
        exam_id: str,
        session_id: str,
        ws_id: str,
        server_id: str,
        roster: Roster,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._signer = signer
        self._exam_id = exam_id
        self._session_id = session_id
        self._ws_id = ws_id
        self._server_id = server_id
        self._roster = roster

        # State updated by open() and ping()
        self.held_upto: int = -1
        self.held_head: str = hashing.ZERO
        self.deadline_ms: int = 0
        self.remaining_ms: int = 0
        self.server_rev: int = 1

    # ------------------------------------------------------------------
    # Internal: sign a canonical body dict, return body bytes + sig hex
    # ------------------------------------------------------------------
    def _sign_body(self, domain: str, body: dict[str, Any]) -> tuple[bytes, str]:
        body_bytes = canon.dumps(body)
        sig = self._signer.sign(domain, body_bytes)
        return body_bytes, sig

    def _signed_json(self, domain: str, body: dict[str, Any]) -> bytes:
        body_bytes, sig = self._sign_body(domain, body)
        doc = {"body": canon.loads(body_bytes), "sig": sig}
        # Flatten to a single JSON object for open/finalize requests
        # (the body fields are top-level, sig is alongside)
        flat = {**canon.loads(body_bytes), "sig": sig}
        return canon.dumps(flat)

    # ------------------------------------------------------------------
    # POST /v1/session/open
    # ------------------------------------------------------------------
    def open(self) -> dict:
        """Open or resume a session. Returns {server_ms, deadline_ms, held_upto, held_head, rev}."""
        body = {
            "v": 1,
            "exam_id": self._exam_id,
            "session_id": self._session_id,
            "ws_id": self._ws_id,
        }
        payload = self._signed_json("enroll", body)
        status, resp = _call("POST", f"{self._base}/v1/session/open", payload)
        _check_4xx(status, resp)
        if status >= 500:
            raise CourierTransient(f"server error {status}")
        doc: dict = canon.loads(resp)
        self.held_upto = doc.get("held_upto", -1)
        self.held_head = doc.get("held_head", hashing.ZERO)
        self.deadline_ms = doc.get("deadline_ms", 0)
        self.server_rev = doc.get("rev", 1)
        return doc

    # ------------------------------------------------------------------
    # POST /v1/batch  (raw signed batch bytes → raw ack bytes)
    # ------------------------------------------------------------------
    def upload_batch(self, batch_bytes: bytes) -> bytes:
        """Upload a signed batch. Returns the server-signed ack anchor bytes."""
        status, resp = _call(
            "POST",
            f"{self._base}/v1/batch",
            batch_bytes,
            content_type="application/octet-stream",
        )
        if status == 200:
            return resp
        if status == 409:
            # Parse specific fork/stale codes
            try:
                doc = canon.loads(resp)
                code = doc.get("error", "CONFLICT")
            except Exception:
                code = "CONFLICT"
            if code == "FORK":
                # Equivocation detected — permanent error
                raise CourierError("FORK", 409, str(resp[:200]))
            if code == "STALE":
                # Already held — try GET receipt or re-sync
                raise CourierError("STALE", 409)
            if code == "ROLLBACK":
                raise CourierError("ROLLBACK", 409, "local chain shorter than server; need TRANSFER")
            if code == "FINALIZED":
                raise CourierError("FINALIZED", 410)
        _check_4xx(status, resp)
        if status >= 500:
            raise CourierTransient(f"batch upload server error {status}")
        return resp  # unreachable but keeps type checker happy

    # ------------------------------------------------------------------
    # PUT /v1/blob/:sha256
    # ------------------------------------------------------------------
    def upload_blob(self, sha256: str, data: bytes) -> None:
        """Upload a file blob. Idempotent: 200 on re-upload of same bytes."""
        status, resp = _call(
            "PUT",
            f"{self._base}/v1/blob/{sha256}",
            data,
            content_type="application/octet-stream",
        )
        if status == 200:
            return
        if status == 422:
            raise CourierError("HASH_MISMATCH", 422, "server re-hash disagrees with path")
        _check_4xx(status, resp)
        if status >= 500:
            raise CourierTransient(f"blob upload server error {status}")

    # ------------------------------------------------------------------
    # POST /v1/ping
    # ------------------------------------------------------------------
    def ping(self, boot_id: str, boot_ns: int, last_seq: int) -> dict:
        """Send a heartbeat. Returns {server_ms, remaining_ms, held_upto}."""
        body = {
            "v": 1,
            "exam_id": self._exam_id,
            "session_id": self._session_id,
            "ws_id": self._ws_id,
            "boot_id": boot_id,
            "boot_ns": boot_ns,
            "last_seq": last_seq,
        }
        payload = self._signed_json("ping", body)
        status, resp = _call("POST", f"{self._base}/v1/ping", payload)
        if status == 410:
            raise CourierError("FINALIZED", 410)
        _check_4xx(status, resp)
        if status >= 500:
            raise CourierTransient(f"ping server error {status}")
        doc: dict = canon.loads(resp)
        self.remaining_ms = doc.get("remaining_ms", 0)
        # held_upto from ping is informational; batch acks are authoritative
        return doc

    # ------------------------------------------------------------------
    # POST /v1/finalize
    # ------------------------------------------------------------------
    def finalize(self) -> bytes:
        """Request finalization. Returns the raw FINAL receipt bytes (IMR2 document)."""
        body = {
            "exam_id": self._exam_id,
            "session_id": self._session_id,
            "ws_id": self._ws_id,
        }
        body_bytes = canon.dumps(body)
        sig = self._signer.sign("final", body_bytes)
        payload = canon.dumps({**canon.loads(body_bytes), "sig": sig})
        status, resp = _call("POST", f"{self._base}/v1/finalize", payload)
        if status == 200:
            return resp
        if status == 409:
            try:
                doc = canon.loads(resp)
                code = doc.get("error", "CONFLICT")
                if code == "MISSING_BLOBS":
                    raise CourierError("MISSING_BLOBS", 409, str(doc.get("detail", "")))
            except CourierError:
                raise
            except Exception:
                pass
        if status == 410:
            # Already finalized — fetch the receipt
            return self.get_receipt() or b""
        _check_4xx(status, resp)
        if status >= 500:
            raise CourierTransient(f"finalize server error {status}")
        return resp

    # ------------------------------------------------------------------
    # GET /v1/receipt/:session_id
    # ------------------------------------------------------------------
    def get_receipt(self) -> bytes | None:
        """Fetch the FINAL receipt bytes. Returns None if not yet finalized."""
        status, resp = _call("GET", f"{self._base}/v1/receipt/{self._session_id}")
        if status == 404:
            return None
        if status == 200:
            return resp
        _check_4xx(status, resp)
        if status >= 500:
            raise CourierTransient(f"receipt fetch server error {status}")
        return None

    # ------------------------------------------------------------------
    # Verify a FINAL receipt against the pinned roster
    # ------------------------------------------------------------------
    def verify_receipt(self, raw_bytes: bytes) -> dict:
        """Parse and verify a FINAL receipt. Returns the Result.to_dict() form."""
        from .final_receipt import encode, validate
        token = encode(raw_bytes)
        result = validate(token, self._roster)
        return result.to_dict()

    # ------------------------------------------------------------------
    # Status dict consumed by SyncController._attempt()
    # ------------------------------------------------------------------
    def status_dict(self) -> dict:
        """Return a dict compatible with SyncController's courier status contract."""
        return {
            "delivered_upto": self.held_upto,
            "pending": 0,
            "rejected": False,
        }
