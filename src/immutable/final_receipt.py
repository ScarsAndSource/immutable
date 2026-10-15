"""Strict offline validation for server-signed v2 FINAL receipts (``IMR2.``)."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Iterable

from . import canon, hashing, keys
from .roster import Roster
from .submission import SubmissionError, parse_manifest

PREFIX = "IMR2."
MAX_TOKEN_CHARS = 4096
_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_KEY = re.compile(r"^[a-z0-9_]+$")
_FIELDS = {"v", "kind", "exam_id", "session_id", "ws_id", "candidate", "final_seq", "head",
           "manifest_sha256", "file_count", "submit_seq", "reason", "finalized_ms",
           "last_confirmed_ms", "outage_count", "outage_total_ms", "journal_head",
           "roster_sha256", "schedule_sha256", "paper_sha256", "server_id"}


class FinalReceiptError(ValueError):
    pass


@dataclass(frozen=True)
class Check:
    code: str
    ok: bool
    text: str
    required: bool = True


@dataclass(frozen=True)
class Result:
    checks: tuple[Check, ...]
    body: dict | None

    @property
    def valid(self) -> bool:
        return all(c.ok for c in self.checks if c.required)

    def to_dict(self) -> dict:
        return {"valid": self.valid, "checks": [c.__dict__ for c in self.checks],
                "receipt": self.body, "limits": "A valid FINAL shows server-signed facts, not who was at the keyboard."}


def encode(raw: bytes) -> str:
    return PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(token: str) -> bytes:
    text = "".join(token.split())
    at = text.find(PREFIX)
    if at < 0:
        raise FinalReceiptError("this is not an IMR2 receipt")
    text, part = text[at:], text[at + len(PREFIX):]
    if len(text) > MAX_TOKEN_CHARS or not _B64.fullmatch(part):
        raise FinalReceiptError("receipt text is damaged or too long")
    try:
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except ValueError as e:
        raise FinalReceiptError("receipt text is damaged") from e
    if encode(raw) != text:
        raise FinalReceiptError("receipt text is not canonical base64url")
    return raw


def parse(token: str) -> tuple[dict, bytes]:
    raw = decode(token)
    try:
        doc = canon.loads(raw, max_bytes=MAX_TOKEN_CHARS, require_canonical=True)
    except canon.CanonError as e:
        raise FinalReceiptError(f"receipt is not canonical JSON: {e}") from None
    if not isinstance(doc, dict) or set(doc) != {"body", "sig"} or not isinstance(doc["body"], dict):
        raise FinalReceiptError("receipt must be {body, sig}")
    body, sig = doc["body"], doc["sig"]
    if set(body) != _FIELDS or any(not isinstance(k, str) or not _KEY.fullmatch(k) for k in body):
        raise FinalReceiptError("receipt body has unexpected or non-ASCII keys")
    if body["v"] != 2 or body["kind"] != "final" or not hashing.is_hex(sig, 128):
        raise FinalReceiptError("receipt version, kind, or signature is invalid")
    if not all(isinstance(body[k], str) and body[k] for k in ("exam_id", "session_id", "ws_id", "candidate", "server_id")):
        raise FinalReceiptError("receipt identifiers are invalid")
    if body["reason"] not in ("submitted", "window_end", "grace_expired"):
        raise FinalReceiptError("receipt reason is invalid")
    for k in ("head", "manifest_sha256", "journal_head", "roster_sha256", "schedule_sha256", "paper_sha256"):
        if not hashing.is_hash(body[k]):
            raise FinalReceiptError(f"receipt {k} is invalid")
    for k in ("final_seq", "file_count", "finalized_ms", "last_confirmed_ms", "outage_count", "outage_total_ms"):
        if not isinstance(body[k], int) or isinstance(body[k], bool) or body[k] < 0:
            raise FinalReceiptError(f"receipt {k} is invalid")
    if body["submit_seq"] is not None and (not isinstance(body["submit_seq"], int) or body["submit_seq"] < 0):
        raise FinalReceiptError("receipt submit_seq is invalid")
    return body, raw


def validate(token: str, roster: Roster, *, manifests: Iterable[bytes] = ()) -> Result:
    checks: list[Check] = []
    def add(code: str, ok: bool, text: str, required: bool = True) -> None:
        checks.append(Check(code, ok, text, required))
    try:
        body, raw = parse(token)
    except FinalReceiptError as e:
        add("F_READABLE", False, str(e))
        return Result(tuple(checks), None)
    add("F_READABLE", True, "The FINAL receipt is canonical and well formed.")
    server = roster.server(body["server_id"])
    add("F_SERVER", server is not None, "The signing server is pinned by the roster." if server else "The server is not in the roster.")
    add("F_SIGNATURE", bool(server and keys.verify(hashing.FINAL, server.pub, canon.dumps(body), canon.loads(raw)["sig"])),
        "The server signature verifies." if server and keys.verify(hashing.FINAL, server.pub, canon.dumps(body), canon.loads(raw)["sig"]) else "The server signature does not verify.")
    add("F_EXAM", body["exam_id"] == roster.exam_id, "The receipt names this exam." if body["exam_id"] == roster.exam_id else "The receipt names another exam.")
    seat = roster.seat(body["ws_id"])
    add("F_SEAT", bool(seat and seat.candidate == body["candidate"]),
        "The receipt candidate matches the rostered seat." if seat and seat.candidate == body["candidate"] else "The receipt candidate does not match the rostered seat.")
    add("F_ROSTER", body["roster_sha256"] == roster.id, "The receipt pins this roster." if body["roster_sha256"] == roster.id else "The receipt pins another roster.")
    add("F_PAPER", body["paper_sha256"] == roster.paper_sha256, "The receipt pins this paper." if body["paper_sha256"] == roster.paper_sha256 else "The receipt pins another paper.")
    if manifests:
        found = False
        for raw_manifest in manifests:
            try:
                manifest = parse_manifest(raw_manifest)
            except SubmissionError:
                continue
            if hashing.sha256_hex(raw_manifest) == body["manifest_sha256"]:
                found = True
                add("F_MANIFEST", len(manifest["files"]) == body["file_count"], "Manifest matches FINAL." if len(manifest["files"]) == body["file_count"] else "Manifest count differs from FINAL.")
                break
        if not found:
            add("F_MANIFEST", False, "No supplied manifest matches the FINAL receipt.")
    return Result(tuple(checks), body)
