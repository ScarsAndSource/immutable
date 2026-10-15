"""test_v2_server.py: smoke tests for the v2 server-side protocol components.

Tests:
  - final_receipt: encode/decode/parse/verify round-trip
  - courier_v2: construction and status_dict()
  - IMR2 token format compliance (FORMAT_V2 §11)

All tests are offline (no network, no Supabase) and run with:
    pytest tests/test_v2_server.py -v
"""
from __future__ import annotations

import json
import time

import pytest

from immutable import canon, hashing, keys
from immutable.final_receipt import (
    FinalReceiptError,
    decode,
    encode,
    parse,
    validate,
)
from immutable.roster import Roster, Seat, Server, Witness


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_roster(assessor_signer: keys.Signer, ws_signer: keys.Signer,
                  server_signer: keys.Signer) -> Roster:
    """Build a v2 roster with one seat and one server."""
    seat = Seat(ws_id="STN-01", pub=ws_signer.pub_hex, candidate="CNTR-001")
    witness = Witness(witness_id="W01", pub=keys.Signer.generate().pub_hex)
    server = Server(server_id="server-01", pub=server_signer.pub_hex)
    return Roster.build(
        assessor_signer,
        exam_id="EXAM-2026-V2",
        paper_sha256=hashing.sha256_hex(b"paper content"),
        seats=[seat],
        witnesses=[witness],
        servers=[server],
    )


def _build_final_bytes(server_signer: keys.Signer, roster: Roster,
                       *, reason: str = "submitted") -> bytes:
    """Build a minimal valid FINAL receipt document (signed by server key)."""
    body = {
        "v": 2,
        "kind": "final",
        "exam_id": roster.exam_id,
        "session_id": "S001",
        "ws_id": "STN-01",
        "candidate": "CNTR-001",
        "final_seq": 42,
        "head": "a" * 64,
        "manifest_sha256": "b" * 64,
        "file_count": 3,
        "submit_seq": 42,
        "reason": reason,
        "finalized_ms": int(time.time() * 1000),
        "last_confirmed_ms": int(time.time() * 1000) - 1000,
        "outage_count": 0,
        "outage_total_ms": 0,
        "journal_head": "c" * 64,
        "roster_sha256": roster.id,
        "schedule_sha256": "d" * 64,
        "paper_sha256": roster.paper_sha256,
        "server_id": "server-01",
    }
    body_bytes = canon.dumps(body)
    sig = server_signer.sign(hashing.FINAL, body_bytes)
    doc = {"body": canon.loads(body_bytes), "sig": sig}
    return canon.dumps(doc)


# ---------------------------------------------------------------------------
# Tests: encode / decode round-trip
# ---------------------------------------------------------------------------

def test_encode_decode_roundtrip():
    raw = b"\x00\x01\x02\x03" * 16
    token = encode(raw)
    assert token.startswith("IMR2.")
    assert decode(token) == raw


def test_decode_rejects_wrong_prefix():
    with pytest.raises(FinalReceiptError, match="not an IMR2"):
        decode("IMR1.AAAA")


def test_decode_rejects_too_long():
    # 3100 bytes → ~4138 base64 chars + 5 for "IMR2." prefix → > 4096
    raw = b"x" * 3100
    token = encode(raw)
    assert len(token) > 4096, f"token len={len(token)}, need >4096"
    with pytest.raises(FinalReceiptError, match="too long|damaged"):
        decode(token)


def test_decode_rejects_invalid_chars():
    with pytest.raises(FinalReceiptError):
        decode("IMR2.!!!!")


# ---------------------------------------------------------------------------
# Tests: parse
# ---------------------------------------------------------------------------

def test_parse_valid_final():
    assessor = keys.Signer.generate()
    ws = keys.Signer.generate()
    server = keys.Signer.generate()
    roster = _build_roster(assessor, ws, server)
    raw = _build_final_bytes(server, roster)
    token = encode(raw)
    result = validate(token, roster)
    assert result.valid, [c for c in result.checks if not c.ok]


def test_parse_rejects_wrong_sig():
    assessor = keys.Signer.generate()
    ws = keys.Signer.generate()
    server = keys.Signer.generate()
    wrong_server = keys.Signer.generate()   # different key
    roster = _build_roster(assessor, ws, server)
    raw = _build_final_bytes(wrong_server, roster)  # signed by wrong key
    token = encode(raw)
    result = validate(token, roster)
    assert not result.valid
    failed_codes = {c.code for c in result.checks if not c.ok}
    assert "F_SIGNATURE" in failed_codes or "F_SERVER" in failed_codes


def test_parse_rejects_wrong_exam_id():
    assessor = keys.Signer.generate()
    ws = keys.Signer.generate()
    server = keys.Signer.generate()
    roster = _build_roster(assessor, ws, server)
    raw = _build_final_bytes(server, roster)
    # Tamper the exam_id in the body
    doc = canon.loads(raw)
    doc["body"]["exam_id"] = "WRONG-EXAM"
    # Re-sign with the correct server key
    body_bytes = canon.dumps(doc["body"])
    sig = server.sign(hashing.FINAL, body_bytes)
    doc["sig"] = sig
    tampered = canon.dumps(doc)
    token = encode(tampered)
    result = validate(token, roster)
    assert not result.valid


def test_parse_rejects_all_reasons():
    assessor = keys.Signer.generate()
    ws = keys.Signer.generate()
    server = keys.Signer.generate()
    roster = _build_roster(assessor, ws, server)
    for reason in ("submitted", "window_end", "grace_expired"):
        raw = _build_final_bytes(server, roster, reason=reason)
        result = validate(encode(raw), roster)
        assert result.valid, f"reason={reason!r} failed: {[c for c in result.checks if not c.ok]}"


def test_parse_rejects_bad_reason():
    assessor = keys.Signer.generate()
    ws = keys.Signer.generate()
    server = keys.Signer.generate()
    roster = _build_roster(assessor, ws, server)
    raw = _build_final_bytes(server, roster)
    doc = canon.loads(raw)
    doc["body"]["reason"] = "hacked"
    body_bytes = canon.dumps(doc["body"])
    sig = server.sign(hashing.FINAL, body_bytes)
    doc["sig"] = sig
    token = encode(canon.dumps(doc))
    with pytest.raises(FinalReceiptError):
        parse(token)


# ---------------------------------------------------------------------------
# Tests: courier_v2 construction (no network)
# ---------------------------------------------------------------------------

def test_courier_v2_construction():
    from immutable.courier_v2 import CourierV2
    assessor = keys.Signer.generate()
    ws = keys.Signer.generate()
    server = keys.Signer.generate()
    roster = _build_roster(assessor, ws, server)
    c = CourierV2(
        "https://example.supabase.co",
        ws,
        exam_id=roster.exam_id,
        session_id="S001",
        ws_id="STN-01",
        server_id="server-01",
        roster=roster,
    )
    assert c.held_upto == -1
    assert c.held_head == hashing.ZERO
    status = c.status_dict()
    assert status["delivered_upto"] == -1
    assert not status["rejected"]


def test_courier_v2_status_advances():
    from immutable.courier_v2 import CourierV2
    assessor = keys.Signer.generate()
    ws = keys.Signer.generate()
    server = keys.Signer.generate()
    roster = _build_roster(assessor, ws, server)
    c = CourierV2(
        "https://example.supabase.co",
        ws,
        exam_id=roster.exam_id,
        session_id="S001",
        ws_id="STN-01",
        server_id="server-01",
        roster=roster,
    )
    # Simulate a successful open response
    c.held_upto = 5
    c.held_head = "e" * 64
    status = c.status_dict()
    assert status["delivered_upto"] == 5
