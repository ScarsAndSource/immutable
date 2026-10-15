"""tests/test_board.py: unit tests for board policy and integration tests for WitnessServer and ImmutableService teacher board."""
from __future__ import annotations

import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from immutable import keys
from immutable.board import (
    BoardPolicy,
    BoardService,
    classify,
    gaps,
    lab_events,
)
from immutable.net import WitnessServer
from immutable.roster import Roster, Seat
from immutable.roster import Witness as RosterWitness
from immutable.server import ImmutableService, ImmutableWebServer
from immutable.witness import Witness


# ---------------------------------------------------------------------------
# Unit tests: pure logic
# ---------------------------------------------------------------------------

def test_classify_thresholds():
    p = BoardPolicy(active_ms=25_000, offline_ms=60_000)
    now = 100_000
    # active: age <= 25_000
    raw_active = {"ws": "STN-01", "session": "S1", "first_contact_ms": 90_000, "last_contact_ms": 95_000}
    assert classify(raw_active, now, p)["status"] == "active"

    # quiet: 25_000 < age <= 60_000
    raw_quiet = {"ws": "STN-01", "session": "S1", "first_contact_ms": 50_000, "last_contact_ms": 65_000}
    assert classify(raw_quiet, now, p)["status"] == "quiet"

    # offline: age > 60_000
    raw_offline = {"ws": "STN-01", "session": "S1", "first_contact_ms": 10_000, "last_contact_ms": 30_000}
    assert classify(raw_offline, now, p)["status"] == "offline"


def test_classify_not_started_and_transferred():
    p = BoardPolicy()
    now = 100_000
    # Not started (enrolled, no contact)
    raw_not_started = {"ws": "STN-02", "session": None, "enrolled": True}
    assert classify(raw_not_started, now, p)["status"] == "not_started"

    # Transferred
    raw_transferred = {"ws": "STN-03", "session": "S3", "transferred": True}
    assert classify(raw_transferred, now, p)["status"] == "transferred"


def test_lab_events_triggers_on_clustered_dropouts():
    p = BoardPolicy(lab_min_seats=3, lab_fraction_pct=40, lab_window_ms=30_000, active_ms=20_000)
    now = 100_000
    # 5 seats total, 3 seats went quiet around timestamp 70_000 (age 30s > 20s active_ms)
    seats = [
        {"ws": "STN-01", "status": "offline", "severity": 0, "age_ms": 30_000, "last_contact_ms": 70_000},
        {"ws": "STN-02", "status": "offline", "severity": 0, "age_ms": 30_000, "last_contact_ms": 71_000},
        {"ws": "STN-03", "status": "offline", "severity": 0, "age_ms": 30_000, "last_contact_ms": 72_000},
        {"ws": "STN-04", "status": "active", "severity": 4, "age_ms": 5_000, "last_contact_ms": 95_000},
        {"ws": "STN-05", "status": "active", "severity": 4, "age_ms": 5_000, "last_contact_ms": 95_000},
    ]
    events = lab_events(seats, now, p)
    assert len(events) == 1
    assert events[0]["kind"] == "dropout"
    assert events[0]["count"] == 3


def test_gaps_finds_silences():
    ts = [10_000, 20_000, 30_000, 70_000, 80_000]
    out = gaps(ts, min_gap_ms=25_000)
    assert len(out) == 1
    assert out[0]["from_ms"] == 30_000
    assert out[0]["to_ms"] == 70_000
    assert out[0]["gap_ms"] == 40_000


def test_board_service_snapshot():
    class DummyWitness:
        def clock_ms(self):
            return 100_000

        def board_raw(self, now_ms=None):
            return {
                "now_ms": 100_000,
                "witness": "W01",
                "exam_id": "EXAM-1",
                "seats": [
                    {
                        "ws": "STN-01",
                        "session": "S1",
                        "first_contact_ms": 80_000,
                        "last_contact_ms": 95_000,
                        "held_upto": 5,
                        "agent_last_seq": 8,
                        "last_action": {"type": "FILE_SAVE", "seq": 5, "wall_ms": 94_000, "seen_ms": 94_500},
                    },
                    {
                        "ws": "STN-02",
                        "session": None,
                        "enrolled": True,
                    },
                ],
            }

        def seat_trail(self, session, ws, min_gap_ms=25_000, now_ms=None):
            return {"session": session, "ws": ws, "contacts_seen": 5, "boots": [], "gaps": []}

    svc = BoardService(DummyWitness())
    snap = svc.snapshot(include_extra=False)
    assert snap["counts"]["total"] == 2
    assert len(snap["seats"]) == 2
    # STN-01 is active with 3 waiting unsent events
    stn1 = next(s for s in snap["seats"] if s["ws"] == "STN-01")
    assert stn1["status"] == "active"
    assert stn1["waiting"] == 3
    assert stn1["last_action"]["type"] == "FILE_SAVE"


# ---------------------------------------------------------------------------
# Integration tests: WitnessServer HTTP routes
# ---------------------------------------------------------------------------

@pytest.fixture
def running_server(tmp_path):
    assessor_signer = keys.Signer.generate()
    witness_signer = keys.Signer.generate()
    ws_signer = keys.Signer.generate()

    roster = Roster.build(
        assessor_signer,
        exam_id="EXAM-TEST",
        paper_sha256="0" * 64,
        seats=[Seat(ws_id="STN-01", pub=ws_signer.pub_hex, candidate="C01")],
        witnesses=[RosterWitness(witness_id="W01", pub=witness_signer.pub_hex)],
    )

    witness = Witness(roster, witness_signer, "W01", directory=tmp_path / "witness")
    srv = WitnessServer(
        witness=witness,
        host="127.0.0.1",
        port=0,
        teacher_token="super-secret-token-123456",
        board_policy=BoardPolicy(),
    )
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.port}"
    try:
        yield base, witness
    finally:
        srv.shutdown()
        witness.close()


def _get(url: str, token: str | None = None) -> tuple[int, dict | str]:
    req = urllib.request.Request(url)
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
            ct = resp.headers.get("Content-Type", "")
            if "application/json" in ct:
                return resp.status, json.loads(data.decode("utf-8"))
            return resp.status, data.decode("utf-8")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body


def test_teacher_routes_disabled_when_no_token(tmp_path):
    assessor_signer = keys.Signer.generate()
    witness_signer = keys.Signer.generate()
    roster = Roster.build(
        assessor_signer,
        exam_id="EXAM-TEST",
        paper_sha256="0" * 64,
        seats=[],
        witnesses=[RosterWitness(witness_id="W01", pub=witness_signer.pub_hex)],
    )
    witness = Witness(roster, witness_signer, "W01", directory=tmp_path / "witness")
    srv = WitnessServer(witness=witness, host="127.0.0.1", port=0, teacher_token="")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{srv.port}"
    try:
        code, _ = _get(f"{base}/v1/board")
        assert code == 404  # Board routes are disabled and 404 when teacher_token is empty
    finally:
        srv.shutdown()
        witness.close()


def test_teacher_routes_reject_bad_token(running_server):
    base, _ = running_server
    # Missing token -> 401
    code, _ = _get(f"{base}/v1/board")
    assert code == 401
    # Wrong token -> 401
    code, _ = _get(f"{base}/v1/board", token="wrong-token-abcde")
    assert code == 401


def test_teacher_board_authorized(running_server):
    base, witness = running_server
    code, body = _get(f"{base}/v1/board", token="super-secret-token-123456")
    assert code == 200
    assert "seats" in body
    assert body["counts"]["total"] >= 1
    stn1 = next(s for s in body["seats"] if s["ws"] == "STN-01")
    assert stn1["status"] == "not_started"


def test_teacher_page_served_as_html(running_server):
    base, _ = running_server
    code, text = _get(f"{base}/teacher")
    assert code == 200
    assert "<!DOCTYPE html>" in text or "<html" in text
    assert "Immutable" in text


# ---------------------------------------------------------------------------
# Console demo: ImmutableWebServer /api/teacher/board and /api/mode
# ---------------------------------------------------------------------------

def test_web_console_teacher_api(tmp_path):
    server = ImmutableWebServer(host="127.0.0.1", port=0, root_dir=tmp_path, mode="demo")
    server.start()
    base_url = f"http://127.0.0.1:{server.port}"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    try:
        # Establish session cookie
        with opener.open(f"{base_url}/", timeout=5) as r:
            assert r.status == 200

        # Mode endpoint
        with opener.open(f"{base_url}/api/mode", timeout=5) as r:
            assert r.status == 200
            data = json.loads(r.read())
            assert data["mode"] == "demo"

        # Teacher board in demo mode
        with opener.open(f"{base_url}/api/teacher/board", timeout=5) as r:
            assert r.status == 200
            data = json.loads(r.read())
            assert "seats" in data
            assert data["has_simulated"] is True
            # STN-19 real seat present
            assert any(s["ws"] == "STN-19" for s in data["seats"])

    finally:
        server.shutdown()
