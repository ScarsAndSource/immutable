"""server.py: lightweight HTTP server and REST API for Immutable frontend.

Provides unified endpoints connecting the web interface with:
  - Student workstation Agent (file observer, run_python, checkpoints, submissions)
  - Lab LAN Witness (cosignatures, held heads, refusals)
  - Assessor Store (ingestion, verification, case note generation)
  - Tamper Lab (interactive scenario execution and outcome judging)
"""
from __future__ import annotations

import json
import mimetypes
import os
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import traceback
from . import anchor as anchor_mod, canon, hashing, keys, receipt as receipt_mod, websec
from .policy import is_relpath
from .agent import Agent, AgentError
from .clockcheck import ClockPolicy
from .courier import Courier
from .events import Event
from .net import HttpTransport, WitnessServer
from .report import render
from .roster import Roster, Seat
from .runner import run_python
from .store import Store
from .witness import Witness

DEFAULT_PORT = 8000


class ImmutableService:
    """Manages active runtime instances of Agent, Witness, Store and Tamper Lab."""

    def __init__(self, root_dir: Path | None = None):
        self.lock = threading.RLock()
        self.root_dir = root_dir or Path(tempfile.mkdtemp(prefix="immutable-web-"))
        self.evidence_dir = self.root_dir / "evidence"
        self.workspace_dir = self.root_dir / "workspace"
        self.witness_dir = self.root_dir / "witness"
        self.store_dir = self.root_dir / "store"

        self.evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.witness_dir.mkdir(parents=True, exist_ok=True)
        self.store_dir.mkdir(parents=True, exist_ok=True)

        # Keys
        self.assessor_signer = keys.Signer.generate()
        self.witness_signer = keys.Signer.generate()
        self.ws_signer = keys.Signer.generate()

        # Exam identifiers
        self.exam_id = "EXAM-2024-P1"
        self.session_id = "S8821"
        self.ws_id = "STN-19"
        self.candidate = "CNTR-8821"

        # Exam paper
        self.paper_file = self.root_dir / "paper.pdf"
        self.paper_file.write_bytes(b"%PDF-1.4 Practical Exam: Algorithmic Logics and Systems Security")
        self.paper_sha = hashing.file_sha256(self.paper_file)

        # Roster
        seats = [Seat(ws_id=self.ws_id, pub=self.ws_signer.pub_hex, candidate=self.candidate)]
        from .roster import Witness as RosterWitness
        witnesses = [RosterWitness(witness_id="W01", pub=self.witness_signer.pub_hex)]
        self.roster = Roster.build(
            self.assessor_signer,
            exam_id=self.exam_id,
            paper_sha256=self.paper_sha,
            seats=seats,
            witnesses=witnesses,
        )
        self.roster_sha = self.roster.id

        # Witness instance
        self.witness = Witness(self.roster, self.witness_signer, "W01", directory=self.witness_dir)
        self.witness_server = WitnessServer(self.witness, host="127.0.0.1", port=0)
        self.witness_thread = threading.Thread(target=self.witness_server.serve_forever, daemon=True)
        self.witness_thread.start()

        # Seed initial files in workspace
        self._seed_workspace()

        # Active agent & courier
        self.agent: Agent | None = None
        self.courier: Courier | None = None
        self.last_receipt: dict[str, Any] | None = None
        self._init_agent()

        # Assessor store
        self.store = Store(self.store_dir, self.roster)

    def _seed_workspace(self) -> None:
        sol_file = self.workspace_dir / "solution.py"
        if not sol_file.exists():
            sol_file.write_text(
                '"""Practical Exam: Task 1 - Consistent Digest Matrix"""\n\n'
                "def solve(n: int) -> int:\n"
                "    total = sum(i * i for i in range(n))\n"
                "    print(f'Computed sum of squares for {n}: {total}')\n"
                "    return total\n\n"
                "if __name__ == '__main__':\n"
                "    solve(10)\n"
            )

        test_file = self.workspace_dir / "test_cases.py"
        if not test_file.exists():
            test_file.write_text(
                "import unittest\nfrom solution import solve\n\n"
                "class SolutionTests(unittest.TestCase):\n"
                "    def test_small(self):\n"
                "        self.assertEqual(solve(3), 0 + 1 + 4)\n\n"
                "if __name__ == '__main__':\n"
                "    unittest.main()\n"
            )

    def _init_agent(self) -> None:
        with self.lock:
            if self.courier:
                try:
                    self.courier.stop()
                except Exception:
                    pass
            if self.agent:
                try:
                    self.agent.close()
                except Exception:
                    pass

            self.agent = Agent.open(
                evidence_dir=self.evidence_dir,
                workspace=self.workspace_dir,
                exam_id=self.exam_id,
                session_id=self.session_id,
                ws_id=self.ws_id,
                signer=self.ws_signer,
                paper_sha256=self.paper_sha,
                roster_sha256=self.roster_sha,
                heartbeat_s=30.0,
            )

            witness_url = f"http://127.0.0.1:{self.witness_server.port}"
            self.courier = Courier(
                outbox=self.evidence_dir / "outbox",
                anchors_dir=self.evidence_dir / "anchors",
                state_path=self.evidence_dir / "courier.json",
                transport=HttpTransport(witness_url),
                signer=self.ws_signer,
                exam_id=self.exam_id,
                session_id=self.session_id,
                ws_id=self.ws_id,
            )
            self.courier.start()

    def get_student_session(self) -> dict[str, Any]:
        with self.lock:
            if not self.agent:
                self._init_agent()
            assert self.agent is not None
            self.agent.tick()

            events_data = []
            for ev in self.agent._wal.events:
                events_data.append({
                    "seq": ev.seq,
                    "type": ev.type,
                    "prev": ev.prev,
                    "hash": ev.hash(),
                    "wall_ms": ev.wall_ms,
                    "boot_id": ev.boot_id,
                    "boot_ns": ev.boot_ns,
                    "data": ev.data,
                })

            files = []
            for p in sorted(self.workspace_dir.rglob("*")):
                if p.is_file() and not p.name.startswith("."):
                    rel = p.relative_to(self.workspace_dir).as_posix()
                    raw = p.read_bytes()
                    files.append({
                        "path": rel,
                        "size": len(raw),
                        "sha256": hashing.sha256_hex(raw),
                    })

            courier_status = {}
            if self.courier:
                courier_status = self.courier.status()

            status = self.agent.status()

            # Check anchors count
            anchors_count = 0
            anchors_dir = self.evidence_dir / "anchors"
            if anchors_dir.exists():
                anchors_count = len(list(anchors_dir.glob("*.anchor.json")))

            chain_intact = False
            if self.agent and self.agent._wal.events:
                evs = self.agent._wal.events
                chain_intact = all(
                    evs[i].prev == evs[i - 1].hash() and evs[i].seq == evs[i - 1].seq + 1
                    for i in range(1, len(evs))
                )

            return {
                "exam_id": self.exam_id,
                "session_id": self.session_id,
                "ws_id": self.ws_id,
                "candidate": self.candidate,
                "head": status["head"],
                "last_seq": status["last_seq"],
                "durable_seq": status["durable_seq"],
                "sealed_upto": status["sealed_upto"],
                "ended": status["ended"],
                "events": events_data,
                "files": files,
                "witness": {
                    "anchors_count": anchors_count,
                    "held_upto": courier_status.get("delivered_upto", -1),
                    "pending": courier_status.get("pending", 0),
                    "unreachable_s": self.courier.unreachable_s() if self.courier else 0,
                    "last_error": courier_status.get("last_error"),
                    "chain_intact": chain_intact,
                },
                "receipt": self.last_receipt,
            }

    def save_file(self, rel_path: str, content: str) -> dict[str, Any]:
        with self.lock:
            if not self.agent:
                raise AgentError("Session not initialized")
            if not is_relpath(rel_path):
                raise ValueError("that file name is not allowed")
            if len(content.encode("utf-8")) > websec.MAX_FILE_BYTES:
                raise ValueError("file too large for the editor")
            root = self.workspace_dir.resolve()
            target = (root / rel_path).resolve()
            if not target.is_relative_to(root):
                raise ValueError("Path escapes workspace")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            self.agent.tick()
            return {"ok": True, "path": rel_path, "sha256": hashing.file_sha256(target)}

    def run_code(self, rel_path: str) -> dict[str, Any]:
        with self.lock:
            if not self.agent:
                raise AgentError("Session not initialized")
            if not is_relpath(rel_path):
                raise ValueError("that file name is not allowed")
            res = run_python(self.agent, rel_path)
            if self.courier:
                self.courier.pump_once()
            return {
                "exit_code": res.exit_code,
                "duration_ms": res.duration_ms,
                "timed_out": res.timed_out,
                "stdout": res.stdout.decode("utf-8", "replace"),
                "stderr": res.stderr.decode("utf-8", "replace"),
            }

    def checkpoint(self) -> dict[str, Any]:
        with self.lock:
            if not self.agent:
                raise AgentError("Session not initialized")
            ev = self.agent.checkpoint()
            self.agent.flush()
            if self.courier:
                self.courier.pump_once()
            return {
                "seq": ev.seq,
                "hash": ev.hash(),
                "merkle_root": ev.data.get("merkle_root"),
                "upto_seq": ev.data.get("upto_seq"),
            }

    def flush(self) -> dict[str, Any]:
        with self.lock:
            if not self.agent:
                raise AgentError("Session not initialized")
            batches = self.agent.flush()
            delivered = 0
            if self.courier:
                for _ in range(5):
                    st = self.courier.pump_once()
                    if st.get("pending", 0) == 0:
                        break
                delivered = self.courier.status().get("delivered_upto", 0)
            return {"sealed_batches": len(batches), "delivered_upto": delivered}

    def submit(self) -> dict[str, Any]:
        with self.lock:
            if not self.agent:
                raise AgentError("Session not initialized")
            if self.agent.status()["ended"]:
                return self.last_receipt or {"error": "Already submitted"}

            sub_res = self.agent.submit()
            if self.courier:
                for _ in range(10):
                    st = self.courier.pump_once()
                    if st.get("pending", 0) == 0:
                        break

            # Ingest into assessor store
            self.store.ingest_path(self.evidence_dir)

            a = anchor_mod.parse(sub_res.receipt)
            token = receipt_mod.encode(sub_res.receipt)
            case = self.store.case(ClockPolicy())
            receipt = {
                "kind": "immutable-receipt/1",
                "receipt_id": a.id[:16],
                "exam_id": self.exam_id, "session_id": self.session_id,
                "ws_id": self.ws_id, "candidate": self.candidate,
                "last_seq": sub_res.last_seq, "events": sub_res.last_seq + 1,
                "head": sub_res.head, "head_groups": receipt_mod.groups(sub_res.head),
                "signed_at": receipt_mod.utc(a.seen_ms),
                "manifest_sha256": sub_res.manifest_sha256, "file_count": sub_res.file_count,
                "skipped_files": sub_res.skipped,
                "token": token, "qr_svg": receipt_mod.qr_svg(token),
                "standing": receipt_mod.standing(case.body, a),
            }
            self.last_receipt = receipt
            return receipt

    def check_receipt(self, token: str) -> dict[str, Any]:
        with self.lock:
            return receipt_mod.validate(token, self.roster, evidence=[self.evidence_dir]).to_dict()

    def get_assessor_case(self) -> dict[str, Any]:
        with self.lock:
            # Re-ingest current evidence
            self.store.ingest_path(self.evidence_dir)
            case = self.store.case(ClockPolicy())
            text_report = render(case)
            return {
                "hash": case.hash,
                "body": case.body,
                "rendered_text": text_report,
            }

    def get_witness_report(self) -> dict[str, Any]:
        with self.lock:
            return self.witness.report()

    def run_tamperlab_trial(self, scenario_id: str, seed: int = 0) -> dict[str, Any]:
        from lab.harness import judge, run_trials
        from lab.scenarios import SCENARIOS
        from lab.world import World

        sc = next((s for s in SCENARIOS if s.id == scenario_id), None)
        if not sc:
            raise ValueError(f"Unknown scenario {scenario_id}")

        with tempfile.TemporaryDirectory() as tmp:
            world = World.build(tmp)
            trials = run_trials(sc, world, Path(tmp), n=1)
            if not trials:
                return {
                    "scenario_id": sc.id,
                    "title": sc.title,
                    "threat": sc.threat,
                    "group": sc.group,
                    "outcome": "INAPPLICABLE",
                    "expected": sc.expect.outcome.value,
                    "verdict": "N/A",
                    "suspect": [],
                    "notes": [],
                    "detail": "Scenario inapplicable in environment",
                }
            t = trials[0]
            sus = sorted(list(t.obs.suspect)) if t.obs else []
            notes = sorted(list(t.obs.notes)) if t.obs else []
            return {
                "scenario_id": sc.id,
                "title": sc.title,
                "threat": sc.threat,
                "group": sc.group,
                "outcome": t.outcome.value,
                "expected": sc.expect.outcome.value,
                "verdict": t.obs.verdict if t.obs else "NO_EVIDENCE",
                "assurance": t.obs.assurance if t.obs else "A0",
                "suspect": sus,
                "notes": notes,
                "error": t.error,
            }

    def list_scenarios(self) -> list[dict[str, Any]]:
        from lab.scenarios import SCENARIOS
        return [
            {
                "id": s.id,
                "threat": s.threat,
                "group": s.group,
                "title": s.title,
                "expected": s.expect.outcome.value,
            }
            for s in SCENARIOS
        ]

    def close(self) -> None:
        if self.courier:
            try:
                self.courier.stop()
            except Exception:
                pass
        if self.agent:
            try:
                self.agent.close()
            except Exception:
                pass
        self.witness_server.shutdown()
        self.witness.close()
        self.store.close()


class WebHandler(BaseHTTPRequestHandler):
    timeout = 15              # drop stalled connections
    server_version = "Immutable"
    sys_version = ""
    _STATIC_OK = {".html", ".js", ".css", ".woff2", ".svg", ".png", ".ico", ".json", ".txt"}
    _MIME = {".woff2": "font/woff2", ".js": "text/javascript; charset=utf-8",
             ".css": "text/css; charset=utf-8", ".html": "text/html; charset=utf-8"}

    def log_message(self, format: str, *args: Any) -> None:
        # Keep console output clean
        pass

    def _security_headers(self) -> None:
        for k, v in self.server.sec_headers.items():
            self.send_header(k, v)

    def _json(self, status: int, data: Any, retry_after: int = 0) -> None:
        body = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if retry_after:
            self.send_header("Retry-After", str(retry_after))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _guard(self) -> bool:
        verdict = websec.check(self.server.sec, self.command, urlparse(self.path).path, self.headers)
        if verdict is None:
            return True
        status, msg, retry = verdict
        self._json(status, {"error": msg}, retry)
        return False

    def do_OPTIONS(self) -> None:          # no CORS: the page is same-origin
        self._json(405, {"error": "method not allowed"})

    def _read_json(self) -> dict[str, Any]:
        n = self.headers.get("Content-Length", "0")
        if not n.isdigit():
            return {}
        n = int(n)
        if n > websec.MAX_BODY:
            raise websec.TooLarge("request body too large")
        if n == 0:
            return {}
        raw = self.rfile.read(n)
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return {}
        return obj if isinstance(obj, dict) else {}

    def do_GET(self) -> None:
        if not self._guard():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        service: ImmutableService = self.server.service

        if path == "/api/status":
            ses = service.get_student_session()
            self._json(200, {
                "status": "online",
                "exam_id": service.exam_id,
                "session_id": service.session_id,
                "ws_id": service.ws_id,
                "head": ses["head"],
                "last_seq": ses["last_seq"],
                "events_count": len(ses["events"]),
            })
            return

        if path == "/api/student/session":
            self._json(200, service.get_student_session())
            return

        if path == "/api/student/receipt":
            receipt = service.last_receipt or service.get_student_session().get("receipt")
            self._json(200, receipt or {})
            return

        if path == "/api/assessor/case":
            self._json(200, service.get_assessor_case())
            return

        if path == "/api/witness/report":
            self._json(200, service.get_witness_report())
            return

        if path == "/api/tamperlab/scenarios":
            self._json(200, service.list_scenarios())
            return

        # Serve static web frontend
        self._serve_static(path)

    def do_POST(self) -> None:
        if not self._guard():
            return
        parsed = urlparse(self.path)
        path = parsed.path
        service: ImmutableService = self.server.service
        try:
            payload = self._read_json()
        except websec.TooLarge:
            self.close_connection = True
            self._json(413, {"error": "request body too large"})
            return

        try:
            if path == "/api/student/init":
                service._init_agent()
                self._json(200, service.get_student_session())
                return

            if path == "/api/student/file":
                rel = payload.get("path")
                content = payload.get("content", "")
                if not rel:
                    self._json(400, {"error": "path required"})
                    return
                res = service.save_file(rel, content)
                self._json(200, res)
                return

            if path == "/api/student/run":
                rel = payload.get("path")
                if not rel:
                    self._json(400, {"error": "path required"})
                    return
                res = service.run_code(rel)
                self._json(200, res)
                return

            if path == "/api/student/checkpoint":
                res = service.checkpoint()
                self._json(200, res)
                return

            if path == "/api/student/flush":
                res = service.flush()
                self._json(200, res)
                return

            if path == "/api/student/submit":
                receipt = service.submit()
                self._json(200, receipt)
                return

            if path == "/api/receipt/check":
                self._json(200, service.check_receipt(str(payload.get("token", ""))))
                return

            if path == "/api/tamperlab/run":
                scenario_id = payload.get("scenario_id", "C0")
                seed = int(payload.get("seed", 0))
                res = service.run_tamperlab_trial(scenario_id, seed)
                self._json(200, res)
                return

            self._json(404, {"error": "unknown_endpoint", "path": path})

        except (ValueError, AgentError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            traceback.print_exc(file=sys.stderr)
            self._json(500, {"error": "internal error"})

    def _serve_static(self, path: str) -> None:
        if path in ("/", ""):
            path = "/index.html"
        web_dir = (Path(__file__).resolve().parent.parent.parent / "web").resolve()
        target = (web_dir / path.lstrip("/")).resolve()
        ok = (target.is_relative_to(web_dir) and target.is_file()
              and target.suffix in self._STATIC_OK
              and not any(p.startswith(".") for p in target.relative_to(web_dir).parts))
        if not ok:
            target = web_dir / "index.html"          # keep the SPA fallback
            if not target.is_file():
                self.send_error(404)
                return
        raw = target.read_bytes()
        ctype = self._MIME.get(target.suffix) or mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-cache")
        self._security_headers()
        if target.name == "index.html":
            self.send_header("Set-Cookie", websec.session_cookie(self.server.sec.token))
        self.end_headers()
        self.wfile.write(raw)


class ImmutableWebServer:
    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_PORT,
                 root_dir: Path | None = None, mode: str = "demo"):
        self.service = ImmutableService(root_dir=root_dir)
        self.httpd = ThreadingHTTPServer((host, port), WebHandler)
        self.httpd.daemon_threads = True
        self.httpd.service = self.service
        self.httpd.sec = websec.Sec.create(host, self.httpd.server_address[1], mode)
        self.httpd.sec_headers = websec.security_headers(
            report_only=bool(os.environ.get("IMMUTABLE_CSP_REPORT_ONLY")))
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def start(self) -> None:
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def shutdown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.service.close()
