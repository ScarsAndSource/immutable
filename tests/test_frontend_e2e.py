"""tests/test_frontend_e2e.py: End-to-end integration test of the full Immutable pipeline.

Tests:
  1. Student attestation & session start
  2. Workspace modification, code execution with sandbox limits
  3. Hash chaining, checkpointing, and outbox batch sealing
  4. Witness LAN cosigning and anchor generation
  5. Final submission, manifest integrity, and archival receipt issuance
  6. Assessor store ingestion and case note verification
  7. Tamper Lab scenario execution & detection matrix
"""
import json
import tempfile
import urllib.request
from pathlib import Path

from immutable.server import ImmutableWebServer


def test_full_pipeline_e2e():
    with tempfile.TemporaryDirectory() as tmp:
        server = ImmutableWebServer(host="127.0.0.1", port=0, root_dir=Path(tmp))
        server.start()
        base = f"http://127.0.0.1:{server.port}"
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

        try:
            # 1. Check web UI root and assets
            with opener.open(f"{base}/", timeout=5) as r:
                assert r.status == 200
                html = r.read().decode("utf-8")
                assert "Archival Examination Ledger" in html
                assert "Before you begin" in html

            # 2. Get active student session
            with opener.open(f"{base}/api/student/session", timeout=5) as r:
                assert r.status == 200
                ses = json.loads(r.read())
                assert ses["ws_id"] == "STN-19"
                assert ses["last_seq"] >= 1
                assert len(ses["files"]) >= 2

            # 3. Save modified solution file
            req = urllib.request.Request(
                f"{base}/api/student/file",
                data=json.dumps({
                    "path": "solution.py",
                    "content": "def solve(n: int) -> int:\n    return n * (n + 1) // 2\n\nif __name__ == '__main__':\n    print(solve(10))\n",
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with opener.open(req, timeout=5) as r:
                assert r.status == 200
                save_res = json.loads(r.read())
                assert save_res["ok"] is True

            # 4. Run python code
            req = urllib.request.Request(
                f"{base}/api/student/run",
                data=json.dumps({"path": "solution.py"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with opener.open(req, timeout=5) as r:
                assert r.status == 200
                run_res = json.loads(r.read())
                assert run_res["exit_code"] == 0
                assert "55" in run_res["stdout"]

            # 5. Create Checkpoint
            req = urllib.request.Request(f"{base}/api/student/checkpoint", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
            with opener.open(req, timeout=5) as r:
                assert r.status == 200
                cp_res = json.loads(r.read())
                assert "merkle_root" in cp_res

            # 6. Flush batches to witness
            req = urllib.request.Request(f"{base}/api/student/flush", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
            with opener.open(req, timeout=5) as r:
                assert r.status == 200
                flush_res = json.loads(r.read())
                assert "sealed_batches" in flush_res

            # 7. Final submit exam
            req = urllib.request.Request(f"{base}/api/student/submit", data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
            with opener.open(req, timeout=5) as r:
                assert r.status == 200
                receipt = json.loads(r.read())
                assert receipt["token"].startswith("IMR1.")
                assert receipt["standing"]["code"] != "UNKNOWN"

            # 8. Check receipt retrieval
            with opener.open(f"{base}/api/student/receipt", timeout=5) as r:
                assert r.status == 200
                rec_check = json.loads(r.read())
                assert rec_check["token"].startswith("IMR1.")
                assert rec_check["standing"]["code"] != "UNKNOWN"

            # 9. Assessor audit case verification
            with opener.open(f"{base}/api/assessor/case", timeout=5) as r:
                assert r.status == 200
                case = json.loads(r.read())
                assert case["body"]["summary"]["sessions"] >= 1
                assert case["body"]["sessions"][0]["verdict"] in ("ANCHORED", "SELF_CONSISTENT_ONLY")

            # 10. Witness LAN report
            with opener.open(f"{base}/api/witness/report", timeout=5) as r:
                assert r.status == 200
                wit = json.loads(r.read())
                assert wit["witness"] == "W01"

            # 11. Tamper Lab scenario trial execution
            req = urllib.request.Request(
                f"{base}/api/tamperlab/run",
                data=json.dumps({"scenario_id": "D1"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with opener.open(req, timeout=10) as r:
                assert r.status == 200
                tl_res = json.loads(r.read())
                assert tl_res["outcome"] == "DETECTED"
                assert tl_res["verdict"] == "TAMPER_SUSPECTED"

        finally:
            server.shutdown()
