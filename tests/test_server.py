import json
import tempfile
import urllib.request
from pathlib import Path

from immutable.server import ImmutableService, ImmutableWebServer


def test_service_lifecycle():
    with tempfile.TemporaryDirectory() as tmp:
        service = ImmutableService(root_dir=Path(tmp))
        try:
            ses = service.get_student_session()
            assert ses["exam_id"] == "EXAM-2024-P1"
            assert ses["ws_id"] == "STN-19"
            assert len(ses["events"]) >= 2  # SESSION_START, BOOT
            assert len(ses["files"]) >= 2   # solution.py, test_cases.py

            # Test save file
            save_res = service.save_file("test_script.py", "x = 42\nprint(x)")
            assert save_res["ok"] is True
            assert save_res["path"] == "test_script.py"

            # Test run code
            run_res = service.run_code("test_script.py")
            assert run_res["exit_code"] == 0
            assert "42" in run_res["stdout"]

            # Test checkpoint
            cp_res = service.checkpoint()
            assert cp_res["seq"] > 0
            assert cp_res["merkle_root"] is not None

            # Test flush
            fl_res = service.flush()
            assert "sealed_batches" in fl_res

            # Test tamper lab trial
            tl_res = service.run_tamperlab_trial("C0")
            assert tl_res["outcome"] == "CLEAN"

            tl_d1 = service.run_tamperlab_trial("D1")
            assert tl_d1["outcome"] == "DETECTED"

            # Test submit
            sub_res = service.submit()
            assert sub_res["token"].startswith("IMR1.")
            assert sub_res["standing"]["code"] != "UNKNOWN"

            # Test assessor case
            case = service.get_assessor_case()
            assert "body" in case
            assert "rendered_text" in case

        finally:
            service.close()


def test_http_api_endpoints():
    with tempfile.TemporaryDirectory() as tmp:
        server = ImmutableWebServer(host="127.0.0.1", port=0, root_dir=Path(tmp))
        server.start()
        base_url = f"http://127.0.0.1:{server.port}"
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        try:
            # GET / (static index.html) - establishes session cookie
            with opener.open(f"{base_url}/", timeout=5) as r:
                assert r.status == 200
                html = r.read().decode("utf-8")
                assert "Immutable" in html
                assert "view-briefing" in html

            # GET /api/status
            with opener.open(f"{base_url}/api/status", timeout=5) as r:
                assert r.status == 200
                data = json.loads(r.read())
                assert data["status"] == "online"

            # GET /style.css
            with opener.open(f"{base_url}/style.css", timeout=5) as r:
                assert r.status == 200
                assert "font-style: normal" in r.read().decode("utf-8")

            # GET /app.js
            with opener.open(f"{base_url}/app.js", timeout=5) as r:
                assert r.status == 200

            # GET /api/student/session
            with opener.open(f"{base_url}/api/student/session", timeout=5) as r:
                assert r.status == 200
                data = json.loads(r.read())
                assert data["ws_id"] == "STN-19"
                assert len(data["events"]) >= 2

            # POST /api/student/run
            req = urllib.request.Request(
                f"{base_url}/api/student/run",
                data=json.dumps({"path": "solution.py"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with opener.open(req, timeout=5) as r:
                assert r.status == 200
                res = json.loads(r.read())
                assert res["exit_code"] == 0

            # POST /api/tamperlab/run
            req = urllib.request.Request(
                f"{base_url}/api/tamperlab/run",
                data=json.dumps({"scenario_id": "C0"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with opener.open(req, timeout=10) as r:
                assert r.status == 200
                res = json.loads(r.read())
                assert res["outcome"] == "CLEAN"

            # GET /health
            req_health = urllib.request.Request(f"{base_url}/health", method="GET")
            with opener.open(req_health, timeout=5) as r:
                assert r.status == 200
                health_data = json.loads(r.read())
                assert health_data == {"status": "ok"}

            # HEAD /health
            req_head_health = urllib.request.Request(f"{base_url}/health", method="HEAD")
            with opener.open(req_head_health, timeout=5) as r:
                assert r.status == 200
                assert r.read() == b""
                assert "application/json" in r.headers.get("Content-Type", "")

            # HEAD / (static)
            req_head_root = urllib.request.Request(f"{base_url}/", method="HEAD")
            with opener.open(req_head_root, timeout=5) as r:
                assert r.status == 200
                assert r.read() == b""

        finally:
            server.shutdown()
