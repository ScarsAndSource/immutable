#!/usr/bin/env python3
"""scripts/preflight.py: run before every rehearsal and before the real demo.

Not a test suite. It checks that this machine and this checkout are ready:
environment, offline assets, the policy page against the code, the front end's
HTML-injection hygiene, disk fsync latency, clock sanity, and a free port.

  python scripts/preflight.py [--port 8000] [--evidence-dir DIR] [--strict] [--smoke]

--strict  turns WARN into FAIL      --smoke  also runs one submit-and-validate round trip
Exit 1 if anything failed.
"""
import argparse
import importlib.util
import re
import socket
import statistics
import sys
import tempfile
import time
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

rows: list[tuple[str, str, str]] = []


def row(level: str, name: str, detail: str = "") -> None:
    rows.append((level, name, detail))


def check_env() -> None:
    row("PASS" if sys.version_info >= (3, 11) else "FAIL", "python >= 3.11", sys.version.split()[0])
    for mod, level in (("cryptography", "FAIL"), ("immutable", "FAIL"), ("segno", "WARN")):
        ok = importlib.util.find_spec(mod) is not None
        row("PASS" if ok else level, f"import {mod}",
            "" if ok else ("receipt QR will be missing (text token still works)" if mod == "segno" else "not installed"))


def check_assets() -> None:
    web = ROOT / "web"
    for rel in ("vendor/tailwind.js", "vendor/fonts.css", "safe.js"):
        row("PASS" if (web / rel).is_file() else "FAIL", f"web/{rel}", "" if (web / rel).is_file() else "run scripts/vendor_web.py")
    ext = re.compile(r"""(?:src|href)\s*=\s*["'](https?://[^"']+)["']|url\(\s*["']?(https?://[^)"']+)""", re.I)
    found = []
    for name in ("index.html", "style.css", "app.js", "safe.js"):
        p = web / name
        if p.exists():
            found += [f"{name}: {m.group(1) or m.group(2)}" for m in ext.finditer(p.read_text(encoding="utf-8"))]
    row("PASS" if not found else "FAIL", "no external URLs in the UI", "; ".join(found[:3]))


def check_policy_doc() -> None:
    path = ROOT / "scripts" / "gen_policy_doc.py"
    doc = ROOT / "docs" / "POLICY.md"
    if not path.exists() or not doc.exists():
        row("FAIL", "docs/POLICY.md matches policy.py", "missing generator or page")
        return
    spec = importlib.util.spec_from_file_location("gen_policy_doc", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        same = mod.render() == doc.read_text(encoding="utf-8")
    except SystemExit as e:
        row("FAIL", "docs/POLICY.md matches policy.py", str(e))
        return
    row("PASS" if same else "FAIL", "docs/POLICY.md matches policy.py", "" if same else "run scripts/gen_policy_doc.py")


def check_innerhtml() -> None:
    p = ROOT / "web" / "app.js"
    if not p.exists():
        return
    bad = []
    for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        m = re.search(r"innerHTML\s*=\s*(.*)", line)
        if not m:
            continue
        rhs = m.group(1).strip()
        static = re.match(r"""^(["'`])[^$]*\1;?$""", rhs) or rhs.startswith(("html`", "html ("))
        if not static:
            bad.append(str(n))
    row("PASS" if not bad else "WARN", "innerHTML only via html`` or static text",
        "lines " + ", ".join(bad) if bad else "")


def check_fsync(directory: str | None) -> None:
    with tempfile.TemporaryDirectory(dir=directory) as d:
        times = []
        fd = os.open(Path(d) / "probe", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            for _ in range(40):
                t = time.perf_counter()
                os.write(fd, b"x" * 4096)
                os.fsync(fd)
                times.append((time.perf_counter() - t) * 1000)
        finally:
            os.close(fd)
    times.sort()
    p95 = times[int(len(times) * 0.95) - 1]
    row("PASS" if p95 < 20 else "WARN", "fsync latency (p95)", f"{p95:.1f} ms, median {statistics.median(times):.1f} ms (target under 20)")


def check_clock() -> None:
    newest = max((p.stat().st_mtime for p in (ROOT / "src").rglob("*.py")), default=0)
    ok = time.time() >= newest - 60
    row("PASS" if ok else "WARN", "wall clock is not behind the code",
        time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + ("" if ok else " (dead RTC battery?)"))


def check_port(port: int) -> None:
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        row("PASS", f"port {port} is free")
    except OSError:
        row("FAIL", f"port {port} is free", "something is already listening")
    finally:
        s.close()


def smoke() -> None:
    try:
        from immutable import receipt
        from immutable.server import ImmutableService
    except ImportError as e:
        row("FAIL", "smoke: imports", str(e))
        return
    with tempfile.TemporaryDirectory() as tmp:
        svc = ImmutableService(root_dir=Path(tmp))
        try:
            svc.save_file("smoke.py", "print(1)")
            svc.flush()
            rc = svc.submit()
            res = receipt.validate(rc["token"], svc.roster, evidence=[svc.evidence_dir])
            bad = [c.code for c in res.checks if c.required and not c.ok]
            row("PASS" if res.valid else "FAIL", "smoke: submit, receipt, validate against evidence",
                f"standing {rc['standing']['code']}" if res.valid else f"failed {bad}")
        except Exception as e:                              # report, never crash the preflight
            row("FAIL", "smoke: round trip", f"{type(e).__name__}: {e}")
        finally:
            svc.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--evidence-dir")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()

    check_env()
    check_assets()
    check_policy_doc()
    check_innerhtml()
    check_fsync(a.evidence_dir)
    check_clock()
    check_port(a.port)
    if a.smoke:
        smoke()

    width = max(len(n) for _, n, _ in rows)
    failed = 0
    for level, name, detail in rows:
        if a.strict and level == "WARN":
            level = "FAIL"
        failed += level == "FAIL"
        print(f"[{level}] {name.ljust(width)}  {detail}")
    print("\nREADY" if not failed else f"\nNOT READY: {failed} failing")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
