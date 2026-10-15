"""runner.py: run the student's Python, with a leash.

This is a leash, not a cage. It exists so a runaway loop, a memory bomb or a
flood of output cannot hang the agent or fill the disk. It does not stop the
student's code from touching the student's own machine; that is not our job and
we do not pretend otherwise.

  * runs in a throwaway snapshot of the workspace (the exact bytes we hashed)
  * hard wall-clock timeout, whole process group killed
  * POSIX: CPU, address-space, file-size and open-file limits set INSIDE the child
    by a tiny bootstrap, so no preexec_fn (which is unsafe next to threads)
  * stdout/stderr go to files, capped; only the stdout HASH goes in the evidence,
    never the text
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import hashing
from .agent import Agent

MAX_OUT = 1 << 20
_POSIX = os.name == "posix"

_BOOT = r'''
import os, sys, runpy
rel, cpu, mem, fsz = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
try:
    import resource
    for which, val in ((resource.RLIMIT_CPU, cpu), (resource.RLIMIT_AS, mem),
                       (resource.RLIMIT_FSIZE, fsz), (resource.RLIMIT_NOFILE, 128)):
        try:
            resource.setrlimit(which, (val, val))
        except (ValueError, OSError):
            pass
except ImportError:
    pass
sys.path.insert(0, os.getcwd())
sys.argv = [rel]
runpy.run_path(rel, run_name="__main__")
'''


@dataclass
class RunResult:
    exit_code: int          # negative = killed by that signal; -9 also means timed out
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool


def _env() -> dict[str, str]:
    keep = {"PATH": os.environ.get("PATH", ""), "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
    if "SYSTEMROOT" in os.environ:                    # Windows needs it to start at all
        keep["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return keep


def run_python(agent: Agent, rel_path: str, *, timeout_s: float = 10.0,
               cpu_s: int = 10, mem_mb: int = 1024) -> RunResult:
    if not rel_path.endswith(".py"):
        raise ValueError("the demo runner runs .py files only")
    ticket = agent.begin_run(rel_path)               # RUN_START is on the log from here
    out_dir = tempfile.mkdtemp(prefix="im-out-")
    exit_code, stdout, stderr, timed_out = -1, b"", b"", False
    t0 = time.monotonic()
    try:
        with open(Path(out_dir, "o"), "wb") as fo, open(Path(out_dir, "e"), "wb") as fe:
            kw = {"start_new_session": True} if _POSIX else \
                 {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
            proc = subprocess.Popen(
                [sys.executable, "-E", "-B", "-c", _BOOT, rel_path,
                 str(cpu_s), str(mem_mb << 20), str(MAX_OUT)],
                cwd=ticket.dir, stdin=subprocess.DEVNULL, stdout=fo, stderr=fe,
                env=_env(), **kw)
            try:
                exit_code = proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    if _POSIX:
                        os.killpg(proc.pid, signal.SIGKILL)
                    else:
                        proc.kill()
                except ProcessLookupError:
                    pass
                proc.wait()
                exit_code = -9
        stdout = Path(out_dir, "o").read_bytes()[:MAX_OUT]
        stderr = Path(out_dir, "e").read_bytes()[:MAX_OUT]
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
        dur = int((time.monotonic() - t0) * 1000)
        agent.end_run(ticket, max(-2**31, min(2**31 - 1, exit_code)),
                      hashing.sha256_hex(stdout), dur)   # RUN_END always follows RUN_START
    return RunResult(exit_code, stdout, stderr, dur, timed_out)
