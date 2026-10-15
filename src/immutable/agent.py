"""agent.py: the keeper of the log on one workstation.

It owns the WAL, the signing key and the outbox, and it is the only thing that
turns what happened on the machine into events. It watches the workspace, notices
saves by content hash, bookends program runs, takes the submission, and seals
durable events into signed batch files.

OUTBOX = transport-agnostic. Sealed batches are plain files:
    <evidence>/outbox/00000000-00000041.batch.json   (first_seq-last_seq)
Ingest (B6) and the witness (B9) both just read this directory, over a LAN, a
USB stick, whatever the lab has. Nothing here needs a network.

Thread-safe: one RLock around every operation that touches the log, so a ticker
thread and a UI thread can share an Agent. The lock is NOT held while student
code runs, so saves made during a run land between RUN_START and RUN_END in
true order.

The Agent is not a sandbox against the student. Same OS user means the student
can kill it or read its key (threat T4). Run it as a separate OS user if you can;
the witness is what bounds the damage if you cannot.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import canon, hashing, merkle, transfer
from .batch import Batch, seal
from .events import Event
from .fsys import FS, RealFS
from .keys import Signer
from .wal import Wal
from .workspace import Listing, Workspace

AGENT_VER = "im-agent/0.1"
MAX_BATCH_EVENTS = 256
_BATCH_FILE = re.compile(r"^(\d{8})-(\d{8})\.batch\.json$")


class AgentError(Exception):
    pass


@dataclass
class RunTicket:
    dir: str          # sandbox copy of the workspace
    rel: str
    sha256: str       # hash of the file inside the sandbox: what actually ran


@dataclass
class SubmitResult:
    manifest_sha256: str
    file_count: int
    last_seq: int
    head: str
    skipped: list[str]


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    try:
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass                                     # Windows: no directory fsync


class Agent:
    def __init__(self, *, evidence_dir: Path, workspace: Workspace, wal: Wal,
                 signer: Signer, heartbeat_s: float, checkpoint_every: int):
        self.evidence = evidence_dir
        self.outbox = evidence_dir / "outbox"
        self.ws = workspace
        self._wal = wal
        self._signer = signer
        self.heartbeat_s = heartbeat_s
        self.checkpoint_every = checkpoint_every
        self._lock = threading.RLock()
        self._known: dict[str, str] = {}
        self._last_cp = -1
        self._ended = False
        self._last_hb = time.monotonic()
        self.last_skipped: list[str] = []
        self.listeners: list[Callable[[Event], None]] = []
        self._sealed_upto = self._scan_outbox()

    # ------------------------------------------------------------- lifecycle
    @classmethod
    def open(cls, *, evidence_dir: str | Path, workspace: str | Path,
             exam_id: str, session_id: str, ws_id: str, signer: Signer,
             paper_sha256: str, roster_sha256: str = hashing.ZERO,
             fs: FS | None = None, heartbeat_s: float = 30.0,
             checkpoint_every: int = 64,
             transfer_token: bytes | None = None,
             assessor_pub: str | None = None) -> "Agent":
        tbody = tsig = None
        if transfer_token is not None:
            if assessor_pub is None:
                raise AgentError("a transfer token needs assessor_pub so it can be checked")
            try:
                tbody, tsig = transfer.verify_token(transfer_token, assessor_pub)
            except transfer.TransferError as e:
                raise AgentError(f"transfer token rejected: {e}") from None
            if (tbody["exam_id"], tbody["session_id"], tbody["to_ws_id"], tbody["to_pub"]) \
                    != (exam_id, session_id, ws_id, signer.pub_hex):
                raise AgentError("transfer token is for a different exam, session, seat or key")

        ev_dir = Path(evidence_dir)
        (ev_dir / "outbox").mkdir(parents=True, exist_ok=True, mode=0o700)
        fs = fs or RealFS()
        wal_path = str(ev_dir / "session.wal")
        ws = workspace if hasattr(workspace, "scan") else Workspace(workspace)

        if fs.exists(wal_path):
            rec = Wal.recover(fs, wal_path, exam_id, session_id, ws_id)   # emits RECOVERY
            a = cls(evidence_dir=ev_dir, workspace=ws, wal=rec.wal, signer=signer,
                    heartbeat_s=heartbeat_s, checkpoint_every=checkpoint_every)
            if any(e.type == "SESSION_END" for e in rec.wal.events):
                raise AgentError("this session already ended; it cannot be reopened")
            for e in rec.wal.events:
                if e.type == "FILE_SAVE":
                    a._known[e.data["path"]] = e.data["sha256"]
                elif e.type == "CHECKPOINT":
                    a._last_cp = e.seq
            a._emit("BOOT", {"reason": "resume"})
        else:
            wal = Wal.create(fs, wal_path, exam_id, session_id, ws_id)
            a = cls(evidence_dir=ev_dir, workspace=ws, wal=wal, signer=signer,
                    heartbeat_s=heartbeat_s, checkpoint_every=checkpoint_every)
            a._emit("SESSION_START", {"paper_sha256": paper_sha256,
                                      "roster_sha256": roster_sha256,
                                      "agent_ver": AGENT_VER})
            a._emit("BOOT", {"reason": "start"})
            if tbody is not None:           # always seq 2: SESSION_START, BOOT, TRANSFER
                a._emit("TRANSFER", {"from_ws_id": tbody["from_ws_id"],
                                     "from_last_seq": tbody["from_last_seq"],
                                     "from_head": tbody["from_head"],
                                     "assessor_sig": tsig})
        a._observe(a.ws.scan())          # baseline: starter files, or changes made while down
        a.flush()
        return a


    def close(self) -> None:
        """Clean stop without submitting. Reopening later is legal and logged as a resume."""
        with self._lock:
            if not self._ended:
                self.flush()
            self._wal.close()

    # ---------------------------------------------------------------- events
    def _emit(self, etype: str, data: dict | None = None) -> Event:
        with self._lock:
            ev = self._wal.append(etype, data)
            if etype == "CHECKPOINT":
                self._last_cp = ev.seq
        for fn in self.listeners:
            try:
                fn(ev)
            except Exception:
                pass
        return ev

    def _check_open(self) -> None:
        if self._ended:
            raise AgentError("session has ended")

    def _observe(self, listing: Listing) -> None:
        """A FILE_SAVE for every path whose content differs from what we last recorded."""
        self.last_skipped = listing.skipped
        for rel in sorted(listing.files):
            info = listing.files[rel]
            if self._known.get(rel) != info.sha256:
                self._emit("FILE_SAVE", {"path": rel, "sha256": info.sha256,
                                         "size": info.size})
                self._known[rel] = info.sha256

    def tick(self) -> None:
        """Call about once a second. Notices saves, heartbeats, checkpoints, flushes."""
        with self._lock:
            self._check_open()
            self._observe(self.ws.scan())
            now = time.monotonic()
            if now - self._last_hb >= self.heartbeat_s:
                self._emit("HEARTBEAT")
                self._last_hb = now
                self.flush()
            if self._wal.events[-1].seq - self._last_cp >= self.checkpoint_every:
                self.checkpoint()

    def checkpoint(self) -> Event:
        """Commit to everything so far. A witness holding this can prove the prefix."""
        with self._lock:
            self._check_open()
            hashes = [e.hash() for e in self._wal.events]
            return self._emit("CHECKPOINT", {"merkle_root": merkle.root(hashes),
                                             "upto_seq": self._wal.events[-1].seq})

    # ----------------------------------------------------------------- runs
    def begin_run(self, rel: str) -> RunTicket:
        """Snapshot the workspace, record what is in it, then record RUN_START.

        The hash in RUN_START is of the sandbox copy: exactly the bytes that will execute.
        """
        with self._lock:
            self._check_open()
            tmp = tempfile.mkdtemp(prefix="im-run-")
            try:
                listing = self.ws.snapshot(tmp)
                self._observe(listing)
                info = listing.files.get(rel)
                if info is None:
                    raise AgentError(f"{rel!r} is not a recordable file in the workspace")
                self._emit("RUN_START", {"path": rel, "sha256": info.sha256})
                return RunTicket(tmp, rel, info.sha256)
            except BaseException:
                shutil.rmtree(tmp, ignore_errors=True)
                raise

    def end_run(self, ticket: RunTicket, exit_code: int, stdout_sha256: str,
                duration_ms: int) -> None:
        try:
            with self._lock:
                self._emit("RUN_END", {"exit_code": exit_code,
                                       "stdout_sha256": stdout_sha256,
                                       "duration_ms": duration_ms})
        finally:
            shutil.rmtree(ticket.dir, ignore_errors=True)

    # --------------------------------------------------------------- submit
    def submit(self) -> SubmitResult:
        """Freeze the submission: blobs by hash name, a canonical manifest, then the closing events."""
        with self._lock:
            self._check_open()
            sub = self.evidence / "submission"
            blobs = sub / "blobs"
            blobs.mkdir(parents=True, exist_ok=True, mode=0o700)

            def sink(_rel: str, data: bytes) -> None:
                p = blobs / hashing.sha256_hex(data)
                if not p.exists():
                    _atomic_write(p, data)

            listing = self.ws.collect(sink)
            self._observe(listing)               # a last-second save precedes SUBMIT
            manifest = canon.dumps({
                "v": 1,
                "exam_id": self._wal._w.exam_id,
                "session_id": self._wal._w.session_id,
                "ws_id": self._wal._w.ws_id,
                "files": [{"path": r, "sha256": listing.files[r].sha256,
                           "size": listing.files[r].size} for r in sorted(listing.files)],
            })
            msha = hashing.sha256_hex(manifest)
            _atomic_write(sub / "manifest.json", manifest)

            self.checkpoint()
            self._emit("SUBMIT", {"manifest_sha256": msha, "file_count": len(listing.files)})
            last = self._emit("SESSION_END", {"reason": "submitted"})
            self.flush()
            self._ended = True
            self._wal.close()
            return SubmitResult(msha, len(listing.files), last.seq, last.hash(),
                                listing.skipped)

    # --------------------------------------------------------------- outbox
    def _scan_outbox(self) -> int:
        top = -1
        for p in self.outbox.iterdir():
            m = _BATCH_FILE.match(p.name)
            if m:
                top = max(top, int(m.group(2)))
        return top

    def flush(self) -> list[Batch]:
        """Seal every durable, not-yet-sealed event into signed batch files."""
        with self._lock:
            events = self._wal.durable_events(self._sealed_upto + 1)
            out = []
            for i in range(0, len(events), MAX_BATCH_EVENTS):
                b = seal(self._signer, events[i:i + MAX_BATCH_EVENTS])
                name = f"{b.header['first_seq']:08d}-{b.header['last_seq']:08d}.batch.json"
                _atomic_write(self.outbox / name, b.to_bytes())
                self._sealed_upto = b.header["last_seq"]
                out.append(b)
            return out

    def status(self) -> dict:
        with self._lock:
            evs = self._wal.events
            return {"last_seq": evs[-1].seq if evs else -1,
                    "durable_seq": self._wal.durable_seq,
                    "sealed_upto": self._sealed_upto,
                    "head": self._wal.head, "ended": self._ended,
                    "skipped": list(self.last_skipped)}
