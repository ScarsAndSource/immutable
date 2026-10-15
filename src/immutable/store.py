"""store.py (B6): the assessor's database. Files in, idempotent, nothing trusted.

SQLite (WAL, synchronous FULL) for batches, anchors, manifests and rejects; blobs live
as files named by their own hash. Every ingest is INSERT OR IGNORE keyed by content id,
so re-importing a USB stick or a retried upload changes nothing.

LIVE ingest (a batch arriving over the lab LAN) also writes an `assessor` anchor, but
only for a clean batch signed by the key enrolled for its seat in the roster, so a
stranger's injected batch cannot create a false anchor and then "conflict" with the
real log. Seats created by transfer get no live anchor here; their witness anchors
(B9) cover them.

Malformed input is remembered only as (id, reason, size), never stored, so a flood of
junk cannot fill the disk. A total-bytes cap guards the rest.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from . import anchor as anchor_mod
from . import hashing, submission
from .batch import MAX_BATCH_BYTES, verify_batch
from .clockcheck import ClockPolicy
from .findings import Code
from .reconcile import Case, reconcile
from .roster import Roster
from .workspace import MAX_FILE

MAX_FILE_ANY = 8 << 20

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches(id TEXT PRIMARY KEY, session_id TEXT, ws_id TEXT,
  first_seq INTEGER, last_seq INTEGER, raw BLOB NOT NULL, live INTEGER, received_ms INTEGER);
CREATE TABLE IF NOT EXISTS anchors(id TEXT PRIMARY KEY, raw BLOB NOT NULL, received_ms INTEGER);
CREATE TABLE IF NOT EXISTS manifests(id TEXT PRIMARY KEY, raw BLOB NOT NULL, received_ms INTEGER);
CREATE TABLE IF NOT EXISTS rejects(id TEXT PRIMARY KEY, code TEXT, detail TEXT,
  size INTEGER, received_ms INTEGER);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


class StoreError(Exception):
    pass


class Ingested:
    def __init__(self, status: str, id: str, detail: str = ""):
        self.status, self.id, self.detail = status, id, detail

    def __repr__(self) -> str:
        return f"Ingested({self.status}, {self.id[:8]}, {self.detail!r})"


class Store:
    def __init__(self, directory: str | Path, roster: Roster, *, max_total_bytes: int = 512 << 20):
        self.dir = Path(directory)
        (self.dir / "blobs").mkdir(parents=True, exist_ok=True)
        self.roster = roster
        self.max_total = max_total_bytes
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.dir / "assessor.db", check_same_thread=False,
                                   isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(SCHEMA)
        row = self._db.execute("SELECT v FROM meta WHERE k='roster_id'").fetchone()
        if row and row[0] != roster.id:
            raise StoreError("this store belongs to a different roster")
        if not row:
            self._db.execute("INSERT INTO meta VALUES('roster_id', ?)", (roster.id,))

    # ---- plumbing
    @contextmanager
    def _tx(self):
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    @staticmethod
    def _now(now_ms: int | None) -> int:
        return now_ms if now_ms is not None else time.time_ns() // 1_000_000

    def _reject(self, rid: str, code: Code, detail: str, size: int, now: int) -> Ingested:
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO rejects VALUES(?,?,?,?,?)",
                             (rid, code.value, detail[:200], size, now))
        return Ingested("rejected", rid, detail)

    def _total(self) -> int:
        return self._db.execute("SELECT COALESCE(SUM(LENGTH(raw)),0) FROM batches").fetchone()[0]

    # ---- ingest
    def ingest_batch(self, raw: bytes, *, live: bool = False, now_ms: int | None = None) -> Ingested:
        now = self._now(now_ms)
        if len(raw) > MAX_BATCH_BYTES:
            return self._reject(hashing.sha256_hex(raw), Code.MALFORMED, "batch file too large", len(raw), now)
        b, fs = verify_batch(raw)
        if b is None:
            return self._reject(hashing.sha256_hex(raw), Code.MALFORMED, fs[0].detail, len(raw), now)
        h = b.header
        if h["exam_id"] != self.roster.exam_id:
            return self._reject(hashing.sha256_hex(b.to_bytes()), Code.WRONG_EXAM,
                                "batch is for a different exam", len(raw), now)
        canonical = b.to_bytes()
        bid = hashing.sha256_hex(canonical)
        with self._lock, self._tx():
            if self._total() + len(canonical) > self.max_total:
                raise StoreError("evidence store is full")
            cur = self._db.execute(
                "INSERT OR IGNORE INTO batches VALUES(?,?,?,?,?,?,?,?)",
                (bid, h["session_id"], h["ws_id"], h["first_seq"], h["last_seq"],
                 canonical, 1 if live else 0, now))
            dup = cur.rowcount == 0
            if live and not fs and not dup:
                seat = self.roster.seat(h["ws_id"])
                if seat is not None and seat.pub == h["signer"]:
                    a = anchor_mod.parse(anchor_mod.make_assessor(
                        exam_id=h["exam_id"], session_id=h["session_id"], ws_id=h["ws_id"],
                        upto_seq=h["last_seq"], head=h["head"], seen_ms=now))
                    self._db.execute("INSERT OR IGNORE INTO anchors VALUES(?,?,?)",
                                     (a.id, a.to_bytes(), now))
        note = "" if not fs else "stored, with findings: " + ", ".join(sorted({f.code.value for f in fs}))
        return Ingested("duplicate" if dup else "stored", bid, note)

    def ingest_anchor(self, raw: bytes, *, now_ms: int | None = None) -> Ingested:
        now = self._now(now_ms)
        try:
            a = anchor_mod.parse(raw)
        except anchor_mod.AnchorError as e:
            return self._reject(hashing.sha256_hex(raw), Code.ANCHOR_INVALID, str(e), len(raw), now)
        if a.exam_id != self.roster.exam_id:
            return self._reject(a.id, Code.WRONG_EXAM, "anchor is for a different exam", len(raw), now)
        with self._lock:
            cur = self._db.execute("INSERT OR IGNORE INTO anchors VALUES(?,?,?)", (a.id, a.to_bytes(), now))
        return Ingested("duplicate" if cur.rowcount == 0 else "stored", a.id)

    def ingest_manifest(self, raw: bytes, *, now_ms: int | None = None) -> Ingested:
        now = self._now(now_ms)
        mid = hashing.sha256_hex(raw)
        try:
            m = submission.parse_manifest(raw)
        except submission.SubmissionError as e:
            return self._reject(mid, Code.MALFORMED, f"manifest: {e}", len(raw), now)
        if m["exam_id"] != self.roster.exam_id:
            return self._reject(mid, Code.WRONG_EXAM, "manifest is for a different exam", len(raw), now)
        with self._lock:
            cur = self._db.execute("INSERT OR IGNORE INTO manifests VALUES(?,?,?)", (mid, raw, now))
        return Ingested("duplicate" if cur.rowcount == 0 else "stored", mid)

    def _blob_path(self, sha: str) -> Path:
        return self.dir / "blobs" / sha[:2] / sha

    def has_blob(self, sha: str) -> bool:
        return hashing.is_hash(sha) and self._blob_path(sha).is_file()

    def ingest_blob(self, data: bytes, *, expect: str | None = None,
                    now_ms: int | None = None) -> Ingested:
        now = self._now(now_ms)
        sha = hashing.sha256_hex(data)
        if expect is not None and sha != expect:
            return self._reject(sha, Code.MALFORMED, "blob contents do not match its name", len(data), now)
        if len(data) > MAX_FILE:
            return self._reject(sha, Code.MALFORMED, "blob larger than the per-file limit", len(data), now)
        p = self._blob_path(sha)
        if p.exists():
            return Ingested("duplicate", sha)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, p)
        return Ingested("stored", sha)

    def _ingest_file(self, p: Path, live: bool):
        n = p.name
        if p.stat().st_size > MAX_FILE_ANY:
            return "skipped", Ingested("rejected", "", f"{n} is too large")
        if n.endswith(".batch.json"):
            return "batch", self.ingest_batch(p.read_bytes(), live=live)
        if n.endswith(".anchor.json"):
            return "anchor", self.ingest_anchor(p.read_bytes())
        if n == "manifest.json":
            return "manifest", self.ingest_manifest(p.read_bytes())
        if p.parent.name == "blobs":
            return "blob", self.ingest_blob(p.read_bytes(), expect=n)
        return None

    def ingest_path(self, path: str | Path, *, live: bool = False) -> dict:
        """A file, or a whole evidence directory (agent layout or a flat folder)."""
        root, counts = Path(path), Counter()
        files = [root] if root.is_file() else \
            [p for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()]
        for p in files:
            r = self._ingest_file(p, live)
            if r:
                counts[f"{r[0]}:{r[1].status}"] += 1
        return dict(sorted(counts.items()))

    def ingest_v2_export(self, path: str | Path) -> dict:
        """Import a server export without changing current verifier semantics."""
        from .v2_export import ingest
        return ingest(self, path)

    # ---- the case
    def case(self, policy: ClockPolicy = ClockPolicy()) -> Case:
        with self._lock:
            q = self._db.execute
            batches = [r[0] for r in q("SELECT raw FROM batches ORDER BY id")]
            anchors = [r[0] for r in q("SELECT raw FROM anchors ORDER BY id")]
            manifests = [r[0] for r in q("SELECT raw FROM manifests ORDER BY id")]
            rejects = [{"id": r[0], "code": r[1], "detail": r[2]}
                       for r in q("SELECT id, code, detail FROM rejects ORDER BY id")]
        return reconcile(batches, self.roster, anchors=anchors, manifests=manifests,
                         has_blob=self.has_blob, policy=policy, prior_rejects=rejects)

    def close(self) -> None:
        self._db.close()
