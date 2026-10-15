"""witness.py (B9): a second holder of every head, on the lab LAN.

WHAT IT DOES
  Receives sealed batches from workstations, checks them hard, remembers one hash
  per (session, seat, seq), and answers with a signed ANCHOR: "by my clock, at T, I
  saw this seat had this head at this position". One anchor pins the whole prefix
  (the hash chain commits to everything before it).

THE RULES THAT MAKE IT WORTH TRUSTING
  * It never cosigns two different heads for one (session, seat, seq). The held
    table's primary key plus the conflict check below make equivocation impossible.
  * It checks neighbours too: a batch whose first prev disagrees with the hash it
    holds at first_seq-1, or whose head disagrees with the prev of the event it holds
    at last_seq+1, is refused. A history rewritten to be internally consistent still
    cannot slide in next to what the witness already saw.
  * Whole-batch atomicity: a refused batch records nothing.
  * Idempotent: the anchor's time is the FIRST time the witness saw that event, so a
    retried upload returns byte-identical bytes (Ed25519 is deterministic).
  * Authorization mirrors the assessor's binding logic: roster seat key, or a key
    bound by an authentic assessor-signed TRANSFER in the batch. After a transfer the
    old seat is retired: events past from_last_seq get no anchor.
  * Junk (malformed, unenrolled, defective) is answered and forgotten. Only
    authenticated conflicts are written to the refusals table, so a LAN attacker
    cannot fill the disk or plant fake "evidence".

The witness also keeps a COPY of every accepted batch under batches/: a second copy
of the evidence for "the lab assistant deleted my work" disputes.

Pings are seat-signed heartbeats (domain "ping") carrying (boot_id, boot_ns), which
must increase within a boot, so a recorded ping cannot be replayed to fake liveness.
They feed the contact record in report(), never a verdict.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import NamedTuple

from . import anchor, board, canon, hashing, keys, transfer
from .batch import MAX_BATCH_BYTES, verify_batch
from .events import ID_RE
from .roster import Roster

SCHEMA = """
CREATE TABLE IF NOT EXISTS held(session TEXT, ws TEXT, seq INTEGER, hash TEXT, prev TEXT,
  seen_ms INTEGER, PRIMARY KEY(session, ws, seq));
CREATE TABLE IF NOT EXISTS bound(session TEXT, ws TEXT, pub TEXT, PRIMARY KEY(session, ws));
CREATE TABLE IF NOT EXISTS retired(session TEXT, ws TEXT, last_seq INTEGER, PRIMARY KEY(session, ws));
CREATE TABLE IF NOT EXISTS pings(session TEXT, ws TEXT, boot_id TEXT, boot_ns INTEGER,
  PRIMARY KEY(session, ws));
CREATE TABLE IF NOT EXISTS contacts(session TEXT, ws TEXT, ts INTEGER, kind TEXT, upto INTEGER);
CREATE INDEX IF NOT EXISTS contacts_ix ON contacts(session, ws, ts);
CREATE TABLE IF NOT EXISTS refusals(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER,
  session TEXT, ws TEXT, code TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS last_event(session TEXT, ws TEXT, seq INTEGER, type TEXT,
  wall_ms INTEGER, seen_ms INTEGER, act_seq INTEGER, act_type TEXT, act_wall_ms INTEGER,
  act_seen_ms INTEGER, submitted INTEGER, ended INTEGER, end_reason TEXT,
  PRIMARY KEY(session, ws));
CREATE TABLE IF NOT EXISTS boots(session TEXT, ws TEXT, boot_id TEXT, first_seen_ms INTEGER,
  first_seq INTEGER, gap_before_ms INTEGER, PRIMARY KEY(session, ws, boot_id));
"""

_PING = ("v", "exam_id", "session_id", "ws_id", "boot_id", "boot_ns", "last_seq")
# what a teacher counts as "something the student did" (types only, never their data)
ACTIVITY = frozenset({"FILE_SAVE", "RUN_START", "RUN_END", "SUBMIT"})
_LE_COLS = ("seq", "type", "wall_ms", "seen_ms", "act_seq", "act_type", "act_wall_ms",
            "act_seen_ms", "submitted", "ended", "end_reason")


class WitnessError(Exception):
    pass


class Reply(NamedTuple):
    status: int
    body: bytes


def _err(status: int, code: str, detail: str) -> Reply:
    return Reply(status, canon.dumps({"error": code, "detail": detail[:400]}))


def make_ping(signer: keys.Signer, *, exam_id: str, session_id: str, ws_id: str,
              boot_id: str, boot_ns: int, last_seq: int) -> bytes:
    body = {"v": 1, "exam_id": exam_id, "session_id": session_id, "ws_id": ws_id,
            "boot_id": boot_id, "boot_ns": boot_ns, "last_seq": last_seq}
    return canon.dumps({"body": body, "sig": signer.sign(hashing.PING, canon.dumps(body))})


def _put(path: Path, data: bytes) -> None:
    if path.exists():
        return
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


class Witness:
    def __init__(self, roster: Roster, signer: keys.Signer, witness_id: str, *,
                 directory: str | Path | None = None, now_ms=None, keep_batches: bool = True):
        w = roster.witness(witness_id)
        if w is None or w.pub != signer.pub_hex:
            raise WitnessError("this key is not the one listed for that witness id in the roster")
        self.roster, self._signer, self.id = roster, signer, witness_id
        self._now = now_ms or (lambda: time.time_ns() // 1_000_000)
        self._lock = threading.RLock()
        self.keep_batches = keep_batches
        self.dir = Path(directory) if directory else None
        self.issued: list[bytes] | None = [] if self.dir is None else None
        if self.dir:
            for sub in ("anchors", "batches"):
                (self.dir / sub).mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.dir / "witness.db") if self.dir else ":memory:",
                                   check_same_thread=False, isolation_level=None)
        if self.dir:
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(SCHEMA)
        row = self._db.execute("SELECT v FROM meta WHERE k='roster_id'").fetchone()
        if row and row[0] != roster.id:
            raise WitnessError("this witness directory belongs to a different roster")
        if not row:
            self._db.execute("INSERT INTO meta VALUES('roster_id', ?)", (roster.id,))

    # ------------------------------------------------------------------ batches
    def submit(self, raw: bytes) -> Reply:
        if len(raw) > MAX_BATCH_BYTES:
            return _err(413, "too_large", "batch file is too large")
        b, fs = verify_batch(raw)
        if b is None:
            return _err(400, "malformed", fs[0].detail)
        if fs:
            return _err(422, "defective", "batch failed its own checks: "
                        + ", ".join(sorted({f.code.value for f in fs})))
        h = b.header
        if h["exam_id"] != self.roster.exam_id:
            return _err(403, "wrong_exam", "batch is for a different exam")
        hashes = [e.hash() for e in b.events]
        bid = hashing.sha256_hex(b.to_bytes())
        now = self._now()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                refusal = self._admit(b, hashes, now)
                self._db.execute("ROLLBACK" if refusal else "COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            if refusal:
                status, code, detail, record = refusal
                if record:
                    self._db.execute(
                        "INSERT INTO refusals(ts, session, ws, code, detail) VALUES(?,?,?,?,?)",
                        (now, h["session_id"], h["ws_id"], code, detail[:400]))
                return _err(status, code, detail)
            seen = self._db.execute(
                "SELECT seen_ms FROM held WHERE session=? AND ws=? AND seq=?",
                (h["session_id"], h["ws_id"], h["last_seq"])).fetchone()[0]
        a = anchor.make_witness(self._signer, exam_id=h["exam_id"], session_id=h["session_id"],
                                ws_id=h["ws_id"], upto_seq=h["last_seq"], head=h["head"],
                                holder=self.id, seen_ms=seen)
        self._store(a, b, bid)
        return Reply(200, a)

    def _authorize(self, b) -> str | None:
        h = b.header
        ses, ws, signer = h["session_id"], h["ws_id"], h["signer"]
        q = self._db.execute
        ok, why = None, ""
        seat = self.roster.seat(ws)
        if seat is not None:
            ok, why = seat.pub == signer, "this key is not the one enrolled for that seat"
        else:
            row = q("SELECT pub FROM bound WHERE session=? AND ws=?", (ses, ws)).fetchone()
            if row:
                ok, why = row[0] == signer, "that seat was bound to a different key by a transfer"
        transfers = [e for e in b.events if e.type == "TRANSFER"
                     and e.exam_id == self.roster.exam_id
                     and not transfer.check_event(e, signer, self.roster.assessor)]
        if ok is None:
            if not transfers:
                return "the seat is not on the roster and no assessor-signed transfer was shown"
            q("INSERT OR IGNORE INTO bound VALUES(?,?,?)", (ses, ws, signer))
            ok = True
        if not ok:
            return why
        for e in transfers:
            q("INSERT OR IGNORE INTO retired VALUES(?,?,?)",
              (ses, e.data["from_ws_id"], e.data["from_last_seq"]))
        return None

    def _admit(self, b, hashes, now):
        h = b.header
        ses, ws = h["session_id"], h["ws_id"]
        first, last = h["first_seq"], h["last_seq"]
        q = self._db.execute
        why = self._authorize(b)
        if why:
            return (403, "not_enrolled", why, False)
        r = q("SELECT last_seq FROM retired WHERE session=? AND ws=?", (ses, ws)).fetchone()
        if r and last > r[0]:
            return (409, "seat_retired",
                    f"seat {ws} was transferred away after event {r[0]}; later events are not accepted", True)
        held = dict(q("SELECT seq, hash FROM held WHERE session=? AND ws=? AND seq BETWEEN ? AND ?",
                      (ses, ws, first, last)).fetchall())
        bad = [f"position {e.seq} is already held as {held[e.seq][:8]} but this batch has {hh[:8]}"
               for e, hh in zip(b.events, hashes) if e.seq in held and held[e.seq] != hh]
        if first > 0:
            p = q("SELECT hash FROM held WHERE session=? AND ws=? AND seq=?", (ses, ws, first - 1)).fetchone()
            if p and p[0] != h["first_prev"]:
                bad.append(f"this batch does not continue the event held at position {first - 1}")
        n = q("SELECT prev FROM held WHERE session=? AND ws=? AND seq=?", (ses, ws, last + 1)).fetchone()
        if n and n[0] != h["head"]:
            bad.append(f"the event held at position {last + 1} does not continue this batch")
        if bad:
            return (409, "conflict", "; ".join(bad[:3]), True)
        self._db.executemany("INSERT OR IGNORE INTO held VALUES(?,?,?,?,?,?)",
                             [(ses, ws, e.seq, hh, e.prev, now) for e, hh in zip(b.events, hashes)])
        self._note_events(ses, ws, b.events, now)   # board facts; same transaction as the batch
        q("INSERT INTO contacts VALUES(?,?,?,?,?)", (ses, ws, now, "batch", last))
        return None

    def _store(self, a_bytes: bytes, b, bid: str) -> None:
        if self.dir is None:
            self.issued.append(a_bytes)
            return
        a = anchor.parse(a_bytes)
        _put(self.dir / "anchors" / f"{a.id}.anchor.json", a_bytes)
        if self.keep_batches:
            _put(self.dir / "batches" / f"{bid}.batch.json", b.to_bytes())

    # ------------------------------------------------------------------ board facts
    def _note_boot(self, ses: str, ws: str, boot_id: str, seq: int, now: int) -> None:
        """First time this boot id is seen, and how long contact had been silent before it."""
        q = self._db.execute
        if q("SELECT 1 FROM boots WHERE session=? AND ws=? AND boot_id=?",
             (ses, ws, boot_id)).fetchone():
            return
        prev = q("SELECT MAX(ts) FROM contacts WHERE session=? AND ws=?", (ses, ws)).fetchone()[0]
        q("INSERT INTO boots VALUES(?,?,?,?,?,?)",
          (ses, ws, boot_id, now, seq, None if prev is None else max(0, now - prev)))

    def _note_events(self, ses: str, ws: str, events, now: int) -> None:
        """Remember event TYPES for the teacher board. Called inside the batch's transaction,
        so a refused batch leaves nothing behind. Types and times only: never event data."""
        q = self._db.execute
        row = q("SELECT " + ", ".join(_LE_COLS) + " FROM last_event WHERE session=? AND ws=?",
                (ses, ws)).fetchone()
        cur = dict(zip(_LE_COLS, row)) if row else {c: None for c in _LE_COLS}
        cur["submitted"] = cur["submitted"] or 0
        cur["ended"] = cur["ended"] or 0
        seen_boots: set[str] = set()
        for e in sorted(events, key=lambda e: e.seq):
            if cur["seq"] is None or e.seq > cur["seq"]:
                cur.update(seq=e.seq, type=e.type, wall_ms=e.wall_ms, seen_ms=now)
            if e.type in ACTIVITY and (cur["act_seq"] is None or e.seq > cur["act_seq"]):
                cur.update(act_seq=e.seq, act_type=e.type, act_wall_ms=e.wall_ms, act_seen_ms=now)
            if e.type == "SUBMIT":
                cur["submitted"] = 1
            if e.type == "SESSION_END":
                cur["ended"] = 1
                cur["end_reason"] = e.data.get("reason")
            if e.boot_id not in seen_boots:
                seen_boots.add(e.boot_id)
                self._note_boot(ses, ws, e.boot_id, e.seq, now)
        q("INSERT OR REPLACE INTO last_event(session, ws, " + ", ".join(_LE_COLS) + ") VALUES(?,?,"
          + ",".join("?" * len(_LE_COLS)) + ")", (ses, ws, *[cur[c] for c in _LE_COLS]))

    # -------------------------------------------------------------------- pings
    def _seat_pub(self, ses: str, ws: str) -> str | None:
        seat = self.roster.seat(ws)
        if seat is not None:
            return seat.pub
        row = self._db.execute("SELECT pub FROM bound WHERE session=? AND ws=?", (ses, ws)).fetchone()
        return row[0] if row else None

    def ping(self, raw: bytes) -> Reply:
        try:
            obj = canon.loads(raw, max_bytes=2048)
        except canon.CanonError as e:
            return _err(400, "malformed", str(e))
        if not isinstance(obj, dict) or set(obj) != {"body", "sig"} \
                or not isinstance(obj["body"], dict) or set(obj["body"]) != set(_PING):
            return _err(400, "malformed", "ping must be {body, sig}")
        b = obj["body"]
        ints = all(isinstance(b[k], int) and not isinstance(b[k], bool) for k in ("boot_ns", "last_seq"))
        if b["v"] != 1 or not ints or b["boot_ns"] < 0 or b["last_seq"] < -1 or not all(
                isinstance(b[k], str) and ID_RE.match(b[k])
                for k in ("exam_id", "session_id", "ws_id", "boot_id")):
            return _err(400, "malformed", "bad ping body")
        if b["exam_id"] != self.roster.exam_id:
            return _err(403, "wrong_exam", "ping is for a different exam")
        ses, ws, now = b["session_id"], b["ws_id"], self._now()
        with self._lock:
            pub = self._seat_pub(ses, ws)
            if pub is None:
                return _err(403, "not_enrolled", "no key is bound to that seat yet")
            if not keys.verify(hashing.PING, pub, canon.dumps(b), obj["sig"]):
                return _err(403, "bad_signature", "ping signature does not verify")
            q = self._db.execute
            row = q("SELECT boot_id, boot_ns FROM pings WHERE session=? AND ws=?", (ses, ws)).fetchone()
            if row and row[0] == b["boot_id"] and b["boot_ns"] <= row[1]:
                return _err(409, "replay", "this ping is not newer than the last one in this boot")
            q("INSERT OR REPLACE INTO pings VALUES(?,?,?,?)", (ses, ws, b["boot_id"], b["boot_ns"]))
            self._note_boot(ses, ws, b["boot_id"], b["last_seq"], now)
            q("INSERT INTO contacts VALUES(?,?,?,?,?)", (ses, ws, now, "ping", b["last_seq"]))
            top = q("SELECT MAX(seq) FROM held WHERE session=? AND ws=?", (ses, ws)).fetchone()[0]
        return Reply(200, canon.dumps({"ok": True, "held_upto": -1 if top is None else top,
                                       "seen_ms": now}))

    # ------------------------------------------------------------------- report
    def report(self) -> dict:
        q = self._db.execute
        seats = []
        for ses, ws, first, last, top, n in q(
                "SELECT session, ws, MIN(seen_ms), MAX(seen_ms), MAX(seq), COUNT(*) FROM held "
                "GROUP BY session, ws ORDER BY session, ws").fetchall():
            ts = [r[0] for r in q("SELECT ts FROM contacts WHERE session=? AND ws=? ORDER BY ts",
                                  (ses, ws)).fetchall()]
            seats.append({"session": ses, "ws": ws, "events_held": n, "held_upto": top,
                          "first_seen_ms": first, "last_seen_ms": last,
                          "contacts": len(ts),
                          "longest_contact_gap_ms": max((b - a for a, b in zip(ts, ts[1:])), default=0)})
        refusals = [{"ts": r[0], "session": r[1], "ws": r[2], "code": r[3], "detail": r[4]}
                    for r in q("SELECT ts, session, ws, code, detail FROM refusals ORDER BY id").fetchall()]
        return {"witness": self.id, "exam_id": self.roster.exam_id, "roster_id": self.roster.id,
                "seats": seats, "refusals": refusals}

    # ------------------------------------------------------------- teacher board
    def clock_ms(self) -> int:
        return self._now()

    def board_raw(self, now_ms: int | None = None) -> dict:
        """Per-seat facts for the teacher board. Facts only: board.classify() draws conclusions.
        Reads only; report() and everything the verifier uses are untouched."""
        now = self._now() if now_ms is None else now_ms
        q = self._db.execute
        with self._lock:
            rows: dict[tuple[str, str], dict] = {}
            for ses, ws, top, n in q(
                    "SELECT session, ws, MAX(seq), COUNT(*) FROM held GROUP BY session, ws").fetchall():
                rows[(ses, ws)] = {"held_upto": top, "events_held": n}
            for ses, ws, first, last, n in q(
                    "SELECT session, ws, MIN(ts), MAX(ts), COUNT(*) FROM contacts "
                    "GROUP BY session, ws").fetchall():
                r = rows.setdefault((ses, ws), {"held_upto": -1, "events_held": 0})
                r.update(first_contact_ms=first, last_contact_ms=last, contacts=n)
            retired = {(s, w) for s, w in q("SELECT session, ws FROM retired").fetchall()}
            out = []
            for (ses, ws), r in sorted(rows.items()):
                args = (ses, ws)
                last = q("SELECT kind FROM contacts WHERE session=? AND ws=? "
                         "ORDER BY ts DESC LIMIT 1", args).fetchone()
                ping = q("SELECT upto FROM contacts WHERE session=? AND ws=? AND kind='ping' "
                         "ORDER BY ts DESC LIMIT 1", args).fetchone()
                le = q("SELECT seq, type, wall_ms, seen_ms, act_seq, act_type, act_wall_ms, "
                       "act_seen_ms, submitted, ended, end_reason FROM last_event "
                       "WHERE session=? AND ws=?", args).fetchone()
                boots = q("SELECT first_seen_ms, gap_before_ms FROM boots WHERE session=? AND ws=? "
                          "ORDER BY first_seen_ms, first_seq", args).fetchall()
                seat = self.roster.seat(ws)
                row = {"session": ses, "ws": ws, "candidate": seat.candidate if seat else None,
                       "enrolled": seat is not None, **r,
                       "last_contact_kind": last[0] if last else None,
                       "agent_last_seq": ping[0] if ping else None,
                       "restarts": max(0, len(boots) - 1),
                       "last_restart": ({"seen_ms": boots[-1][0], "gap_before_ms": boots[-1][1]}
                                        if len(boots) > 1 else None),
                       "transferred": (ses, ws) in retired}
                if le:
                    row["last_event"] = {"type": le[1], "seq": le[0], "wall_ms": le[2], "seen_ms": le[3]}
                    if le[5] is not None:
                        row["last_action"] = {"type": le[5], "seq": le[4], "wall_ms": le[6],
                                              "seen_ms": le[7]}
                    row.update(submitted=bool(le[8]), ended=bool(le[9]), end_reason=le[10])
                out.append(row)
            seen_ws = {ws for _, ws in rows}
            for seat in self.roster.seats:               # enrolled, never heard from
                if seat.candidate and seat.ws_id not in seen_ws:
                    out.append({"session": None, "ws": seat.ws_id, "candidate": seat.candidate,
                                "enrolled": True, "events_held": 0, "held_upto": -1})
        return {"witness": self.id, "exam_id": self.roster.exam_id, "now_ms": now, "seats": out}

    def seat_trail(self, session: str, ws: str, *, min_gap_ms: int = 25_000,
                   now_ms: int | None = None) -> dict | None:
        """Contact silences and boots for one seat (the board's detail drawer)."""
        now = self._now() if now_ms is None else now_ms
        q = self._db.execute
        with self._lock:
            ts = [r[0] for r in q("SELECT ts FROM contacts WHERE session=? AND ws=? "
                                  "ORDER BY ts DESC LIMIT 5000", (session, ws)).fetchall()][::-1]
            boots = [{"seen_ms": a, "gap_before_ms": g, "first_seq": s} for a, g, s in q(
                "SELECT first_seen_ms, gap_before_ms, first_seq FROM boots WHERE session=? AND ws=? "
                "ORDER BY first_seen_ms, first_seq", (session, ws)).fetchall()]
        if not ts and not boots:
            return None
        seat = self.roster.seat(ws)
        return {"session": session, "ws": ws, "candidate": seat.candidate if seat else None,
                "now_ms": now, "contacts_seen": len(ts),
                "first_contact_ms": ts[0] if ts else None,
                "gaps": board.gaps(ts, min_gap_ms), "boots": boots,
                "longest_gap_ms": max((b - a for a, b in zip(ts, ts[1:])), default=0)}

    def close(self) -> None:
        with suppress(Exception):
            self._db.close()
