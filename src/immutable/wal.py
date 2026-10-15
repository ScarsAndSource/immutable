"""wal.py: the log that survives the power cut, and says so.

Frame on disk:   "CW" | len u32be | payload (canonical event JSON) | crc32 u32be
(crc covers len||payload). The hash chain inside the payloads is the real
integrity; the CRC exists only so a torn write is recognisable as a torn write.

THE TORN-TAIL RULE
  Scan from byte 0. A record is accepted if it is whole and its CRC matches.
  The first record that is not accepted is judged by one question: could
  anything valid come after it?
    * it runs past EOF, or is a stub shorter than a header, or is a zero-filled
      tail, or is CRC-bad AND ends exactly at EOF  ->  TORN TAIL. Truncate there.
      This is what a power cut leaves behind.
    * anything else (bad magic with data, CRC-bad with bytes after it, valid
      CRC but the event breaks the chain)  ->  CORRUPT. We refuse to guess and
      raise WalCorrupt. A human decides. We would rather stop than quietly drop
      the middle of someone's evidence.

FAIL-STOP
  If a write or fsync fails, the log is in an unknown state (a failed fsync can
  drop pages while reporting nothing on retry). So the Wal marks itself broken
  and refuses every further append. Restart goes through recover().

ACKNOWLEDGED MEANS FSYNCED
  append(sync=True) returns only after fsync. durable_seq is the last event that
  is on disk. Only durable events may be sealed into batches or shown to the
  witness; otherwise someone could hold a head that our own disk never kept.
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from . import canon, clock, hashing, policy
from .batch import Batch, seal
from .events import ChainWriter, Event, EventError
from .fsys import FS, Handle
from .keys import Signer

MAGIC = b"CW"
HDR = 6                    # magic + len
TRL = 4                    # crc
MAX_RECORD = 1 << 16


class WalError(Exception):
    pass


class WalMissing(WalError):
    """No log where one should be. Could be a restore-on-reboot wipe (deployment risk #4)."""


class WalCorrupt(WalError):
    pass


def frame(payload: bytes) -> bytes:
    if not 0 < len(payload) <= MAX_RECORD:
        raise WalError("record size out of range")
    ln = struct.pack(">I", len(payload))
    crc = zlib.crc32(ln + payload) & 0xFFFFFFFF
    return MAGIC + ln + payload + struct.pack(">I", crc)


@dataclass
class Scan:
    payloads: list[bytes]
    valid_end: int
    torn_bytes: int
    corrupt_at: int | None


def scan(buf: bytes) -> Scan:
    pos, n, out = 0, len(buf), []
    while pos < n:
        if n - pos < HDR:
            return Scan(out, pos, n - pos, None)                   # stub
        if buf[pos:pos + 2] != MAGIC:
            if buf.count(b"\x00", pos) == n - pos:                 # zero-filled tail
                return Scan(out, pos, n - pos, None)
            return Scan(out, pos, 0, pos)
        (ln,) = struct.unpack_from(">I", buf, pos + 2)
        if not 0 < ln <= MAX_RECORD:
            return Scan(out, pos, 0, pos)
        end = pos + HDR + ln + TRL
        if end > n:
            return Scan(out, pos, n - pos, None)                   # runs past EOF
        payload = buf[pos + HDR: pos + HDR + ln]
        (crc,) = struct.unpack_from(">I", buf, pos + HDR + ln)
        if crc != zlib.crc32(buf[pos + 2: pos + HDR] + payload) & 0xFFFFFFFF:
            if end == n:
                return Scan(out, pos, n - pos, None)               # damaged last record
            return Scan(out, pos, 0, pos)                          # damage with data after
        out.append(bytes(payload))
        pos = end
    return Scan(out, pos, 0, None)


def _replay(payloads: list[bytes], exam: str, session: str, ws: str) -> list[Event]:
    events: list[Event] = []
    prev = hashing.ZERO
    for i, p in enumerate(payloads):
        try:
            ev = Event.from_body(canon.loads(p, max_bytes=MAX_RECORD, require_canonical=True))
            policy.validate(ev.type, ev.data)
        except (canon.CanonError, EventError, policy.PolicyError) as e:
            raise WalCorrupt(f"record {i} is intact but invalid: {e}") from None
        if (ev.exam_id, ev.session_id, ev.ws_id) != (exam, session, ws):
            raise WalCorrupt(f"record {i} belongs to a different exam, session or seat")
        if ev.seq != i or ev.prev != prev:
            raise WalCorrupt(f"record {i} breaks the chain")
        prev = ev.hash()
        events.append(ev)
    return events


@dataclass
class Recovered:
    wal: "Wal"
    events_found: int
    last_good_seq: int | None
    discarded_bytes: int
    recovery_event: Event | None
    batch: Batch | None            # the RECOVERY event, sealed at once if a signer was given


class Wal:
    def __init__(self, fs: FS, path: str, writer: ChainWriter, handle: Handle,
                 events: list[Event]):
        self._fs, self.path, self._w, self._h = fs, path, writer, handle
        self.events = events
        self._durable = -1
        self._broken = False

    # ---- lifecycle
    @classmethod
    def create(cls, fs: FS, path: str, exam_id: str, session_id: str, ws_id: str) -> "Wal":
        h = fs.open_append(path, create=True)       # FileExistsError if a log is already there
        try:
            fs.sync_dir(path)                       # the file's existence must survive too
        except Exception:
            h.close()
            raise
        return cls(fs, path, ChainWriter(exam_id, session_id, ws_id), h, [])

    @classmethod
    def recover(cls, fs: FS, path: str, exam_id: str, session_id: str, ws_id: str,
                *, signer: Signer | None = None) -> Recovered:
        if not fs.exists(path):
            raise WalMissing(path)
        sc = scan(fs.read(path))
        if sc.corrupt_at is not None:
            raise WalCorrupt(f"damaged record at byte {sc.corrupt_at} with data after it; "
                             "this is not a torn tail, refusing to guess")
        events = _replay(sc.payloads, exam_id, session_id, ws_id)
        if sc.torn_bytes:
            fs.truncate(path, sc.valid_end)

        last = events[-1] if events else None
        writer = ChainWriter(
            exam_id, session_id, ws_id, boot_id=clock.boot_id(),
            head=last.hash() if last else hashing.ZERO,
            next_seq=last.seq + 1 if last else 0)
        wal = cls(fs, path, writer, fs.open_append(path), events)
        try:
            wal._h.sync()               # what we read back may only have been in cache
        except Exception as e:
            wal._broken = True
            raise WalError(f"fsync failed during recovery: {e}") from e
        wal._durable = len(events) - 1

        if last is None:
            return Recovered(wal, 0, None, sc.torn_bytes, None, None)
        rec = wal.append("RECOVERY", {"last_good_seq": last.seq,
                                      "discarded_bytes": sc.torn_bytes})
        sealed = seal(signer, [rec]) if signer else None
        return Recovered(wal, len(events), last.seq, sc.torn_bytes, rec, sealed)

    # ---- writing
    def append(self, etype: str, data: dict | None = None, *, sync: bool = True) -> Event:
        if self._broken:
            raise WalError("fail-stop: an earlier I/O error left this log in an unknown "
                           "state; restart through Wal.recover")
        ev = self._w.append(etype, data)            # PolicyError here changes nothing
        try:
            self._h.write(frame(ev.canonical()))
            self.events.append(ev)
            if sync:
                self._h.sync()
                self._durable = ev.seq
        except Exception as e:
            self._broken = True
            raise WalError(f"write failed, log is now fail-stopped: {e}") from e
        return ev

    def commit(self) -> None:
        """Group commit: one fsync for everything appended with sync=False."""
        if self._broken:
            raise WalError("fail-stop: log is broken")
        try:
            self._h.sync()
            self._durable = len(self.events) - 1
        except Exception as e:
            self._broken = True
            raise WalError(f"fsync failed, log is now fail-stopped: {e}") from e

    # ---- reading
    @property
    def durable_seq(self) -> int:
        return self._durable

    @property
    def head(self) -> str:
        return self._w.head

    def durable_events(self, from_seq: int = 0) -> list[Event]:
        """Events that are on disk. Seal and send only these."""
        return [e for e in self.events if from_seq <= e.seq <= self._durable]

    def close(self) -> None:
        self._h.close()
