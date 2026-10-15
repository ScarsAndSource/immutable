"""events.py: one entry in the log, and the hand that writes the next one."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import canon, clock, hashing, policy

ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_FIELDS = ("v", "exam_id", "session_id", "ws_id", "seq", "prev", "type",
           "wall_ms", "boot_ns", "boot_id", "data")


class EventError(ValueError):
    pass


def _isint(x: object) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


@dataclass(frozen=True, eq=False)
class Event:
    exam_id: str
    session_id: str
    ws_id: str
    seq: int
    prev: str
    type: str
    wall_ms: int
    boot_ns: int
    boot_id: str
    data: dict = field(default_factory=dict)
    v: int = 1

    def body(self) -> dict[str, Any]:
        return {f: getattr(self, f) for f in _FIELDS}

    def canonical(self) -> bytes:
        return canon.dumps(self.body())

    def hash(self) -> str:
        return hashing.hx(hashing.EVENT, self.canonical())

    @classmethod
    def from_body(cls, d: object) -> "Event":
        """Strict constructor for untrusted input. Raises EventError."""
        if not isinstance(d, dict) or set(d) != set(_FIELDS):
            raise EventError("event must have exactly the v1 fields")
        if d["v"] != 1 or not _isint(d["v"]):
            raise EventError("unsupported event version")
        for k in ("exam_id", "session_id", "ws_id"):
            if not (isinstance(d[k], str) and ID_RE.match(d[k])):
                raise EventError(f"bad {k}")
        for k in ("seq", "wall_ms", "boot_ns"):
            if not _isint(d[k]) or d[k] < 0:
                raise EventError(f"bad {k}")
        if not hashing.is_hash(d["prev"]):
            raise EventError("bad prev")
        if not (isinstance(d["boot_id"], str) and ID_RE.match(d["boot_id"])):
            raise EventError("bad boot_id")
        if not isinstance(d["type"], str) or not isinstance(d["data"], dict):
            raise EventError("bad type or data")
        return cls(**{k: d[k] for k in _FIELDS})


class ChainWriter:
    """Appends events to one session's chain. Knows seq and prev so nobody else has to.

    Durability (the write-ahead log) is the next layer; this only builds events.
    """

    def __init__(self, exam_id: str, session_id: str, ws_id: str, *,
                 boot_id: str | None = None, head: str = hashing.ZERO,
                 next_seq: int = 0):
        for name, val in (("exam_id", exam_id), ("session_id", session_id),
                          ("ws_id", ws_id)):
            if not ID_RE.match(val):
                raise EventError(f"bad {name}")
        self.exam_id, self.session_id, self.ws_id = exam_id, session_id, ws_id
        self.boot_id = boot_id or clock.boot_id()
        self.head = head
        self.next_seq = next_seq

    def append(self, etype: str, data: dict | None = None, *,
               wall_ms: int | None = None, boot_ns: int | None = None) -> Event:
        data = data or {}
        policy.validate(etype, data)             # no allow-list, no event
        if wall_ms is None or boot_ns is None:
            w, b = clock.stamp()
            wall_ms = w if wall_ms is None else wall_ms
            boot_ns = b if boot_ns is None else boot_ns
        ev = Event(self.exam_id, self.session_id, self.ws_id, self.next_seq,
                   self.head, etype, wall_ms, boot_ns, self.boot_id, data)
        self.head = ev.hash()
        self.next_seq += 1
        return ev
