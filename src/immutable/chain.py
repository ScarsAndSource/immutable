"""chain.py: put one key's events back in order and say exactly where trust stops.

A Branch is everything one signing key said about one (session, seat), as a map
seq -> {event hash -> event}. Two events at one seq with different hashes is a FORK.
Identical events arriving twice collapse into one, which is what makes ingest
idempotent.

walk() follows prev links from the genesis value. The TRUNK is the longest
unambiguous, contiguous, hash-linked prefix. It ends at the first gap, fork or
broken link. We never pick a winner between fork branches: the trunk is the common
prefix, and everything after is reported, not trusted.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .events import Event
from .findings import Code, Finding
from .hashing import ZERO


@dataclass
class Branch:
    session_id: str
    ws_id: str
    signer: str
    by_seq: dict[int, dict[str, Event]] = field(default_factory=dict)
    batch_ids: set[str] = field(default_factory=set)

    def add(self, ev: Event) -> None:
        self.by_seq.setdefault(ev.seq, {})[ev.hash()] = ev

    @property
    def max_seq(self) -> int:
        return max(self.by_seq, default=-1)

    @property
    def total(self) -> int:
        return sum(len(c) for c in self.by_seq.values())


@dataclass
class Walk:
    trunk: list[Event]
    findings: list[Finding]
    max_seq: int
    beyond: int            # distinct events seen that are not on the trunk


def walk(br: Branch) -> Walk:
    seqs = sorted(br.by_seq)
    if not seqs:
        return Walk([], [], -1, 0)
    f: list[Finding] = []

    exp = 0
    for s in seqs:
        if s > exp:
            f.append(Finding(Code.MISSING_RANGE, exp,
                             f"events {exp} to {s - 1} are referenced by later events but were not provided"))
        exp = s + 1

    for s in seqs:
        cell = br.by_seq[s]
        if len(cell) > 1:
            f.append(Finding(Code.FORK, s, f"{len(cell)} different events were signed for position {s} "
                                           f"({', '.join(h[:8] for h in sorted(cell))})"))

    trunk: list[Event] = []
    prev, s, top = ZERO, 0, seqs[-1]
    while s <= top:
        cell = br.by_seq.get(s)
        if not cell:
            break                                   # gap, already reported
        linked = sorted(h for h, e in cell.items() if e.prev == prev)
        if len(linked) != 1:
            if not linked:
                where = "the first event does not start a chain" if s == 0 else \
                        f"events at position {s} do not continue the chain from event {s - 1}"
                f.append(Finding(Code.LINK_BREAK, s, where))
            break                                   # fork, already reported
        ev = cell[linked[0]]
        trunk.append(ev)
        prev = linked[0]
        s += 1
    return Walk(trunk, f, top, br.total - len(trunk))
