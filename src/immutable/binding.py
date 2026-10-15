"""binding.py: given the roster and the chains we saw, who really is who?

resolve() builds seat -> key -> candidate, applies authentic transfers, and returns
(bindings, [(observed chain, finding)]). Findings are paired with the chain that
caused them, so the reconciler can count them against that chain only. A forged
chain injected next to an honest one therefore cannot change the honest verdict.

Only transfer problems are produced here: TRANSFER_INVALID, TRANSFER_MISMATCH.
Key-versus-seat checks live in reconcile, where primary and foreign chains are known.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Mapping

from .events import Event
from .findings import Code, Finding
from .roster import Roster
from .transfer import check_event


@dataclass(frozen=True)
class Binding:
    ws_id: str
    pub: str
    candidate: str | None
    via: str                      # "roster" | "transfer" | "retired"


@dataclass
class Observed:
    """One (session, seat, key) chain as the reconciler sees it."""
    session_id: str
    ws_id: str
    signer: str
    last_seq: int                                           # highest seq seen at all
    hashes: Mapping[int, str] = field(default_factory=dict)  # seq -> hash on the trunk
    transfer: Event | None = None


def resolve(roster: Roster, observed: list[Observed]
            ) -> tuple[dict[str, Binding], list[tuple[Observed, Finding]]]:
    out: list[tuple[Observed, Finding]] = []

    def emit(o: Observed, f: Finding) -> None:
        out.append((o, replace(f, session=o.session_id, ws=o.ws_id)))

    bindings = {s.ws_id: Binding(s.ws_id, s.pub, s.candidate, "roster") for s in roster.seats}
    order = sorted(observed, key=lambda x: (x.session_id, x.ws_id, x.signer))

    authentic: list[tuple[Observed, Event]] = []
    for o in order:
        ev = o.transfer
        if ev is None:
            continue
        bad = check_event(ev, o.signer, roster.assessor)
        if ev.exam_id != roster.exam_id:
            bad.append(Finding(Code.TRANSFER_INVALID, ev.seq, "transfer is for another exam"))
        for f in bad:
            emit(o, f)
        if not bad:
            authentic.append((o, ev))

    pending = list(authentic)
    progress = True
    while pending and progress:
        progress = False
        for item in list(pending):
            o, ev = item
            frm = bindings.get(ev.data["from_ws_id"])
            if frm is None:
                continue
            pending.remove(item)
            progress = True
            existing = bindings.get(ev.ws_id)
            if existing is not None and existing.pub != o.signer:
                emit(o, Finding(Code.TRANSFER_INVALID, ev.seq,
                                f"seat {ev.ws_id} is enrolled with a different key"))
                continue
            bindings[ev.ws_id] = Binding(ev.ws_id, o.signer, frm.candidate, "transfer")
            bindings[frm.ws_id] = Binding(frm.ws_id, frm.pub, None, "retired")
    for o, ev in pending:
        emit(o, Finding(Code.TRANSFER_INVALID, ev.seq,
                        f"transfer comes from seat {ev.data['from_ws_id']}, which is not "
                        "bound to anyone at that point"))

    by_chain: dict[tuple[str, str], list[Observed]] = {}
    for o in order:
        by_chain.setdefault((o.session_id, o.ws_id), []).append(o)

    def chain(sid: str, ws: str) -> Observed | None:
        lst = by_chain.get((sid, ws), [])
        b = bindings.get(ws)
        return next((o for o in lst if b and b.pub == o.signer), lst[0] if lst else None)

    for o, ev in authentic:
        n, head = ev.data["from_last_seq"], ev.data["from_head"]
        old = chain(o.session_id, ev.data["from_ws_id"])
        ws = ev.data["from_ws_id"]
        if old is None:
            emit(o, Finding(Code.TRANSFER_MISMATCH, ev.seq, f"no log was provided for the old seat {ws}"))
        elif old.last_seq > n:
            emit(o, Finding(Code.TRANSFER_MISMATCH, ev.seq,
                            f"old seat {ws} kept writing after the transfer (events {n + 1} to {old.last_seq})"))
        elif old.last_seq < n:
            emit(o, Finding(Code.TRANSFER_MISMATCH, ev.seq,
                            f"old seat {ws} log ends at {old.last_seq} but the assessor recorded {n}; its tail is missing"))
        elif old.hashes.get(n) != head:
            emit(o, Finding(Code.TRANSFER_MISMATCH, ev.seq,
                            f"old seat {ws} has no event matching what the assessor recorded at {n}"))
    return bindings, out


def candidate_of(bindings: dict[str, Binding], ws_id: str) -> str | None:
    b = bindings.get(ws_id)
    return b.candidate if b else None
