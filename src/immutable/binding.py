"""binding.py: given the roster and the chains we saw, who really is who?

resolve() builds the seat -> key -> candidate map, applies valid transfers, and
returns every identity problem as a coded finding. It never decides guilt: a
duplicate key means "two seats claim one key", which could be imaging, a cloned
disk or an attacker, and a human reads the case.

Checks:
  DUPLICATE_KEY      one public key seen on more than one seat (imaging, cloning)
  UNKNOWN_SEAT       a chain from a ws_id the roster and transfers never mention
  KEY_NOT_ENROLLED   a chain signed by a key that is not the one bound to its seat
  TRANSFER_INVALID   forged, misplaced, or unresolvable transfer
  TRANSFER_MISMATCH  old chain does not end where the assessor said it did
                     (kept writing after the swap, different head, or not provided)
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Mapping

from . import keys
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
    """One chain as seen by the reconciler (B6)."""
    session_id: str
    ws_id: str
    signer: str                                   # pub that signed its batches
    last_seq: int
    hashes: Mapping[int, str] = field(default_factory=dict)   # seq -> event hash
    transfer: Event | None = None                 # its TRANSFER event, if it has one


def _kid(pub: str) -> str:
    return keys.key_id(pub)[:12]


def resolve(roster: Roster, observed: list[Observed]
            ) -> tuple[dict[str, Binding], list[Finding]]:
    out: list[Finding] = []
    bindings = {s.ws_id: Binding(s.ws_id, s.pub, s.candidate, "roster") for s in roster.seats}

    # 1. the same key on two seats (roster keys are already unique; chains may not be)
    seen: dict[str, set[str]] = defaultdict(set)
    for s in roster.seats:
        seen[s.pub].add(s.ws_id)
    for o in observed:
        seen[o.signer].add(o.ws_id)
    for pub, wss in sorted(seen.items()):
        if len(wss) > 1:
            out.append(Finding(Code.DUPLICATE_KEY, None,
                               f"key {_kid(pub)} appears on seats {sorted(wss)}"))

    # 2. transfers: authentic first, then applied in dependency order
    pending: list[tuple[Observed, Event]] = []
    for o in sorted((x for x in observed if x.transfer is not None),
                    key=lambda x: (x.ws_id, x.session_id)):
        ev = o.transfer
        bad = check_event(ev, o.signer, roster.assessor)
        if ev.exam_id != roster.exam_id:
            bad.append(Finding(Code.TRANSFER_INVALID, ev.seq, "transfer is for another exam"))
        if bad:
            out.extend(bad)
        else:
            pending.append((o, ev))

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
                out.append(Finding(Code.TRANSFER_INVALID, ev.seq,
                                   f"seat {ev.ws_id} is enrolled with a different key"))
                continue
            bindings[ev.ws_id] = Binding(ev.ws_id, o.signer, frm.candidate, "transfer")
            bindings[frm.ws_id] = Binding(frm.ws_id, frm.pub, None, "retired")
    for o, ev in pending:
        out.append(Finding(Code.TRANSFER_INVALID, ev.seq,
                           f"transfer comes from seat {ev.data['from_ws_id']}, "
                           "which is not bound to anyone at that point"))

    # 3. the old chain must stop exactly where the assessor said
    chains = {(o.session_id, o.ws_id): o for o in observed}
    for o in observed:
        ev = o.transfer
        if ev is None:
            continue
        n, head = ev.data["from_last_seq"], ev.data["from_head"]
        old = chains.get((o.session_id, ev.data["from_ws_id"]))
        if old is None:
            out.append(Finding(Code.TRANSFER_MISMATCH, ev.seq,
                               f"no log was provided for the old seat {ev.data['from_ws_id']}"))
        elif old.last_seq > n:
            out.append(Finding(Code.TRANSFER_MISMATCH, ev.seq,
                               f"old seat {old.ws_id} kept writing after the transfer "
                               f"(events {n + 1}..{old.last_seq})"))
        elif old.last_seq < n:
            out.append(Finding(Code.TRANSFER_MISMATCH, ev.seq,
                               f"old seat {old.ws_id} log ends at {old.last_seq} but the "
                               f"assessor recorded {n}: its tail is missing"))
        elif old.hashes.get(n) != head:
            out.append(Finding(Code.TRANSFER_MISMATCH, ev.seq,
                               f"old seat {old.ws_id} has a different event at {n} "
                               "than the one the assessor recorded"))

    # 4. every chain must be signed by the key its seat is bound to
    for o in observed:
        b = bindings.get(o.ws_id)
        if b is None:
            out.append(Finding(Code.UNKNOWN_SEAT, None,
                               f"seat {o.ws_id} is not on the roster or in any transfer"))
        elif b.pub != o.signer:
            out.append(Finding(Code.KEY_NOT_ENROLLED, None,
                               f"seat {o.ws_id} was signed by key {_kid(o.signer)}, "
                               f"not its enrolled key {_kid(b.pub)}"))
    return bindings, out


def candidate_of(bindings: dict[str, Binding], ws_id: str) -> str | None:
    b = bindings.get(ws_id)
    return b.candidate if b else None
