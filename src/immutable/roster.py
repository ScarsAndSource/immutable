"""roster.py: who is allowed to speak, signed by the one party who decides.

THE CEREMONY (all offline, files only; a USB stick is a fine network)
  1. Exam office makes an assessor key. Its fingerprint is read out / printed on
     the paper envelope. That fingerprint is the root of trust, delivered out of band.
  2. Each workstation makes its own key on that machine and writes an ENROLLMENT
     REQUEST: {exam_id, ws_id, pub} signed with the key it names. The signature is
     proof of possession; nobody can enroll a public key they do not hold.
     Keys are made at enrollment and never baked into a disk image.
  3. The office merges requests with a candidate list into the ROSTER and signs it.

THE ROSTER binds seat -> key -> candidate pseudonym -> exam paper hash, and lists
the witness keys. Real student identity is never in here; the exam office keeps
that mapping to itself. The roster's sha256 (plain, of the file bytes) goes into
every session's SESSION_START, so evidence is pinned to one exact roster.

Separation of duties is enforced at build and parse: the assessor key, every seat
key and every witness key must be pairwise distinct. A student machine holding the
assessor key, or a witness that is also a seat, would collapse the whole model.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass

from . import canon, hashing, keys
from .events import ID_RE

MAX_SEATS = 2000
MAX_WITNESSES = 16
MAX_ROSTER_BYTES = 2 << 20

_BODY = ("v", "exam_id", "issued_ms", "paper_sha256", "assessor", "seats", "witnesses")


class RosterError(ValueError):
    pass


@dataclass(frozen=True)
class Seat:
    ws_id: str
    pub: str
    candidate: str | None = None      # None = spare seat


@dataclass(frozen=True)
class Witness:
    witness_id: str
    pub: str


def _ident(x: object) -> bool:
    return isinstance(x, str) and bool(ID_RE.match(x))


def _uint(x: object) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 2**53


def _validate(body: object) -> tuple[tuple[Seat, ...], tuple[Witness, ...]]:
    if not isinstance(body, dict) or set(body) != set(_BODY):
        raise RosterError("roster body must have exactly the v1 fields")
    if body["v"] != 1 or not _uint(body["v"]):
        raise RosterError("unsupported roster version")
    if not _ident(body["exam_id"]):
        raise RosterError("bad exam_id")
    if not _uint(body["issued_ms"]):
        raise RosterError("bad issued_ms")
    if not hashing.is_hash(body["paper_sha256"]):
        raise RosterError("bad paper_sha256")
    if not hashing.is_hex(body["assessor"], 64):
        raise RosterError("bad assessor key")

    raw_seats, raw_wit = body["seats"], body["witnesses"]
    if not isinstance(raw_seats, list) or not isinstance(raw_wit, list):
        raise RosterError("seats and witnesses must be lists")
    if len(raw_seats) > MAX_SEATS or len(raw_wit) > MAX_WITNESSES:
        raise RosterError("too many seats or witnesses")

    seats: list[Seat] = []
    for s in raw_seats:
        if not isinstance(s, dict) or set(s) != {"ws_id", "pub", "candidate"}:
            raise RosterError("bad seat entry")
        if not _ident(s["ws_id"]) or not hashing.is_hex(s["pub"], 64) \
                or not (s["candidate"] is None or _ident(s["candidate"])):
            raise RosterError(f"bad seat entry for {s.get('ws_id')!r}")
        seats.append(Seat(s["ws_id"], s["pub"], s["candidate"]))
    ids = [s.ws_id for s in seats]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise RosterError("seats must be sorted by ws_id with no duplicates")
    cands = [s.candidate for s in seats if s.candidate is not None]
    if len(set(cands)) != len(cands):
        raise RosterError("a candidate is assigned to more than one seat")

    wits: list[Witness] = []
    for w in raw_wit:
        if not isinstance(w, dict) or set(w) != {"witness_id", "pub"} \
                or not _ident(w["witness_id"]) or not hashing.is_hex(w["pub"], 64):
            raise RosterError("bad witness entry")
        wits.append(Witness(w["witness_id"], w["pub"]))
    wids = [w.witness_id for w in wits]
    if wids != sorted(wids) or len(set(wids)) != len(wids):
        raise RosterError("witnesses must be sorted by id with no duplicates")

    owners: dict[str, list[str]] = defaultdict(list)
    owners[body["assessor"]].append("assessor")
    for s in seats:
        owners[s.pub].append(f"seat {s.ws_id}")
    for w in wits:
        owners[w.pub].append(f"witness {w.witness_id}")
    for pub, who in owners.items():
        if len(who) > 1:
            raise RosterError(f"one key is used by several roles ({', '.join(who)}); "
                              f"key id {keys.key_id(pub)[:16]}")
    return tuple(seats), tuple(wits)


class Roster:
    def __init__(self, body: dict, sig: str, raw: bytes):
        self.body, self.sig, self.raw = body, sig, raw
        self.seats, self.witnesses = _validate(body)
        self._by_ws = {s.ws_id: s for s in self.seats}
        self._by_pub = {s.pub: s for s in self.seats}
        self._wit = {w.witness_id: w for w in self.witnesses}

    # -- identity of the roster itself
    @property
    def id(self) -> str:
        """Plain SHA-256 of the file bytes; what SESSION_START.roster_sha256 holds."""
        return hashing.sha256_hex(self.raw)

    @property
    def exam_id(self) -> str:
        return self.body["exam_id"]

    @property
    def paper_sha256(self) -> str:
        return self.body["paper_sha256"]

    @property
    def assessor(self) -> str:
        return self.body["assessor"]

    @property
    def issued_ms(self) -> int:
        return self.body["issued_ms"]

    # -- lookups
    def seat(self, ws_id: str) -> Seat | None:
        return self._by_ws.get(ws_id)

    def seat_by_pub(self, pub: str) -> Seat | None:
        return self._by_pub.get(pub)

    def witness(self, witness_id: str) -> Witness | None:
        return self._wit.get(witness_id)

    def witness_by_pub(self, pub: str) -> Witness | None:
        return next((w for w in self.witnesses if w.pub == pub), None)

    # -- construction
    @classmethod
    def build(cls, assessor: keys.Signer, *, exam_id: str, paper_sha256: str,
              seats: list[Seat], witnesses: list[Witness] | tuple = (),
              issued_ms: int | None = None) -> "Roster":
        body = {
            "v": 1, "exam_id": exam_id,
            "issued_ms": time.time_ns() // 1_000_000 if issued_ms is None else issued_ms,
            "paper_sha256": paper_sha256, "assessor": assessor.pub_hex,
            "seats": [{"ws_id": s.ws_id, "pub": s.pub, "candidate": s.candidate}
                      for s in sorted(seats, key=lambda s: s.ws_id)],
            "witnesses": [{"witness_id": w.witness_id, "pub": w.pub}
                          for w in sorted(witnesses, key=lambda w: w.witness_id)],
        }
        _validate(body)
        sig = assessor.sign(hashing.ROSTER, canon.dumps(body))
        raw = canon.dumps({"body": body, "sig": sig})
        return cls(body, sig, raw)

    @classmethod
    def parse(cls, raw: bytes, *, trusted_assessor: str | None = None) -> "Roster":
        """Strict, signature-checked. Pass trusted_assessor: that key is the root of trust."""
        try:
            obj = canon.loads(raw, max_bytes=MAX_ROSTER_BYTES, require_canonical=True)
        except canon.CanonError as e:
            raise RosterError(f"roster file is not valid canonical JSON: {e}") from None
        if not isinstance(obj, dict) or set(obj) != {"body", "sig"}:
            raise RosterError("roster must be {body, sig}")
        body, sig = obj["body"], obj["sig"]
        if not isinstance(body, dict) or not hashing.is_hex(body.get("assessor"), 64):
            raise RosterError("roster has no usable assessor key")
        if trusted_assessor is not None and body["assessor"] != trusted_assessor:
            raise RosterError("roster is signed by a key other than the trusted assessor")
        if not keys.verify(hashing.ROSTER, body["assessor"], canon.dumps(body), sig):
            raise RosterError("roster signature does not verify")
        return cls(body, sig, raw)


# ----------------------------------------------------------- enrollment request

def make_request(signer: keys.Signer, exam_id: str, ws_id: str) -> bytes:
    if not (_ident(exam_id) and _ident(ws_id)):
        raise RosterError("bad exam_id or ws_id")
    body = {"v": 1, "exam_id": exam_id, "ws_id": ws_id, "pub": signer.pub_hex}
    sig = signer.sign(hashing.ENROLL, canon.dumps(body))
    return canon.dumps({"body": body, "sig": sig})


def parse_request(raw: bytes) -> dict:
    """Returns the body only if the signature proves the sender holds the key."""
    try:
        obj = canon.loads(raw, max_bytes=4096)
    except canon.CanonError as e:
        raise RosterError(f"enrollment request unreadable: {e}") from None
    if not isinstance(obj, dict) or set(obj) != {"body", "sig"}:
        raise RosterError("enrollment request must be {body, sig}")
    b = obj["body"]
    if not isinstance(b, dict) or set(b) != {"v", "exam_id", "ws_id", "pub"} or b["v"] != 1 \
            or not _ident(b["exam_id"]) or not _ident(b["ws_id"]) \
            or not hashing.is_hex(b["pub"], 64):
        raise RosterError("bad enrollment request body")
    if not keys.verify(hashing.ENROLL, b["pub"], canon.dumps(b), obj["sig"]):
        raise RosterError(f"request for {b['ws_id']} does not prove possession of its key")
    return b


# -------------------------------------------------------------------- preflight

def preflight(roster: Roster, *, exam_id: str, ws_id: str, pub: str,
              paper_sha256: str, as_transfer: bool = False) -> list[str]:
    """Plain-language reasons an agent should refuse to start. Empty list = go."""
    out = []
    if roster.exam_id != exam_id:
        out.append(f"this roster is for exam {roster.exam_id}, not {exam_id}")
    if roster.paper_sha256 != paper_sha256:
        out.append("the exam paper on this machine is not the one the roster was issued for")
    if not as_transfer:
        seat = roster.seat(ws_id)
        if seat is None:
            out.append(f"seat {ws_id} is not on the roster")
        elif seat.pub != pub:
            out.append(f"this machine's key is not the one enrolled for seat {ws_id}")
    return out
