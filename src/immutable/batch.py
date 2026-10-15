"""batch.py: a signed run of events, sealed like an envelope.

The header names the exam, session, workstation and the exact sequence range,
and commits to the head and the Merkle root. The signature covers the header,
so a batch cannot be moved to another session, seat or exam without breaking.

verify_batch returns findings. An empty list means *self-consistent* (A0), not
"verified". Only an outside holder of a head can upgrade that.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import canon, hashing, keys, merkle, policy
from .events import Event, EventError
from .findings import Code, Finding

_HEADER_FIELDS = ("v", "exam_id", "session_id", "ws_id", "first_seq", "last_seq",
                  "count", "first_prev", "head", "merkle_root", "signer")
MAX_BATCH_BYTES = 4 << 20


class BatchError(ValueError):
    pass


@dataclass(frozen=True, eq=False)
class Batch:
    header: dict
    events: list[Event]
    sig: str

    def to_bytes(self) -> bytes:
        return canon.dumps({"header": self.header,
                            "events": [e.body() for e in self.events],
                            "sig": self.sig})

    @classmethod
    def parse(cls, raw: bytes, *, max_bytes: int = MAX_BATCH_BYTES) -> "Batch":
        obj = canon.loads(raw, max_bytes=max_bytes)
        if not isinstance(obj, dict) or set(obj) != {"header", "events", "sig"}:
            raise BatchError("batch must be {header, events, sig}")
        header, evs, sig = obj["header"], obj["events"], obj["sig"]
        if not isinstance(header, dict) or set(header) != set(_HEADER_FIELDS):
            raise BatchError("bad header fields")
        if not isinstance(evs, list) or not evs:
            raise BatchError("events must be a non-empty list")
        for k in ("first_seq", "last_seq", "count"):
            if not isinstance(header[k], int) or isinstance(header[k], bool) \
                    or header[k] < 0:
                raise BatchError(f"bad header {k}")
        for k in ("first_prev", "head", "merkle_root"):
            if not hashing.is_hash(header[k]):
                raise BatchError(f"bad header {k}")
        if header["v"] != 1 or not hashing.is_hex(header["signer"], 64) \
                or not hashing.is_hex(sig, 128):
            raise BatchError("bad version, signer or signature shape")
        return cls(header, [Event.from_body(e) for e in evs], sig)


def seal(signer: keys.Signer, events: list[Event]) -> Batch:
    """Build and sign a batch from a contiguous run of one session's events."""
    if not events:
        raise BatchError("nothing to seal")
    first, last = events[0], events[-1]
    for i, e in enumerate(events):
        if (e.exam_id, e.session_id, e.ws_id) != \
                (first.exam_id, first.session_id, first.ws_id):
            raise BatchError("events span more than one session or seat")
        if e.seq != first.seq + i:
            raise BatchError("events are not contiguous")
    hashes = [e.hash() for e in events]
    header = {
        "v": 1, "exam_id": first.exam_id, "session_id": first.session_id,
        "ws_id": first.ws_id, "first_seq": first.seq, "last_seq": last.seq,
        "count": len(events), "first_prev": first.prev, "head": hashes[-1],
        "merkle_root": merkle.root(hashes), "signer": signer.pub_hex,
    }
    sig = signer.sign(hashing.BATCH, canon.dumps(header))
    return Batch(header, list(events), sig)


def verify_batch(raw: bytes, *, expected_pub: str | None = None,
                 ) -> tuple[Batch | None, list[Finding]]:
    """Check a batch end to end. Returns (batch or None, findings)."""
    try:
        b = Batch.parse(raw)
    except (canon.CanonError, EventError, BatchError) as e:
        return None, [Finding(Code.MALFORMED, None, str(e))]

    f: list[Finding] = []
    h = b.header

    if not keys.verify(hashing.BATCH, h["signer"], canon.dumps(h), b.sig):
        f.append(Finding(Code.BAD_SIGNATURE, None, "header signature does not verify"))
    if expected_pub is not None and h["signer"] != expected_pub:
        f.append(Finding(Code.SIGNER_MISMATCH, None,
                         "signer is not the key enrolled for this seat"))

    prev = h["first_prev"]
    hashes: list[str] = []
    for i, e in enumerate(b.events):
        if (e.exam_id, e.session_id, e.ws_id) != \
                (h["exam_id"], h["session_id"], h["ws_id"]):
            f.append(Finding(Code.WRONG_CONTEXT, e.seq,
                             "event belongs to a different exam, session or seat"))
        try:
            policy.validate(e.type, e.data)
        except policy.PolicyError as err:
            f.append(Finding(Code.POLICY_VIOLATION, e.seq, str(err)))
        if e.seq != h["first_seq"] + i:
            f.append(Finding(Code.SEQ_GAP, e.seq,
                             f"expected seq {h['first_seq'] + i}"))
        if e.prev != prev:
            f.append(Finding(Code.CHAIN_BREAK, e.seq,
                             "prev does not match the previous event's hash"))
        prev = e.hash()
        hashes.append(prev)

    if h["count"] != len(b.events):
        f.append(Finding(Code.HEADER_MISMATCH, None, "count differs from events"))
    if h["last_seq"] != h["first_seq"] + len(b.events) - 1:
        f.append(Finding(Code.HEADER_MISMATCH, None, "last_seq differs from events"))
    if h["head"] != hashes[-1]:
        f.append(Finding(Code.HEADER_MISMATCH, None, "head differs from last event"))
    if h["merkle_root"] != merkle.root(hashes):
        f.append(Finding(Code.HEADER_MISMATCH, None, "merkle_root differs from events"))
    return b, f
