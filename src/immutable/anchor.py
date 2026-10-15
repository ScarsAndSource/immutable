"""anchor.py: proof that someone outside the workstation held a head.

An anchor says: "holder H saw, at its own clock time seen_ms, that seat W of session
S had an event with hash `head` at position `upto_seq`." Because the hash chain
commits to everything before that event, one anchor pins the whole prefix.

kinds
  witness   signed by a roster witness key (domain "cosign"). Written by B9.
  assessor  unsigned record made by the assessor's own store when a batch arrives
            live over the LAN. Trusted only as far as the assessor's own database is.
  receipt   signed by the seat's enrolled key (domain "receipt"). Written by B10.
            A receipt alone is not an outside holder; assurance A2 needs A1 too.

File: canonical {"body": {...}, "sig": hex | null}.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import canon, hashing, keys
from .events import ID_RE
from .roster import Roster

KINDS = ("witness", "assessor", "receipt")
_BODY = ("v", "exam_id", "session_id", "ws_id", "upto_seq", "head", "kind", "holder", "seen_ms")


class AnchorError(ValueError):
    pass


@dataclass(frozen=True)
class Anchor:
    exam_id: str
    session_id: str
    ws_id: str
    upto_seq: int
    head: str
    kind: str
    holder: str
    seen_ms: int
    sig: str | None = None

    def body(self) -> dict:
        return {"v": 1, "exam_id": self.exam_id, "session_id": self.session_id,
                "ws_id": self.ws_id, "upto_seq": self.upto_seq, "head": self.head,
                "kind": self.kind, "holder": self.holder, "seen_ms": self.seen_ms}

    def to_bytes(self) -> bytes:
        return canon.dumps({"body": self.body(), "sig": self.sig})

    @property
    def id(self) -> str:
        return hashing.sha256_hex(self.to_bytes())


def _uint(x: object) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 2**53


def _validate(b: object) -> dict:
    if not isinstance(b, dict) or set(b) != set(_BODY) or b["v"] != 1:
        raise AnchorError("anchor body must have exactly the v1 fields")
    for k in ("exam_id", "session_id", "ws_id", "holder"):
        if not (isinstance(b[k], str) and ID_RE.match(b[k])):
            raise AnchorError(f"bad {k}")
    if not _uint(b["upto_seq"]) or not _uint(b["seen_ms"]):
        raise AnchorError("bad upto_seq or seen_ms")
    if not hashing.is_hash(b["head"]) or b["kind"] not in KINDS:
        raise AnchorError("bad head or kind")
    return b


def _make(kind: str, domain: str | None, signer: keys.Signer | None, **kw) -> bytes:
    a = Anchor(kind=kind, **kw)
    _validate(a.body())
    sig = signer.sign(domain, canon.dumps(a.body())) if signer else None
    return Anchor(kind=kind, sig=sig, **kw).to_bytes()


def make_witness(signer: keys.Signer, *, exam_id: str, session_id: str, ws_id: str,
                 upto_seq: int, head: str, holder: str, seen_ms: int) -> bytes:
    return _make("witness", hashing.COSIGN, signer, exam_id=exam_id, session_id=session_id,
                 ws_id=ws_id, upto_seq=upto_seq, head=head, holder=holder, seen_ms=seen_ms)


def make_receipt(signer: keys.Signer, *, exam_id: str, session_id: str, ws_id: str,
                 upto_seq: int, head: str, seen_ms: int) -> bytes:
    return _make("receipt", hashing.RECEIPT, signer, exam_id=exam_id, session_id=session_id,
                 ws_id=ws_id, upto_seq=upto_seq, head=head, holder=ws_id, seen_ms=seen_ms)


def make_assessor(*, exam_id: str, session_id: str, ws_id: str, upto_seq: int,
                  head: str, seen_ms: int) -> bytes:
    return _make("assessor", None, None, exam_id=exam_id, session_id=session_id,
                 ws_id=ws_id, upto_seq=upto_seq, head=head, holder="assessor", seen_ms=seen_ms)


def parse(raw: bytes) -> Anchor:
    """Shape check only. Authenticity is `authenticate`."""
    try:
        obj = canon.loads(raw, max_bytes=4096)
    except canon.CanonError as e:
        raise AnchorError(f"unreadable: {e}") from None
    if not isinstance(obj, dict) or set(obj) != {"body", "sig"}:
        raise AnchorError("anchor must be {body, sig}")
    b, sig = _validate(obj["body"]), obj["sig"]
    if b["kind"] == "assessor":
        if sig is not None:
            raise AnchorError("assessor anchors are unsigned")
    elif not hashing.is_hex(sig, 128):
        raise AnchorError("this kind of anchor needs a signature")
    return Anchor(b["exam_id"], b["session_id"], b["ws_id"], b["upto_seq"], b["head"],
                  b["kind"], b["holder"], b["seen_ms"], sig)


def authenticate(a: Anchor, roster: Roster, seat_pub: str | None = None) -> str | None:
    """None if the anchor is genuine, otherwise a plain-language reason."""
    if a.kind == "assessor":
        return None
    data = canon.dumps(a.body())
    if a.kind == "witness":
        w = roster.witness(a.holder)
        if w is None:
            return "the witness is not on the roster"
        return None if keys.verify(hashing.COSIGN, w.pub, data, a.sig) else "witness signature does not verify"
    if seat_pub is None:
        return "no key is bound to that seat"
    return None if keys.verify(hashing.RECEIPT, seat_pub, data, a.sig) else "receipt signature does not verify"
