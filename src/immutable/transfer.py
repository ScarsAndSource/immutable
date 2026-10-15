"""transfer.py: a legitimate seat swap, written down by the one who may authorise it.

A machine dies, a student is moved. The session continues on a new workstation
with its own key and its own chain. Left alone that is indistinguishable from a
student hopping to a machine of their choosing, so the assessor signs it:

  statement = {v, exam_id, session_id, from_ws_id, from_last_seq, from_head,
               to_ws_id, to_pub}                 (signed under domain "transfer")

It names the exact point where the old chain stops and the exact key and seat that
carries on. The new chain's third event (after SESSION_START and BOOT) is a
TRANSFER event carrying from_*, plus the assessor's signature. to_ws_id and to_pub
are not repeated in the event: they are the event's own ws_id and the signer of its
batch, so the signature only verifies for the machine it was issued to.

The assessor reads from_last_seq / from_head off the old machine's evidence or off
the witness, so a head the witness never held is exactly what a lazy or malicious
lab assistant cannot invent after the fact.
"""
from __future__ import annotations

from . import canon, hashing, keys
from .events import ID_RE, Event
from .findings import Code, Finding

_FIELDS = ("v", "exam_id", "session_id", "from_ws_id", "from_last_seq",
           "from_head", "to_ws_id", "to_pub")
TRANSFER_SEQ = 2


class TransferError(ValueError):
    pass


def _check_body(b: object) -> dict:
    if not isinstance(b, dict) or set(b) != set(_FIELDS) or b["v"] != 1:
        raise TransferError("transfer statement must have exactly the v1 fields")
    for k in ("exam_id", "session_id", "from_ws_id", "to_ws_id"):
        if not (isinstance(b[k], str) and ID_RE.match(b[k])):
            raise TransferError(f"bad {k}")
    n = b["from_last_seq"]
    if not (isinstance(n, int) and not isinstance(n, bool) and 0 <= n < 2**53):
        raise TransferError("bad from_last_seq")
    if not hashing.is_hash(b["from_head"]) or not hashing.is_hex(b["to_pub"], 64):
        raise TransferError("bad from_head or to_pub")
    if b["from_ws_id"] == b["to_ws_id"]:
        raise TransferError("a seat cannot be transferred to itself")
    return b


def issue(assessor: keys.Signer, *, exam_id: str, session_id: str, from_ws_id: str,
          from_last_seq: int, from_head: str, to_ws_id: str, to_pub: str) -> bytes:
    body = _check_body({"v": 1, "exam_id": exam_id, "session_id": session_id,
                        "from_ws_id": from_ws_id, "from_last_seq": from_last_seq,
                        "from_head": from_head, "to_ws_id": to_ws_id, "to_pub": to_pub})
    sig = assessor.sign(hashing.TRANSFER, canon.dumps(body))
    return canon.dumps({"body": body, "sig": sig})


def verify_token(raw: bytes, assessor_pub: str) -> tuple[dict, str]:
    """(statement, signature) if and only if the assessor signed it."""
    try:
        obj = canon.loads(raw, max_bytes=4096)
    except canon.CanonError as e:
        raise TransferError(f"transfer token unreadable: {e}") from None
    if not isinstance(obj, dict) or set(obj) != {"body", "sig"}:
        raise TransferError("transfer token must be {body, sig}")
    body = _check_body(obj["body"])
    if not keys.verify(hashing.TRANSFER, assessor_pub, canon.dumps(body), obj["sig"]):
        raise TransferError("assessor signature does not verify")
    return body, obj["sig"]


def statement_from_event(ev: Event, signer_pub: str) -> dict:
    d = ev.data
    return {"v": 1, "exam_id": ev.exam_id, "session_id": ev.session_id,
            "from_ws_id": d["from_ws_id"], "from_last_seq": d["from_last_seq"],
            "from_head": d["from_head"], "to_ws_id": ev.ws_id, "to_pub": signer_pub}


def check_event(ev: Event, signer_pub: str, assessor_pub: str) -> list[Finding]:
    """Is this TRANSFER event one the assessor really authorised for this exact seat and key?"""
    if ev.type != "TRANSFER":
        return [Finding(Code.TRANSFER_INVALID, ev.seq, "event is not a TRANSFER")]
    out = []
    if ev.seq != TRANSFER_SEQ:
        out.append(Finding(Code.TRANSFER_INVALID, ev.seq,
                           f"a transfer must be event {TRANSFER_SEQ} of the new chain"))
    try:
        stmt = _check_body(statement_from_event(ev, signer_pub))
    except TransferError as e:
        return out + [Finding(Code.TRANSFER_INVALID, ev.seq, str(e))]
    if not keys.verify(hashing.TRANSFER, assessor_pub, canon.dumps(stmt),
                       ev.data["assessor_sig"]):
        out.append(Finding(Code.TRANSFER_INVALID, ev.seq,
                           "assessor signature does not cover this seat and key"))
    return out
