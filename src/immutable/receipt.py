"""receipt.py (B10): the student's copy of the final head, and the check of it.

A receipt is not a new format. It is the `receipt` anchor of anchor.py, signed by
the key enrolled for the seat, wrapped as text so it can be printed, copied or scanned:

    IMR1.<base64url of the canonical anchor file>

A valid receipt shows: the key the assessor enrolled for seat X signed "my log ended
at event N with head H". It does NOT show the log is honest. Someone with
administrator rights on that machine can sign anything. So a receipt is a second
copy of the head, never the first, and A2 still needs an outside holder (verifier.py).
"""
from __future__ import annotations

import base64
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import anchor as anchor_mod
from .anchor import Anchor, AnchorError
from .clock import wall_ms
from .roster import Roster

PREFIX = "IMR1."
MAX_TOKEN_CHARS = 2048
_B64 = re.compile(r"^[A-Za-z0-9_-]+$")

LIMITS = ("A valid receipt shows that this seat's enrolled key signed these words. It does not "
          "show that the log is honest: anyone with administrator rights on the machine could "
          "sign anything. Check it against the evidence, and against an outside holder.")


class ReceiptError(ValueError):
    pass


# ------------------------------------------------------------------ make
def issue(signer, *, exam_id: str, session_id: str, ws_id: str, last_seq: int,
          head: str, seen_ms: int | None = None) -> bytes:
    return anchor_mod.make_receipt(
        signer, exam_id=exam_id, session_id=session_id, ws_id=ws_id, upto_seq=last_seq,
        head=head, seen_ms=wall_ms() if seen_ms is None else seen_ms)


def encode(raw: bytes) -> str:
    return PREFIX + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(token: str) -> bytes:
    """Tolerates spaces, line wraps and text before the token (the token must be last)."""
    t = "".join(token.split())
    i = t.find(PREFIX)
    if i < 0:
        raise ReceiptError("this is not an Immutable receipt (it should contain IMR1.)")
    t = t[i:]
    body = t[len(PREFIX):]
    if len(t) > MAX_TOKEN_CHARS or not _B64.match(body):
        raise ReceiptError("the receipt text is damaged or too long")
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except ValueError:
        raise ReceiptError("the receipt text is damaged") from None
    if encode(raw) != PREFIX + body:
        raise ReceiptError("the receipt text is damaged")
    return raw


def parse(token: str) -> Anchor:
    raw = decode(token)
    try:
        a = anchor_mod.parse(raw)
    except AnchorError as e:
        raise ReceiptError(f"the receipt is not well formed: {e}") from None
    if a.kind != "receipt":
        raise ReceiptError("this is an anchor, but not a student receipt")
    if raw != a.to_bytes():
        raise ReceiptError("the receipt is not in canonical form")
    return a


# ------------------------------------------------------------------ show
def groups(h: str, n: int = 4) -> str:
    return " ".join(h[i:i + n] for i in range(0, len(h), n))


def utc(ms: int) -> str:
    return time.strftime("%d %b %Y %H:%M:%S UTC", time.gmtime(ms // 1000))


def qr_svg(token: str) -> str | None:
    """Inline SVG, or None when the optional `segno` package is not installed."""
    try:
        import segno
    except ImportError:
        return None
    q = segno.make(token, error="l", micro=False, boost_error=False)
    return q.svg_inline(scale=4, border=3, dark="#16213A", light="#FFFFFF",
                        omitsize=True, title="Receipt QR code")


# ------------------------------------------------------------------ check
@dataclass(frozen=True)
class Check:
    code: str
    ok: bool
    text: str
    required: bool = True

    def to_dict(self) -> dict:
        return {"code": self.code, "ok": self.ok, "text": self.text, "required": self.required}


@dataclass(frozen=True)
class Result:
    checks: tuple[Check, ...]
    anchor: Anchor | None
    against_log: bool

    @property
    def valid(self) -> bool:
        return all(c.ok for c in self.checks if c.required)

    def to_dict(self) -> dict:
        a = self.anchor
        return {
            "valid": self.valid, "against_log": self.against_log, "limits": LIMITS,
            "checks": [c.to_dict() for c in self.checks],
            "receipt": None if a is None else {
                "receipt_id": a.id[:16], "exam_id": a.exam_id, "session_id": a.session_id,
                "ws_id": a.ws_id, "upto_seq": a.upto_seq, "head": a.head,
                "signed_at": utc(a.seen_ms)},
        }


_STATUS_TEXT = {
    "consistent": "The log holds exactly the event this receipt names.",
    "conflict": "The log holds a different event at that position. One of the two was rewritten.",
    "beyond-log": "The receipt names events that the supplied log does not contain.",
    "beyond-trunk": "The receipt names an event on a side branch, not on the main log.",
    "rollback": "The receipt names events that a restart later dropped from the log.",
}


def _report_holding(node: Any, anchor_id: str) -> dict | None:
    """Find the per-seat report that judged this anchor, wherever the case file nests it."""
    if isinstance(node, dict):
        lst = node.get("anchors")
        if (isinstance(lst, list) and "assurance" in node
                and any(isinstance(x, dict) and x.get("id") == anchor_id for x in lst)):
            return node
        node = list(node.values())
    if isinstance(node, list):
        for v in node:
            r = _report_holding(v, anchor_id)
            if r is not None:
                return r
    return None


def validate(token: str, roster: Roster, *, evidence: Iterable[str | Path] = ()) -> Result:
    checks: list[Check] = []

    def add(code: str, ok: bool, text: str, required: bool = True) -> bool:
        checks.append(Check(code, ok, text, required))
        return ok

    evidence = [Path(p) for p in evidence]
    try:
        a = parse(token)
    except ReceiptError as e:
        add("R_READABLE", False, str(e))
        return Result(tuple(checks), None, False)
    add("R_READABLE", True, "The receipt text is well formed.")

    add("R_EXAM", a.exam_id == roster.exam_id,
        f"The receipt is for this exam ({a.exam_id})." if a.exam_id == roster.exam_id
        else f"The receipt is for exam {a.exam_id}, not this exam ({roster.exam_id}).")
    seat = roster.seat(a.ws_id)
    add("R_SEAT", seat is not None,
        f"Seat {a.ws_id} is on the roster." if seat else
        f"Seat {a.ws_id} is not on the roster. (Seats made by a transfer are not supported by "
        "this standalone check yet.)")
    why = anchor_mod.authenticate(a, roster, seat.pub) if seat else "no key is enrolled for that seat"
    add("R_SIGNATURE", why is None,
        "The signature comes from the key the assessor enrolled for that seat." if why is None
        else f"The signature does not check out: {why}.")

    if evidence:
        _against_log(a, roster, evidence, add)
    return Result(tuple(checks), a, bool(evidence))


def _against_log(a: Anchor, roster: Roster, evidence: list[Path], add) -> None:
    from .clockcheck import ClockPolicy      # lazy: keeps agent -> receipt free of import cycles
    from .store import Store

    with tempfile.TemporaryDirectory(prefix="imr-", ignore_cleanup_errors=True) as tmp:
        store = Store(tmp, roster)
        for p in evidence:
            store.ingest_path(p)
        store.ingest_anchor(a.to_bytes())
        case = store.case(ClockPolicy())

    rep = _report_holding(case.body, a.id)
    if rep is None:
        add("R_ON_LOG", False, "The evidence has no log for this seat that can be compared with "
                               "the receipt (the receipt may have been rejected).")
        return
    st = next(x["status"] for x in rep["anchors"] if x["id"] == a.id)
    add("R_ON_LOG", st == "consistent", _STATUS_TEXT.get(st, f"The receipt was judged: {st}."))
    final = bool(rep.get("ended")) and rep.get("last_seq") == a.upto_seq
    add("R_FINAL", final, "The receipt names the final event of a session that closed normally."
        if final else "The receipt does not name the final event of a closed session.")
    add("R_VERDICT", rep.get("verdict") != "TAMPER_SUSPECTED",
        "The verifier found nothing in this session that needs human review."
        if rep.get("verdict") != "TAMPER_SUSPECTED"
        else "The verifier found something in this session that needs human review.", False)
    add("R_ASSURANCE", rep.get("assurance") == "A2",
        "An outside holder and this receipt both match the final log (A2)."
        if rep.get("assurance") == "A2"
        else f"Assurance is {rep.get('assurance')}, not A2: an outside holder is also needed.", False)


def standing(case_body: dict, a: Anchor) -> dict:
    """Calm, student-facing status taken from the real case file."""
    rep = _report_holding(case_body, a.id)
    if rep is None:
        return {"code": "UNKNOWN", "assurance": None, "witness_upto": None,
                "text": "Your receipt could not be matched to the records yet. Tell the invigilator."}
    wit = [x["upto_seq"] for x in rep["anchors"]
           if x["kind"] == "witness" and x["status"] == "consistent"]
    wu = max(wit, default=None)
    asr = rep["assurance"]
    if rep.get("verdict") == "TAMPER_SUSPECTED":
        code, text = "REVIEW", "The assessor will look at this session before the result is final."
    elif wu is None:
        code, text = "THIS_COMPUTER", ("Your work is signed, but nothing outside this computer holds a "
                                       "checkpoint of it yet. Tell the invigilator.")
    elif wu >= a.upto_seq:
        code, text = "HELD_BY_WITNESS", ("The lab witness held your work up to the final event. "
                                         "Your receipt matches it.")
    else:
        code, text = "PARTLY_HELD", (f"The lab witness held your work up to event {wu}. The last "
                                     f"{a.upto_seq - wu} events are held by this computer and your receipt.")
    return {"code": code, "assurance": asr, "witness_upto": wu, "text": text}
