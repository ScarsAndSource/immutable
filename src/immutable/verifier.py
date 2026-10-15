"""verifier.py (B5): one reconstructed chain in, one honest assessment out.

The assessment has three parts that are never merged into a single green tick:
  proven      statements that follow from signatures, hashes and outside holders
  suspicious  SUSPECT findings (impossibilities and protocol breaks)
  unprovable  what no log signed on a user-controlled machine can establish, always
              printed, even for a spotless session

Assurance (from docs/THREAT_MODEL.md)
  A0  self-consistent only. No outside party ever held a head.
  A1  an outside holder saw the log up to anchored_upto. Beyond it: unanchored tail.
  A2  A1 plus a student receipt matching the final head of a session that closed.

The word ANCHORED is only ever used for A1 or A2.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum

from . import clockcheck, rules, submission
from .anchor import Anchor
from .chain import Branch, Walk
from .clockcheck import ClockPolicy
from .findings import Code, Finding, Severity
from .roster import Roster


class Verdict(str, Enum):
    TAMPER_SUSPECTED = "TAMPER_SUSPECTED"
    NO_EVIDENCE = "NO_EVIDENCE"
    SELF_CONSISTENT_ONLY = "SELF_CONSISTENT_ONLY"
    ANCHORED = "ANCHORED"


_ORDER = {Verdict.TAMPER_SUSPECTED: 3, Verdict.NO_EVIDENCE: 2,
          Verdict.SELF_CONSISTENT_ONLY: 1, Verdict.ANCHORED: 0}
_RANK = {"A0": 0, "A1": 1, "A2": 2}


def utc(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@dataclass
class ChainReport:
    session_id: str
    ws_id: str
    signer: str
    candidate: str | None
    verdict: Verdict
    assurance: str
    trunk_len: int
    last_seq: int
    first_wall_ms: int | None
    last_wall_ms: int | None
    anchored_upto: int | None
    unanchored_events: int
    unanchored_seconds: int
    unlinked_events: int
    ended: bool
    submitted: bool
    anchors: list
    proven: list
    unprovable: list
    findings: list
    stats: dict

    def to_dict(self) -> dict:
        return {
            "ws_id": self.ws_id, "signer": self.signer, "candidate": self.candidate,
            "verdict": self.verdict.value, "assurance": self.assurance,
            "trunk_len": self.trunk_len, "last_seq": self.last_seq,
            "first_wall_ms": self.first_wall_ms, "last_wall_ms": self.last_wall_ms,
            "anchored_upto": self.anchored_upto,
            "unanchored_events": self.unanchored_events,
            "unanchored_seconds": self.unanchored_seconds,
            "unlinked_events": self.unlinked_events,
            "ended": self.ended, "submitted": self.submitted,
            "anchors": self.anchors, "proven": self.proven, "unprovable": self.unprovable,
            "findings": [x.to_dict() for x in sorted(self.findings, key=lambda x: x.sort_key)],
            "stats": self.stats,
        }


def _judge(a: Anchor, trunk, branch: Branch, recov, last: int):
    who = {"witness": f"Witness {a.holder}", "assessor": "The assessor's server",
           "receipt": "The student's receipt"}[a.kind]
    if a.upto_seq <= last:
        if trunk[a.upto_seq].hash() == a.head:
            return "consistent", None
        status = "conflict"
    else:
        cell = branch.by_seq.get(a.upto_seq)
        if cell and a.head in cell:
            return "beyond-trunk", None
        status = "beyond-log"
    rb = next((r for r in recov if r.data["last_good_seq"] < a.upto_seq), None)
    if rb is not None:
        return "rollback", Finding(
            Code.ROLLBACK, a.upto_seq,
            f"{who} saw events up to {a.upto_seq}, but after a restart at event {rb.seq} this log says it "
            f"ended at {rb.data['last_good_seq']}. History that an outside party saw is missing from this log.")
    if status == "conflict":
        return status, Finding(Code.ANCHOR_CONFLICT, a.upto_seq,
                               f"{who} holds a different event at position {a.upto_seq} than this log does. "
                               "One of the two histories was rewritten.")
    end = f"this log ends at {last}" if last >= 0 else "no log from this seat was provided"
    return status, Finding(Code.TRUNCATED, a.upto_seq,
                           f"{who} saw events up to {a.upto_seq}, but {end}. Events seen outside are missing.")


def assess_chain(*, roster: Roster, session_id: str, ws_id: str, signer: str,
                 candidate: str | None, branch: Branch, wk: Walk, extra: list[Finding],
                 anchors: list[Anchor], manifest: bytes | None, has_blob,
                 policy: ClockPolicy) -> ChainReport:
    trunk = wk.trunk
    last = trunk[-1].seq if trunk else -1
    F: list[Finding] = list(wk.findings) + list(extra)

    rf, rs = rules.check(trunk, roster)
    F += rf

    recov = [e for e in trunk if e.type == "RECOVERY"]
    judged, consistent = [], []
    for a in sorted(anchors, key=lambda x: (x.upto_seq, x.kind, x.holder, x.head)):
        status, fnd = _judge(a, trunk, branch, recov, last)
        judged.append({"id": a.id, "kind": a.kind, "holder": a.holder,
                       "upto_seq": a.upto_seq, "seen_ms": a.seen_ms, "status": status})
        if fnd:
            F.append(fnd)
        if status == "consistent":
            consistent.append(a)

    cf, ci = clockcheck.check(trunk, consistent, policy)
    F += cf

    submitted = any(e.type == "SUBMIT" for e in trunk)
    sub_stats = None
    if submitted:
        sev = next(e for e in trunk if e.type == "SUBMIT")
        if manifest is None:
            F.append(Finding(Code.MANIFEST_MISSING, sev.seq,
                             "a submission was recorded but its manifest was not provided, so the files were not checked"))
        else:
            sf, sub_stats = submission.check(manifest, sev, rs["saves_at_submit"] or {}, has_blob)
            F += sf

    F = [x if x.session else replace(x, session=session_id, ws=ws_id) for x in F]
    codes = {x.code for x in F}

    outside = [a for a in consistent if a.kind != "receipt"]
    anchored_upto = max((a.upto_seq for a in outside), default=None)
    ended = bool(trunk) and trunk[-1].type == "SESSION_END"
    receipt_ok = any(a.kind == "receipt" and a.upto_seq == last for a in consistent)
    assurance = "A0" if anchored_upto is None else ("A2" if receipt_ok and ended else "A1")

    if not trunk:
        un_events, un_secs = 0, 0
    elif anchored_upto is None:
        un_events = len(trunk)
        un_secs = max(0, trunk[-1].wall_ms - trunk[0].wall_ms) // 1000
    else:
        un_events = last - anchored_upto
        un_secs = max(0, trunk[-1].wall_ms - trunk[anchored_upto].wall_ms) // 1000

    if any(x.severity is Severity.SUSPECT for x in F):
        verdict = Verdict.TAMPER_SUSPECTED
    elif not trunk:
        verdict = Verdict.NO_EVIDENCE
    elif assurance == "A0":
        verdict = Verdict.SELF_CONSISTENT_ONLY
    else:
        verdict = Verdict.ANCHORED

    proven = []
    if trunk:
        proven.append({"code": "CHAIN_OK", "text": f"Events 0 to {last} form one unbroken hash chain signed by the key enrolled for seat {ws_id}."})
        if not codes & {Code.BAD_START, Code.ROSTER_MISMATCH, Code.PAPER_MISMATCH}:
            proven.append({"code": "PINNED", "text": "The session opened against the roster and exam paper issued for this exam."})
    if rs["checkpoints_ok"] and Code.CHECKPOINT_BAD not in codes:
        proven.append({"code": "CHECKPOINTS_OK", "text": f"{rs['checkpoints_ok']} Merkle checkpoints were recomputed and match."})
    best: dict[tuple, Anchor] = {}
    for a in consistent:
        k = (a.kind, a.holder)
        if k not in best or a.upto_seq > best[k].upto_seq:
            best[k] = a
    for k in sorted(best):
        a = best[k]
        if a.kind == "receipt":
            text = f"The student's receipt names events up to {a.upto_seq} and matches this log."
        else:
            who = f"Witness {a.holder}" if a.kind == "witness" else "The assessor's server"
            text = f"{who} saw events up to {a.upto_seq} at {utc(a.seen_ms)} by its own clock, and they match this log."
        proven.append({"code": f"ANCHOR_{a.kind.upper()}", "text": text})
    if sub_stats and sub_stats["checked"] and not codes & {Code.SUBMISSION_MISMATCH, Code.BLOB_MISSING}:
        proven.append({"code": "SUBMISSION_OK", "text": f"{sub_stats['files']} submitted files match what was recorded while working."})

    unprov = []
    if trunk and anchored_upto is None:
        unprov.append({"code": "NO_ANCHOR", "text": "No outside party ever held a checkpoint of this log. A user with administrator rights on the workstation could have written all of it after the fact."})
    elif trunk and un_events > 0:
        unprov.append({"code": "UNANCHORED_TAIL", "text": f"Nothing after event {anchored_upto} can be proven. {un_events} events, about {un_secs} seconds by the machine's own clock, are held only by this workstation."})
    if trunk and not ended:
        unprov.append({"code": "OPEN_SESSION", "text": f"The log does not end with a normal close. Whether anything happened after event {last} cannot be known."})
    if wk.beyond:
        unprov.append({"code": "UNLINKED_EVENTS", "text": f"{wk.beyond} events were received that cannot be linked into the chain. They are listed but not trusted."})
    unprov.append({"code": "TIME_CLAIMS", "text": "Wall-clock times are claims made by the workstation. Only an outside holder's clock bounds them, and only as an upper limit."})
    unprov.append({"code": "OUT_OF_SCOPE", "text": "This shows what the machine logged. It does not show who sat at it, or whether they had outside help."})

    return ChainReport(
        session_id, ws_id, signer, candidate, verdict, assurance, len(trunk), last,
        trunk[0].wall_ms if trunk else None, trunk[-1].wall_ms if trunk else None,
        anchored_upto, un_events, un_secs, wk.beyond, ended, submitted,
        judged, proven, unprov, F,
        {"events": rs["events"], "checkpoints_ok": rs["checkpoints_ok"],
         "clock": ci, "submission": sub_stats})


def assess_session(session_id: str, chains: list[ChainReport], findings: list[Finding],
                   ignored: list[Finding]) -> dict:
    sus = [x for x in findings if x.severity is Severity.SUSPECT]
    sus += [x for c in chains for x in c.findings if x.severity is Severity.SUSPECT]
    if sus:
        verdict = Verdict.TAMPER_SUSPECTED
    elif not chains or all(c.trunk_len == 0 for c in chains):
        verdict = Verdict.NO_EVIDENCE
    else:
        verdict = max((c.verdict for c in chains), key=lambda v: _ORDER[v])
    withs = [c.assurance for c in chains if c.trunk_len]
    assurance = min(withs, key=lambda a: _RANK[a]) if withs else "A0"
    notes = sum(1 for c in chains for x in c.findings if x.severity is Severity.NOTE)
    notes += sum(1 for x in findings if x.severity is Severity.NOTE)
    return {
        "session_id": session_id, "verdict": verdict.value, "assurance": assurance,
        "human_review_required": verdict is Verdict.TAMPER_SUSPECTED,
        "chains": [c.to_dict() for c in sorted(chains, key=lambda c: (c.ws_id, c.signer))],
        "findings": [x.to_dict() for x in sorted(findings, key=lambda x: x.sort_key)],
        "ignored": [x.to_dict() for x in sorted(ignored, key=lambda x: x.sort_key)],
        "counts": {"suspect": len(sus), "note": notes},
    }
