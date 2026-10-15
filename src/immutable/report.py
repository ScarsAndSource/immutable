"""report.py: the case note. Calm, plain, and never accusing.

Every session shows what is proven, what is suspicious and what cannot be proven.
The last section is printed even for a spotless session. That is the point.
"""
from __future__ import annotations

from .findings import Code, MEANING
from .reconcile import Case
from .verifier import utc

_VERDICT = {
    "TAMPER_SUSPECTED": "Evidence inconsistent. A human should review this. This is not a finding of misconduct.",
    "ANCHORED": "No inconsistency found. An outside holder confirms the log up to the point shown below.",
    "SELF_CONSISTENT_ONLY": "No inconsistency found, but no outside party ever held a checkpoint. This proves little against a user with administrator rights.",
    "NO_EVIDENCE": "No usable events were received for this session.",
}


def g4(h: str) -> str:
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def _line(f: dict) -> str:
    where = f"event {f['seq']}: " if f["seq"] is not None else ""
    seat = f" (seat {f['ws']})" if f["ws"] else ""
    return f"  [{f['code']}] {where}{f['detail']}{seat}"


def render(case: Case) -> str:
    b = case.body
    s = b["summary"]
    L = [f"EVIDENCE REPORT   exam {b['exam_id']}",
         f"case hash   {g4(case.hash[:32])}",
         f"roster      {g4(b['roster_id'][:32])}",
         f"verifier    {b['verifier']}  spec {b['spec']}", "",
         f"{s['sessions']} session(s): {s['tamper_suspected']} need human review, {s['anchored']} anchored, "
         f"{s['self_consistent_only']} self-consistent only, {s['no_evidence']} without evidence."]

    for ses in b["sessions"]:
        L += ["", "=" * 72, f"SESSION {ses['session_id']}   {ses['verdict']}   assurance {ses['assurance']}",
              _VERDICT[ses["verdict"]], ""]
        codes: set[str] = set()
        suspicious = [dict(f) for f in ses["findings"] if f["severity"] == "suspect"]
        notes = [dict(f) for f in ses["findings"] if f["severity"] == "note"]
        proven, unprov = [], []
        for c in ses["chains"]:
            head = f"seat {c['ws_id']}" + (f", candidate {c['candidate']}" if c["candidate"] else "")
            L.append(f"{head}: {c['trunk_len']} events"
                     + (f", anchored up to {c['anchored_upto']}" if c["anchored_upto"] is not None else ", not anchored")
                     + (f", from {utc(c['first_wall_ms'])} to {utc(c['last_wall_ms'])} by the machine's clock"
                        if c["first_wall_ms"] is not None else ""))
            cv = c["stats"].get("coverage") or {}
            if cv.get("anchors"):
                L.append(f"    coverage: {cv['pinned_events']} of {cv['total_events']} events pinned by "
                         f"{', '.join(cv['holders'])} ({cv['anchors']} anchors); longest stretch held only by the "
                         f"workstation: {cv['max_unprotected_ms'] // 1000} s by its own clock; longest gap between "
                         f"outside checks: {cv['max_anchor_gap_ms'] // 1000} s")
            suspicious += [f for f in c["findings"] if f["severity"] == "suspect"]
            notes += [f for f in c["findings"] if f["severity"] == "note"]
            proven += [f"seat {c['ws_id']}: {p['text']}" for p in c["proven"]]
            unprov += [f"seat {c['ws_id']}: {p['text']}" for p in c["unprovable"]]

        L += ["", "WHAT IS PROVEN"] + ([f"  + {p}" for p in proven] or ["  (nothing)"])
        L += ["", "WHAT IS SUSPICIOUS"]
        L += [_line(f) for f in sorted(suspicious, key=lambda f: (f["ws"] or "", f["seq"] if f["seq"] is not None else -1, f["code"]))] \
            or ["  (nothing)"]
        L += ["", "WHAT CANNOT BE PROVEN"] + [f"  ? {u}" for u in unprov]
        if notes:
            L += ["", "NOTES"] + [_line(f) for f in sorted(notes, key=lambda f: (f["ws"] or "", f["seq"] if f["seq"] is not None else -1, f["code"]))]
        if ses["ignored"]:
            L += ["", "IGNORED INPUT (not counted toward the verdict)"] + [_line(f) for f in ses["ignored"]]
        codes = {f["code"] for f in suspicious + notes + ses["ignored"]}
        if codes:
            L += ["", "READING GUIDE"]
            for c in sorted(codes):
                m = MEANING.get(Code(c))
                if m:
                    L += [f"  {c}: {m[0]}", f"      Next: {m[1]}"]

    if b["rejected"]:
        L += ["", "=" * 72, "INPUT THAT WAS NOT USED"]
        L += [f"  [{r['code']}] {r['id'][:12]}  {r['detail']}" for r in b["rejected"]]
    return "\n".join(L) + "\n"
