"""reconcile.py (B6): any pile of files in, one deterministic case file out.

reconcile() is a pure function of the SET of inputs. Arrival order, duplicates and
re-imports cannot change a single byte of the result, because:
  * inputs are deduplicated by content id, then processed in sorted order
  * chains are rebuilt from a seq -> {hash -> event} map, never from arrival order
  * every list in the output is explicitly sorted; there are no timestamps from `now`
    and no set or dict iteration order leaks into the body
tools/shuffle_check.py hammers exactly this property.

Who is believed
  A chain is PRIMARY if its signing key is the one bound to its seat (roster, or an
  authentic assessor transfer). Only primary chains can move a verdict. Anything else
  signed for the same seat is IGNORED (listed, never counted), so a stranger cannot
  frame a student by injecting files. If a session has no primary chain at all, the
  foreign chains become findings, because then they are all the evidence there is.

Verdict inputs are per session. A session with an outside holder but no log at all is
TAMPER_SUSPECTED (TRUNCATED): deleting everything does not erase the witness.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from . import anchor as anchor_mod
from . import canon, hashing, keys, submission, verifier
from .batch import verify_batch
from .binding import Observed, resolve
from .chain import Branch, walk
from .clockcheck import ClockPolicy
from .findings import Code, Finding
from .roster import Roster

SPEC_VERSION = 1
VERIFIER_VERSION = "im-verify/0.1"


@dataclass
class Case:
    body: dict

    @property
    def hash(self) -> str:
        return hashing.sha256_hex(canon.dumps(self.body))

    def to_bytes(self) -> bytes:
        return canon.dumps({"body": self.body, "hash": self.hash})


def _kid(pub: str) -> str:
    return keys.key_id(pub)[:12]


def reconcile(batches: Iterable[bytes], roster: Roster, *,
              anchors: Iterable[bytes] = (), manifests: Iterable[bytes] = (),
              has_blob: Callable[[str], bool] | None = None,
              policy: ClockPolicy = ClockPolicy(),
              prior_rejects: Iterable[dict] = ()) -> Case:
    rejected: dict[str, dict] = {}

    def reject(rid: str, code: Code, detail: str) -> None:
        rejected.setdefault(rid, {"id": rid, "code": code.value, "detail": detail})

    for r in prior_rejects:
        rejected.setdefault(r["id"], {"id": r["id"], "code": r["code"], "detail": r["detail"]})

    # ---- 1. intake: parse and verify every batch on its own
    clean: dict[str, object] = {}
    defective: dict[str, tuple] = {}
    for raw in batches:
        b, fs = verify_batch(raw)
        if b is None:
            reject(hashing.sha256_hex(raw), Code.MALFORMED, fs[0].detail)
            continue
        bid = hashing.sha256_hex(b.to_bytes())
        if b.header["exam_id"] != roster.exam_id:
            reject(bid, Code.WRONG_EXAM, "batch is for a different exam")
        elif any(f.code is Code.BAD_SIGNATURE for f in fs):
            reject(bid, Code.BAD_SIGNATURE, "batch signature does not verify")
        elif fs:
            defective[bid] = (b, fs)
        else:
            clean[bid] = b

    # ---- 2. branches: everything one key said about one (session, seat)
    branches: dict[tuple, Branch] = {}
    for bid, b in sorted(clean.items()):
        h = b.header
        br = branches.setdefault((h["session_id"], h["ws_id"], h["signer"]),
                                 Branch(h["session_id"], h["ws_id"], h["signer"]))
        br.batch_ids.add(bid)
        for ev in b.events:
            br.add(ev)
    defect_by_key: dict[tuple, list[Finding]] = defaultdict(list)
    for bid, (b, fs) in sorted(defective.items()):
        h = b.header
        k = (h["session_id"], h["ws_id"], h["signer"])
        branches.setdefault(k, Branch(*k))
        codes = ", ".join(sorted({f.code.value for f in fs}))
        defect_by_key[k].append(Finding(
            Code.BATCH_DEFECT, h["first_seq"],
            f"batch {bid[:8]} (events {h['first_seq']} to {h['last_seq']}) is signed but internally "
            f"inconsistent ({codes}) and was not used"))
    walks = {k: walk(br) for k, br in sorted(branches.items())}

    # ---- 3. identity
    observed = []
    for k, br in sorted(branches.items()):
        wk = walks[k]
        tr = next((e for s in sorted(br.by_seq) for _, e in sorted(br.by_seq[s].items())
                   if e.type == "TRANSFER"), None)
        observed.append(Observed(k[0], k[1], k[2], br.max_seq,
                                 {e.seq: e.hash() for e in wk.trunk}, tr))
    bindings, bfind = resolve(roster, observed)

    def is_primary(ws: str, signer: str) -> bool:
        b = bindings.get(ws)
        return b is not None and b.pub == signer

    key_ws: dict[str, set] = defaultdict(set)
    for s in roster.seats:
        key_ws[s.pub].add(s.ws_id)
    for (_, ws, signer) in branches:
        key_ws[signer].add(ws)
    dups = {p: sorted(w) for p, w in key_ws.items() if len(w) > 1}

    def dup_finding(signer: str, sid: str, ws: str) -> Finding:
        return Finding(Code.DUPLICATE_KEY, None,
                       f"key {_kid(signer)} is used on seats {', '.join(dups[signer])}", sid, ws)

    # ---- 4. anchors and manifests
    accepted: dict[str, anchor_mod.Anchor] = {}
    for raw in anchors:
        try:
            a = anchor_mod.parse(raw)
        except anchor_mod.AnchorError as e:
            reject(hashing.sha256_hex(raw), Code.ANCHOR_INVALID, str(e))
            continue
        if a.exam_id != roster.exam_id:
            reject(a.id, Code.WRONG_EXAM, "anchor is for a different exam")
        elif a.ws_id not in bindings:
            reject(a.id, Code.ANCHOR_INVALID, "anchor names a seat that is not on the roster")
        else:
            why = anchor_mod.authenticate(a, roster, bindings[a.ws_id].pub)
            if why:
                reject(a.id, Code.ANCHOR_INVALID, why)
            else:
                accepted[a.id] = a
    anchors_by: dict[tuple, list] = defaultdict(list)
    for aid in sorted(accepted):
        a = accepted[aid]
        anchors_by[(a.session_id, a.ws_id)].append(a)

    mf_by: dict[tuple, dict[str, bytes]] = defaultdict(dict)
    for raw in manifests:
        mid = hashing.sha256_hex(raw)
        try:
            m = submission.parse_manifest(raw)
        except submission.SubmissionError as e:
            reject(mid, Code.MALFORMED, f"manifest: {e}")
            continue
        if m["exam_id"] != roster.exam_id:
            reject(mid, Code.WRONG_EXAM, "manifest is for a different exam")
        else:
            mf_by[(m["session_id"], m["ws_id"])][mid] = raw

    # ---- 5. per session
    sessions = sorted({k[0] for k in branches} | {a.session_id for a in accepted.values()})
    session_dicts = []
    for sid in sessions:
        keys_here = sorted(k for k in branches if k[0] == sid)
        prim = [k for k in keys_here if is_primary(k[1], k[2])]
        prim_ws = {k[1] for k in prim}
        specs = [(k, branches[k], walks[k]) for k in prim]
        for ws in sorted({a.ws_id for a in accepted.values() if a.session_id == sid} - prim_ws):
            k = (sid, ws, bindings[ws].pub)
            br = Branch(*k)
            specs.append((k, br, walk(br)))
        specs.sort(key=lambda t: (t[0][1], t[0][2]))

        reports = []
        for k, br, wk in specs:
            ws, signer = k[1], k[2]
            extra = [f for o, f in bfind if (o.session_id, o.ws_id, o.signer) == k]
            extra += defect_by_key.get(k, [])
            if signer in dups:
                extra.append(dup_finding(signer, sid, ws))
            mfs = sorted(mf_by.get((sid, ws), {}).items())
            if len(mfs) > 1:
                extra.append(Finding(Code.SUBMISSION_MISMATCH, None,
                                     f"{len(mfs)} different manifests were provided for this seat"))
            reports.append(verifier.assess_chain(
                roster=roster, session_id=sid, ws_id=ws, signer=signer,
                candidate=bindings[ws].candidate, branch=br, wk=wk, extra=extra,
                anchors=anchors_by.get((sid, ws), []),
                manifest=mfs[0][1] if mfs else None, has_blob=has_blob, policy=policy))

        sess_f: list[Finding] = []
        ignored: list[Finding] = []
        for k in [x for x in keys_here if x not in prim]:
            ws, signer = k[1], k[2]
            n = branches[k].total
            if ws in bindings:
                code = Code.KEY_NOT_ENROLLED
                detail = f"seat {ws} was signed by key {_kid(signer)}, not its enrolled key; {n} events ignored"
            else:
                code = Code.UNKNOWN_SEAT
                detail = f"seat {ws} is not on the roster or in any valid transfer; {n} events ignored"
            related = [f for o, f in bfind if (o.session_id, o.ws_id, o.signer) == k]
            related += defect_by_key.get(k, [])
            if signer in dups:
                related.append(dup_finding(signer, sid, ws))
            if reports:
                ignored.append(Finding(Code.FOREIGN_BATCH, None, detail, sid, ws))
                ignored += related
            else:
                sess_f.append(Finding(code, None, detail, sid, ws))
                sess_f += related
        session_dicts.append(verifier.assess_session(sid, reports, sess_f, ignored))

    verdicts = [s["verdict"] for s in session_dicts]
    summary = {"sessions": len(session_dicts)}
    for v in verifier.Verdict:
        summary[v.value.lower()] = verdicts.count(v.value)

    body = {
        "spec": SPEC_VERSION, "verifier": VERIFIER_VERSION,
        "exam_id": roster.exam_id, "roster_id": roster.id, "assessor": roster.assessor,
        "clock_policy": policy.to_dict(),
        "inputs": {"batches": sorted(list(clean) + list(defective)),
                   "anchors": sorted(accepted),
                   "manifests": sorted({m for d in mf_by.values() for m in d})},
        "rejected": sorted(rejected.values(), key=lambda r: r["id"]),
        "sessions": session_dicts,
        "summary": summary,
    }
    return Case(body)
