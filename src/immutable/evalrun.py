"""evalrun.py (B8): the false-alarm experiment, end to end.

M honest sessions, each with benign faults injected by a mechanism that mirrors reality
(see faults.py), run through the REAL agent, WAL, courier, witness and reconcile().
The number that matters is TAMPER_SUSPECTED on a session where nobody did anything wrong.
Reported with a Clopper-Pearson 95% upper bound, never as a bare "0%".

Every session is also reconciled with the anchors removed, to show that the witness
neither creates nor hides accusations on honest data.

A second, separate experiment (lying_disk=True) models storage that acknowledges fsync
and loses data. It is NOT benign: the witness saw history the machine later lost, so
ROLLBACK / TRUNCATED / FORK are the CORRECT answer. Its flag rate is reported next to the
headline, never inside it.

Everything here is SIMULATED and labelled so. `real` results (tools/evaluate.py real) are
merged in as a separate row.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from .clockcheck import ClockPolicy
from .reconcile import SPEC_VERSION, VERIFIER_VERSION
from .simlab import reconcile_lab, simulate_lab
from .stats import percentile, upper_bound


def run(*, labs: int, seats: int, seed: int, profile: str, duration_s: int,
        policy: ClockPolicy = ClockPolicy(), anchors_variant: bool = True,
        lying_disk: bool = False, progress=None) -> dict:
    n = suspects = suspects_a0 = 0
    verdicts, assurance, notes = Counter(), Counter(), Counter()
    per_fault = defaultdict(lambda: {"sessions": 0, "flagged": 0})
    flagged, unprot, tails, pinned_ratio, gaps = [], [], [], [], []
    for i in range(labs):
        lab = simulate_lab(seed + i, n_seats=seats, profile=profile, duration_s=duration_s,
                           lying_disk=lying_disk)
        case = reconcile_lab(lab, policy=policy)
        bad0 = set()
        if anchors_variant:
            c0 = reconcile_lab(lab, with_anchors=False, policy=policy)
            bad0 = {s["session_id"] for s in c0.body["sessions"] if s["verdict"] == "TAMPER_SUSPECTED"}
        for ses in case.body["sessions"]:
            sid = ses["session_id"]
            info = lab.stations.get(sid, {"faults": [], "ws": []})
            bad = ses["verdict"] == "TAMPER_SUSPECTED"
            n += 1
            suspects += bad
            suspects_a0 += sid in bad0
            verdicts[ses["verdict"]] += 1
            assurance[ses["assurance"]] += 1
            for k in (info["faults"] or ["none"]):
                per_fault[k]["sessions"] += 1
                per_fault[k]["flagged"] += bad
            codes = {f["code"] for f in ses["findings"] if f["severity"] == "note"}
            for c in ses["chains"]:
                codes |= {f["code"] for f in c["findings"] if f["severity"] == "note"}
                cov = c["stats"]["coverage"]
                if cov["anchors"]:
                    unprot.append(cov["max_unprotected_ms"] / 1000)
                    gaps.append(cov["max_anchor_gap_ms"] / 1000)
                    pinned_ratio.append(cov["pinned_events"] / max(1, cov["total_events"]))
                tails.append(c["unanchored_seconds"])
            for c in codes:
                notes[c] += 1
            if bad and len(flagged) < 20:
                sus = [f"{f['code']} (seat {f['ws']}, seq {f['seq']}): {f['detail']}"
                       for f in ses["findings"] if f["severity"] == "suspect"]
                for c in ses["chains"]:
                    sus += [f"{f['code']} (seat {c['ws_id']}, seq {f['seq']}): {f['detail']}"
                            for f in c["findings"] if f["severity"] == "suspect"]
                flagged.append({"lab_seed": lab.seed, "session": sid, "faults": info["faults"],
                                "findings": sus[:6]})
        if progress:
            progress(i + 1, labs)
    q = lambda xs, p: round(percentile(xs, p), 1)
    return {
        "label": "SIMULATED",
        "params": {"labs": labs, "seats": seats, "seed": seed, "profile": profile,
                   "duration_s": duration_s, "lying_disk": lying_disk,
                   "policy": policy.to_dict(), "verifier": VERIFIER_VERSION, "spec": SPEC_VERSION},
        "sessions": n, "suspect": suspects, "suspect_without_anchors": suspects_a0,
        "upper_95": upper_bound(suspects, n), "upper_95_without_anchors": upper_bound(suspects_a0, n),
        "verdicts": dict(sorted(verdicts.items())), "assurance": dict(sorted(assurance.items())),
        "per_fault": {k: per_fault[k] for k in sorted(per_fault)},
        "notes": dict(sorted(notes.items())),
        "coverage": {"pinned_ratio_p50": round(percentile(pinned_ratio, .5), 4),
                     "pinned_ratio_p05": round(percentile(pinned_ratio, .05), 4),
                     "unprotected_s_p50": q(unprot, .5), "unprotected_s_p95": q(unprot, .95),
                     "unprotected_s_max": q(unprot, 1.0), "anchor_gap_s_p95": q(gaps, .95),
                     "unanchored_tail_s_p95": q(tails, .95), "unanchored_tail_s_max": q(tails, 1.0)},
        "flagged": flagged,
    }


def render_markdown(r: dict, lying: dict | None = None, real: dict | None = None) -> str:
    p, n, k = r["params"], r["sessions"], r["suspect"]
    L = [f"# False-alarm evaluation ({r['label']})", "",
         f"{n} honest sessions from {p['labs']} simulated labs of {p['seats']} stations, "
         f"profile `{p['profile']}`, {p['duration_s']} s exams, seed {p['seed']}. "
         f"Verifier {p['verifier']}, spec {p['spec']}. Clock policy {p['policy']}.", "",
         "## Headline", "",
         f"- TAMPER_SUSPECTED on honest sessions: **{k} of {n}**.",
         f"- With 95% confidence the true false-alarm rate on this simulated population is below "
         f"**{100 * r['upper_95']:.2f}%**.",
         f"- Same data reconciled with anchors removed: {r['suspect_without_anchors']} of {n} flagged "
         f"(bound {100 * r['upper_95_without_anchors']:.2f}%).", ""]
    if real:
        L += [f"- Real machines (separate row, not mixed in): {real['suspect']} of {real['sessions']} flagged.", ""]
    L += ["## Outcomes", "", "| verdict | sessions |", "|---|---|"]
    L += [f"| {v} | {c} |" for v, c in r["verdicts"].items()]
    L += ["", "| assurance | sessions |", "|---|---|"] + [f"| {a} | {c} |" for a, c in r["assurance"].items()]
    L += ["", "## By injected fault (a session counts once per fault it had)", "",
          "| fault | sessions | flagged |", "|---|---|---|"]
    L += [f"| {k} | {v['sessions']} | {v['flagged']} |" for k, v in r["per_fault"].items()]
    L += ["", "## Notes raised (informational, cannot move a verdict)", "",
          "| code | sessions |", "|---|---|"] + [f"| {c} | {v} |" for c, v in r["notes"].items()]
    c = r["coverage"]
    L += ["", "## Anchored-prefix coverage", "",
          f"- Share of each log pinned by the witness: median {100 * c['pinned_ratio_p50']:.1f}%, "
          f"5th percentile {100 * c['pinned_ratio_p05']:.1f}%.",
          f"- Longest stretch of work held only by the workstation, by its own clock: median "
          f"{c['unprotected_s_p50']} s, 95th percentile {c['unprotected_s_p95']} s, worst {c['unprotected_s_max']} s.",
          f"- Longest gap between outside checks (outside clock): 95th percentile {c['anchor_gap_s_p95']} s.",
          f"- Unanchored tail at the end of the session: 95th percentile {c['unanchored_tail_s_p95']} s, "
          f"worst {c['unanchored_tail_s_max']} s.", ""]
    if r["flagged"]:
        L += ["## Flagged honest sessions (these are bugs or findings to explain)", ""]
        for f in r["flagged"]:
            L += [f"- lab seed {f['lab_seed']}, {f['session']}, faults {f['faults']}"] + \
                 [f"    - {x}" for x in f["findings"]]
        L.append("")
    if lying:
        L += ["## Hardware that lies about fsync (NOT benign, reported separately)", "",
              f"{lying['suspect']} of {lying['sessions']} sessions flagged. This is the correct outcome: "
              "the witness held events the machine later lost, and the verifier says so. Software cannot "
              "prevent this loss; it can only make it visible.", ""]
    L += ["## Limits", "",
          "- Simulated faults mirror mechanisms I know, not every fault reality has. Torn sectors in the "
          "middle of the log are not modelled (recovery refuses and a human decides).",
          "- Sessions inside one lab are independent by construction; real labs share power and network.",
          "- Run `tools/evaluate.py real` on a batch of genuine clean sessions before quoting a real-world rate.",
          "- The generator and seeds are in the repository; every number here reproduces exactly.", ""]
    return "\n".join(L)
