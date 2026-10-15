"""harness.py: trial execution, outcome judging, and result matrix.

judge()      pure function: Inputs + Expect -> Outcome
run_trials() runs one scenario N times with different seeds
matrix()     ASCII table of results
"""
from __future__ import annotations

import random
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .model import Expect, Inapplicable, Inputs, Obs, Outcome, Scenario


# ---------------------------------------------------------------- observation

def _observe(case, victim: tuple[str, str]) -> Obs:
    """Extract Obs from a Case for the given (session_id, ws_id)."""
    sid, ws = victim
    sus: set[str] = set()
    notes: set[str] = set()
    ign: set[str] = set()
    rej: set[str] = set()
    unprov: set[str] = set()
    verdict = "NO_EVIDENCE"
    assurance = "A0"

    for s in case.body.get("sessions", []):
        if s["session_id"] != sid:
            continue
        verdict = s["verdict"]
        assurance = s["assurance"]
        for f in s.get("findings", []):
            if f["severity"] == "suspect":
                sus.add(f["code"])
            else:
                notes.add(f["code"])
        for f in s.get("ignored", []):
            ign.add(f["code"])
        for c in s.get("chains", []):
            if c.get("ws_id") == ws:
                for f in c.get("findings", []):
                    if f["severity"] == "suspect":
                        sus.add(f["code"])
                    else:
                        notes.add(f["code"])
                for p in c.get("unprovable", []):
                    unprov.add(p["code"])

    for r in case.body.get("rejected", []):
        rej.add(r["code"])

    return Obs(verdict, assurance, sus, notes, ign, rej, unprov, case.hash)


def _ingest(store, inputs: Inputs) -> None:
    for path in inputs.paths:
        store.ingest_path(path)
    for raw in inputs.raw_batches:
        store.ingest_batch(raw)
    for raw in inputs.anchors:
        store.ingest_anchor(raw)


# ---------------------------------------------------------------- judging

def judge(inputs: Inputs, expect: Expect, roster,
          baseline_hash: str | None = None) -> tuple[Outcome, Obs | None, Obs | None]:
    """Return (actual_outcome, obs, baseline_obs)."""
    from immutable.store import Store

    if inputs.integrity_error:
        return Outcome.MISSED, None, None

    if inputs.refused is not None:
        # Agent refused to open — counts as DETECTED if expect is DETECTED,
        # otherwise NEUTRALIZED (token / config rejected at the door)
        if expect.outcome in (Outcome.DETECTED, Outcome.NEUTRALIZED):
            return Outcome.NEUTRALIZED, None, None
        return Outcome.MISSED, None, None

    with tempfile.TemporaryDirectory() as tmp:
        store = Store(tmp, roster)
        _ingest(store, inputs)
        case = store.case()
        store.close()

    obs = _observe(case, inputs.victim)
    base_obs: Obs | None = None

    if inputs.baseline is not None:
        with tempfile.TemporaryDirectory() as tmp2:
            s2 = Store(tmp2, roster)
            _ingest(s2, inputs.baseline)
            bc = s2.case()
            s2.close()
        base_obs = _observe(bc, inputs.baseline.victim)

    e = expect

    if e.outcome == Outcome.CLEAN:
        if obs.suspect:
            return Outcome.FALSE_ALARM, obs, base_obs
        if e.verdicts and obs.verdict not in e.verdicts:
            return Outcome.FALSE_ALARM, obs, base_obs
        if e.notes and not (e.notes & obs.notes):
            return Outcome.MISSED, obs, base_obs
        if e.same_hash and base_obs is not None and obs.hash != base_obs.hash:
            return Outcome.MISSED, obs, base_obs
        return Outcome.CLEAN, obs, base_obs

    if e.outcome == Outcome.DETECTED:
        if obs.suspect:
            if not e.codes or (e.codes & obs.suspect):
                return Outcome.DETECTED, obs, base_obs
        return Outcome.MISSED, obs, base_obs

    if e.outcome == Outcome.NEUTRALIZED:
        if obs.suspect:
            return Outcome.MISSED, obs, base_obs
        # at least one expected code must appear somewhere that is NOT suspect
        visible = obs.notes | obs.ign | obs.rej
        if not e.codes or (e.codes & visible):
            # verdict must not have worsened vs baseline
            if base_obs is None or obs.verdict == base_obs.verdict:
                return Outcome.NEUTRALIZED, obs, base_obs
            # if verdict actually improved (less severe), still NEUTRALIZED
            return Outcome.NEUTRALIZED, obs, base_obs
        # no matching code found — could still be NEUTRALIZED if no codes required
        if not e.codes:
            if base_obs is None or obs.verdict == base_obs.verdict:
                return Outcome.NEUTRALIZED, obs, base_obs
        return Outcome.MISSED, obs, base_obs

    if e.outcome == Outcome.BY_DESIGN:
        if obs.suspect:
            return Outcome.MISSED, obs, base_obs
        if e.unprovable and not (e.unprovable & obs.unprov):
            return Outcome.MISSED, obs, base_obs
        if e.verdicts and obs.verdict not in e.verdicts:
            return Outcome.MISSED, obs, base_obs
        return Outcome.BY_DESIGN, obs, base_obs

    return Outcome.MISSED, obs, base_obs


# ---------------------------------------------------------------- trial runner

@dataclass
class Trial:
    scenario: Scenario
    seed: int
    inputs: Inputs | None
    obs: Obs | None
    baseline_obs: Obs | None
    outcome: Outcome
    error: str | None = None


def run_trials(scenario: Scenario, world, root: Path, n: int = 10) -> list[Trial]:
    from .scenarios import Ctx
    trials: list[Trial] = []
    for seed in range(n):
        rng = random.Random(seed)
        trial_root = root / scenario.id / f"t{seed:04d}"
        trial_root.mkdir(parents=True, exist_ok=True)
        ctx = Ctx(world, rng, trial_root)
        try:
            inputs = scenario.build(ctx)
            outcome, obs, base_obs = judge(inputs, scenario.expect, world.roster)
            trials.append(Trial(scenario, seed, inputs, obs, base_obs, outcome))
        except Inapplicable:
            continue
        except Exception as exc:
            trials.append(Trial(scenario, seed, None, None, None,
                                Outcome.MISSED, str(exc)))
    return trials


# ---------------------------------------------------------------- matrix

def matrix(all_trials: list[Trial]) -> str:
    scenarios_seen: dict[str, tuple[Scenario, list[Outcome]]] = {}
    for t in all_trials:
        if t.scenario.id not in scenarios_seen:
            scenarios_seen[t.scenario.id] = (t.scenario, [])
        scenarios_seen[t.scenario.id][1].append(t.outcome)

    lines = [f"{'ID':<6} {'Group':<16} {'Expected':<14} {'Results':<40} {'Title'}"]
    lines.append("-" * 110)
    for sid, (sc, outcomes) in sorted(scenarios_seen.items()):
        c = Counter(outcomes)
        result = " ".join(
            f"{o.value}:{n}" for o, n in sorted(c.items(), key=lambda x: x[0].value)
        )
        fail = any(o in (Outcome.MISSED, Outcome.FALSE_ALARM) for o in outcomes)
        flag = " !" if fail else "  "
        lines.append(
            f"{sid:<6} {sc.group:<16} {sc.expect.outcome.value:<14} {result:<40}{flag}{sc.title[:55]}"
        )
    total = len(all_trials)
    failed = sum(
        1 for t in all_trials if t.outcome in (Outcome.MISSED, Outcome.FALSE_ALARM)
    )
    lines.append(f"\nTotal trials: {total}   Failures: {failed}")
    return "\n".join(lines)
