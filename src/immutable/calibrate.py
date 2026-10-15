"""calibrate.py (B8): choose the clock thresholds from curves, and say what they miss.

Two populations, one verdict-free question each:
  NOISE      sessions with restarts and crashes but no clock fault: how often does a
             threshold raise a note on an honest quiet session?
  DETECTION  sessions with one injected wall step of known size (or a sustained rate
             error): how often does the threshold notice it?
Clock findings are NOTES, so thresholds never create accusations; they decide how
loudly a human is told to read times with care.

THE FLOOR. A simulation cannot know real-world clock jitter, so calibration may only
RAISE thresholds above a conservative floor (step 1000 ms, drift 1000 ppm; Linux adjtime
slews at most 500 ppm). Lower the floor only after measuring real machines.

THE BOUND. Wall-clock error that stays under both thresholds is invisible. Over a boot
of length D seconds that is at most step_ms/1000 + drift_ppm*1e-6*D seconds. That number
goes in the report: "time is uncertain by X", not "time is verified".
"""
from __future__ import annotations

import math
from dataclasses import asdict

from . import clockcheck
from .clockcheck import ClockPolicy
from .findings import Code
from .simlab import simulate_lab, trunks

STEP_GRID_MS = (100, 250, 500, 1000, 2000, 5000, 10000, 30000)
DRIFT_GRID_PPM = (250, 500, 1000, 2000, 5000, 10000, 20000)
STEP_SIZES_MS = (250, 1000, 5000, 30000, 300000)
DRIFT_RATES_PPM = (1000, 5000, 20000, 100000)
FLOOR_STEP_MS = 1000
FLOOR_DRIFT_PPM = 1000


def _sample(profile: str, per_cell: int, seats: int, seed: int, duration_s: int, baseline_ppm: int) -> list:
    out = []
    for i in range(math.ceil(per_cell / seats)):
        lab = simulate_lab(seed + i, n_seats=seats, profile=profile, duration_s=duration_s,
                           witness_on=False, baseline_ppm=baseline_ppm)
        out += list(trunks(lab).values())
    return out


def _frac(traces: list, policy: ClockPolicy, *codes) -> float:
    hit = 0
    for tr in traces:
        f, _ = clockcheck.check(tr, [], policy)
        hit += any(x.code in codes for x in f)
    return hit / len(traces) if traces else 0.0


def _pick(noise: dict, grid: tuple, target: float, floor: int) -> int:
    ok = [g for g in grid if noise[g] <= target]
    return max(floor, min(ok) if ok else grid[-1])


def run(*, per_cell: int = 60, seats: int = 6, seed: int = 1, duration_s: int = 10_800,
        baseline_ppm: int = 150, target_noise: float = 0.001) -> dict:
    huge = 10**9
    quiet = _sample("quiet", per_cell, seats, seed, duration_s, baseline_ppm)
    noise_step = {t: _frac(quiet, ClockPolicy(step_note_ms=t, drift_note_ppm=huge), Code.CLOCK_STEP)
                  for t in STEP_GRID_MS}
    step = _pick(noise_step, STEP_GRID_MS, target_noise, FLOOR_STEP_MS)
    noise_drift = {p: _frac(quiet, ClockPolicy(step_note_ms=step, drift_note_ppm=p), Code.CLOCK_DRIFT)
                   for p in DRIFT_GRID_PPM}
    drift = _pick(noise_drift, DRIFT_GRID_PPM, target_noise, FLOOR_DRIFT_PPM)

    det_step = {}
    for i, size in enumerate(STEP_SIZES_MS):
        tr = _sample(f"step:{size}", per_cell, seats, seed + 1000 * (i + 1), duration_s, baseline_ppm)
        det_step[size] = {t: _frac(tr, ClockPolicy(step_note_ms=t, drift_note_ppm=huge), Code.CLOCK_STEP)
                          for t in STEP_GRID_MS}
    det_drift = {}
    for i, rate in enumerate(DRIFT_RATES_PPM):
        tr = _sample(f"slew:{rate}", per_cell, seats, seed + 5000 + 1000 * i, duration_s, baseline_ppm)
        det_drift[rate] = {p: _frac(tr, ClockPolicy(step_note_ms=step, drift_note_ppm=p),
                                    Code.CLOCK_DRIFT, Code.CLOCK_STEP) for p in DRIFT_GRID_PPM}
    policy = ClockPolicy(step_note_ms=step, drift_note_ppm=drift)
    return {"params": {"per_cell": per_cell, "seats": seats, "seed": seed, "duration_s": duration_s,
                       "baseline_ppm": baseline_ppm, "target_noise": target_noise,
                       "floor_step_ms": FLOOR_STEP_MS, "floor_drift_ppm": FLOOR_DRIFT_PPM},
            "noise_step": noise_step, "noise_drift": noise_drift,
            "detect_step": det_step, "detect_drift": det_drift,
            "policy": asdict(policy),
            "undetected_bound_s": step / 1000 + drift * 1e-6 * duration_s}


def _table(title: str, cols: tuple, rows: dict, unit: str, corner: str) -> list:
    out = [f"### {title}", "", f"| {corner} | " + " | ".join(f"{c} {unit}" for c in cols) + " |",
           "|---|" + "---|" * len(cols)]
    for k, r in rows.items():
        out.append(f"| {k} | " + " | ".join(f"{100 * r[c]:.1f}%" for c in cols) + " |")
    return out + [""]


def render_markdown(r: dict) -> str:
    p, pol = r["params"], r["policy"]
    L = ["# Clock threshold calibration (SIMULATED)", "",
         f"{p['per_cell']} sessions per cell, {p['seats']} stations per lab, seed {p['seed']}, "
         f"{p['duration_s']} s exams, baseline clock error up to +/-{p['baseline_ppm']} ppm. "
         "The baseline distribution is an assumption, not a measurement.", ""]
    L += _table("Noise: honest quiet sessions that raised a CLOCK_STEP note", STEP_GRID_MS,
                {"quiet": r["noise_step"]}, "ms", "population")
    L += _table("Detection: injected wall step noticed", STEP_GRID_MS,
                {f"{k} ms step": v for k, v in r["detect_step"].items()}, "ms", "injected")
    L += _table(f"Noise: quiet sessions that raised CLOCK_DRIFT (step threshold {pol['step_note_ms']} ms)",
                DRIFT_GRID_PPM, {"quiet": r["noise_drift"]}, "ppm", "population")
    L += _table("Detection: sustained clock rate error noticed (drift or step note)", DRIFT_GRID_PPM,
                {f"{k} ppm": v for k, v in r["detect_drift"].items()}, "ppm", "injected")
    L += ["## Chosen policy", "", f"- step_note_ms = {pol['step_note_ms']}",
          f"- drift_note_ppm = {pol['drift_note_ppm']}",
          f"- silence_note_ms = {pol['silence_note_ms']}, offset_note_ms = {pol['offset_note_ms']}", "",
          f"Target noise {100 * p['target_noise']:.2f}%. Thresholds are never lowered below the floor "
          f"({p['floor_step_ms']} ms, {p['floor_drift_ppm']} ppm) because the simulation cannot know real jitter.", "",
          "## What this cannot see", "",
          f"Wall-clock error below both thresholds is invisible. Over a {p['duration_s']} s boot that is "
          f"at most about {r['undetected_bound_s']:.1f} s. Report times as uncertain by that much, "
          "never as verified. All clock findings are notes; none can raise TAMPER_SUSPECTED.", ""]
    return "\n".join(L)
