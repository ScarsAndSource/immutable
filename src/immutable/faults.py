"""faults.py: the bad days an honest student has, as seeded data.

Every fault here is BENIGN: it happens to people who did nothing wrong, and the
verifier must never turn it into an accusation. Each maps to a real mechanism:

  clean_restart  agent restarted, same boot (updater, user closed it)
  agent_crash    kill -9: the page cache survives, bytes in flight land whole
  power_cut      power loss: unsynced bytes drop / tear / zero-fill; machine reboots
  reboot         clean reboot: new boot id, uptime restarts
  ntp_step       the wall clock is stepped by a time sync (200 ms to 2 min, either way)
  vm_pause       VM paused and resumed: wall catches up, uptime does not
  suspend        laptop sleep: both clocks keep counting, nothing is logged
  seat_swap      the machine died; assessor moves the session with a signed transfer

Modifiers on power_cut / reboot: rtc_dead (the clock battery is flat: wall resets to the
year 2000 after boot) and fix_after_s (a time sync later snaps it back).

Profiles: clean, quiet (restarts and crashes only), typical, harsh (3x typical),
"step:<ms>" (quiet + exactly one wall step of that size) and "slew:<ppm>" (quiet + a
sustained clock rate error). The last two exist for calibration.

NOT modelled, and said so in the report: torn sectors in the middle of the log
(recovery refuses and a human decides) and disks that lie about fsync (a separate,
explicitly non-benign experiment: `lying_disk`).
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass


@dataclass
class Fault:
    t: int
    kind: str
    params: dict


@dataclass
class Plan:
    slew_ppm: int
    faults: list
    lying_disk: bool = False
    profile: str = "typical"


_TYPICAL = {"clean_restart": 0.4, "agent_crash": 0.3, "power_cut": 0.35, "reboot": 0.15,
            "ntp_step": 0.5, "vm_pause": 0.08, "suspend": 0.25, "seat_swap": 0.04}
_QUIET = {k: _TYPICAL[k] for k in ("clean_restart", "agent_crash", "power_cut", "reboot")}
PROFILES = {"clean": {}, "quiet": _QUIET, "typical": _TYPICAL,
            "harsh": {k: v * 3 for k, v in _TYPICAL.items()}}
KINDS = tuple(_TYPICAL)


def _poisson(rng: random.Random, lam: float) -> int:
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _params(rng: random.Random, kind: str) -> dict:
    if kind == "clean_restart":
        return {"down_s": rng.randint(5, 60)}
    if kind == "agent_crash":
        return {"down_s": rng.randint(2, 30)}
    if kind in ("power_cut", "reboot"):
        dead = rng.random() < (0.15 if kind == "power_cut" else 0.10)
        fix = rng.randint(60, 900) if dead and rng.random() < 0.6 else 0
        return {"down_s": rng.randint(30, 180) if kind == "power_cut" else rng.randint(30, 120),
                "rtc_dead": dead, "fix_after_s": fix}
    if kind == "ntp_step":
        ms = int(math.exp(rng.uniform(math.log(200), math.log(120_000))))
        return {"delta_ms": ms * rng.choice((-1, 1))}
    if kind == "vm_pause":
        return {"pause_s": rng.randint(5, 600)}
    if kind == "suspend":
        return {"sleep_s": rng.randint(60, 1800)}
    return {}


def make_plan(rng: random.Random, profile: str, duration_s: int, *,
              baseline_ppm: int = 150, lying_disk: bool = False) -> Plan:
    base, _, arg = profile.partition(":")
    if base in ("step", "slew"):
        table = _QUIET
    elif base in PROFILES:
        table = PROFILES[base]
    else:
        raise ValueError(f"unknown profile {profile!r}")
    slew = rng.randint(-baseline_ppm, baseline_ppm)
    lo, hi = 120, max(121, duration_s - 180)
    faults = []
    for kind, lam in table.items():
        n = _poisson(rng, lam)
        if kind == "seat_swap":
            n = min(n, 1)
        faults += [Fault(rng.randint(lo, hi), kind, _params(rng, kind)) for _ in range(n)]
    if base == "step":
        faults.append(Fault(rng.randint(600, max(601, duration_s - 600)), "ntp_step",
                            {"delta_ms": int(arg) * rng.choice((-1, 1))}))
    if base == "slew":
        slew = int(arg) * rng.choice((-1, 1))
    faults.sort(key=lambda f: (f.t, f.kind))
    return Plan(slew, faults, lying_disk, profile)
