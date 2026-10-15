#!/usr/bin/env python3
"""tools/tamper_lab.py: list, probe, run, and sweep the tamper lab.

Commands
    list    print all scenarios
    probe   inspect the agent's API surface (tells you what flush method was found)
    run     execute scenarios and print the result matrix
    sweep   run the power-cut WAL sweep
"""
import argparse
import json
import random
import sys
import tempfile
from pathlib import Path

# Add src/ and repo root to path so both `immutable` and `lab` are importable
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from lab.scenarios import SCENARIOS
from lab.world import World


# ----------------------------------------------------------------- commands

def cmd_list(a) -> None:
    print(f"{'ID':<6} {'Threat':<6} {'Group':<18} Title")
    print("-" * 80)
    for s in SCENARIOS:
        print(f"{s.id:<6} [{s.threat:<4}] {s.group:<18} {s.title}")
    print(f"\n{len(SCENARIOS)} scenarios total.")


def cmd_probe(a) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        world = World.build(tmp, n_seats=2, n_spares=1)
        from lab import adapter
        from lab.run import Run, make_ops
        import random as _r
        rng = _r.Random(0)
        ops = make_ops(rng, 5, submit=False)
        ws = world.seat_ids[0]
        ev_dir = Path(tmp) / "probe_ev"
        r = Run.start(world, ev_dir, ws_id=ws, signer=world.seats[ws],
                      session_id="PROBE001")
        r.play(ops)
        print("Agent public API:")
        for line in adapter.describe(r.h.agent):
            print(f"  {line}")
        print()
        found = None
        for name in adapter.FLUSH_CANDIDATES:
            if callable(getattr(r.h.agent, name, None)):
                found = name
                break
        if found:
            print(f"FLUSH method found: {found!r}")
        else:
            print("WARNING: no flush method found!")
            print(f"Tried: {adapter.FLUSH_CANDIDATES}")
            print("Edit lab/adapter.py to add the correct method name.")


def cmd_run(a) -> None:
    rng = random.Random(a.seed)
    ids = set(a.ids) if a.ids else None
    scenarios = [s for s in SCENARIOS if ids is None or s.id in ids]
    if not scenarios:
        print("No matching scenarios.", file=sys.stderr)
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmp:
        world = World.build(tmp)
        from lab.harness import run_trials, matrix
        all_trials = []
        for sc in scenarios:
            trials = run_trials(sc, world, Path(tmp) / "trials", n=a.n)
            all_trials += trials

    print(matrix(all_trials))
    failed = [
        t for t in all_trials
        if t.outcome.value in ("MISSED", "FALSE_ALARM")
    ]
    if failed:
        print(f"\n{len(failed)} FAILURE(S) — see matrix above (! marker)")
        sys.exit(1)
    else:
        print("\nAll trials passed.")


def cmd_sweep(a) -> None:
    rng = random.Random(a.seed)
    with tempfile.TemporaryDirectory() as tmp:
        world = World.build(tmp, n_seats=2, n_spares=1)
        from lab.powersweep import sweep
        results = sweep(world, Path(tmp) / "sweep", rng, n_ops=a.ops)
    print(json.dumps(results, indent=2))
    if results["lost_acked"]:
        print(f"\nFAILED: {results['lost_acked']} truncation(s) silently lost acked events.",
              file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\nPassed. {results['ok']} clean, {results['corrupt_refused']} refused (expected).")


# ----------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="tamper_lab",
        description="Tamper lab: simulate attacks against the immutable evidence chain.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List all scenarios").set_defaults(fn=cmd_list)

    probe_p = sub.add_parser("probe", help="Inspect the agent API surface")
    probe_p.set_defaults(fn=cmd_probe)

    run_p = sub.add_parser("run", help="Run scenarios and print result matrix")
    run_p.add_argument("ids", nargs="*", help="Scenario IDs to run (default: all)")
    run_p.add_argument("--n", type=int, default=5,
                       help="Trials per scenario (default: 5)")
    run_p.add_argument("--seed", type=int, default=0, help="RNG seed (default: 0)")
    run_p.set_defaults(fn=cmd_run)

    sweep_p = sub.add_parser("sweep", help="WAL power-cut sweep")
    sweep_p.add_argument("--seed", type=int, default=0)
    sweep_p.add_argument("--ops", type=int, default=10,
                         help="Number of ops before cut (default: 10)")
    sweep_p.set_defaults(fn=cmd_sweep)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
