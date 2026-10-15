"""Measure the pipeline against honest-but-unlucky students.

  python tools/evaluate.py false-alarms --labs 50 --seats 6 --seed 1 --out eval/ [--lying-disk] [--real-json real.json]
  python tools/evaluate.py calibrate    --per-cell 60 --out eval/          (writes eval/clock_policy.json)
  python tools/evaluate.py real         --roster roster.json --assessor-pub PUB --out real.json DIR...
  python tools/evaluate.py replay       --seed 17 --seats 6 --profile typical [--lying-disk] [--no-anchors]

`replay` prints the full case note for one simulated lab: use it on any flagged seed.
"""
import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable import calibrate, evalrun
from immutable.clockcheck import ClockPolicy
from immutable.report import render
from immutable.roster import Roster
from immutable.simlab import reconcile_lab, simulate_lab
from immutable.store import Store


def load_policy(path):
    if not path:
        return ClockPolicy()
    d = json.loads(Path(path).read_text())
    return ClockPolicy(**{k: d[k] for k in ClockPolicy.__dataclass_fields__ if k in d})


def progress(i, n):
    print(f"\r  lab {i}/{n}", end="", file=sys.stderr, flush=True)


def cmd_false_alarms(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    policy = load_policy(a.policy)
    kw = dict(labs=a.labs, seats=a.seats, seed=a.seed, profile=a.profile,
              duration_s=a.duration, policy=policy, progress=progress)
    r = evalrun.run(**kw)
    print(file=sys.stderr)
    lying = None
    if a.lying_disk:
        lying = evalrun.run(**{**kw, "labs": max(5, a.labs // 5)}, lying_disk=True, anchors_variant=False)
        print(file=sys.stderr)
    real = json.loads(Path(a.real_json).read_text()) if a.real_json else None
    (out / "false_alarms.json").write_text(json.dumps({"main": r, "lying_disk": lying, "real": real},
                                                      indent=2, sort_keys=True))
    md = evalrun.render_markdown(r, lying, real)
    (out / "false_alarms.md").write_text(md)
    print(md)
    return 1 if r["suspect"] else 0


def cmd_calibrate(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    r = calibrate.run(per_cell=a.per_cell, seats=a.seats, seed=a.seed, duration_s=a.duration,
                      baseline_ppm=a.baseline_ppm, target_noise=a.target_noise)
    (out / "clock_policy.json").write_text(json.dumps(r["policy"], indent=2, sort_keys=True))
    (out / "clock_calibration.json").write_text(json.dumps(r, indent=2, sort_keys=True, default=str))
    md = calibrate.render_markdown(r)
    (out / "clock_calibration.md").write_text(md)
    print(md)
    print(f"policy written to {out / 'clock_policy.json'}  (pass it to assessor.py --policy)")
    return 0


def cmd_real(a):
    roster = Roster.parse(Path(a.roster).read_bytes(), trusted_assessor=a.assessor_pub)
    policy = load_policy(a.policy)
    n = k = 0
    notes = Counter()
    for d in a.dirs:
        with tempfile.TemporaryDirectory() as tmp:
            st = Store(tmp, roster)
            st.ingest_path(d)
            case = st.case(policy)
            st.close()
        for s in case.body["sessions"]:
            n += 1
            k += s["verdict"] == "TAMPER_SUSPECTED"
            codes = {f["code"] for f in s["findings"] if f["severity"] == "note"}
            for c in s["chains"]:
                codes |= {f["code"] for f in c["findings"] if f["severity"] == "note"}
            notes.update(codes)
            if s["verdict"] == "TAMPER_SUSPECTED":
                print(f"FLAGGED {d} session {s['session_id']}")
    Path(a.out).write_text(json.dumps({"source": "real machines", "sessions": n, "suspect": k,
                                       "notes": dict(sorted(notes.items()))}, indent=2, sort_keys=True))
    print(f"{k} of {n} real sessions flagged; notes {dict(notes)}")
    return 1 if k else 0


def cmd_replay(a):
    lab = simulate_lab(a.seed, n_seats=a.seats, profile=a.profile, duration_s=a.duration,
                       lying_disk=a.lying_disk)
    print("faults:", {k: v["faults"] for k, v in lab.stations.items()})
    case = reconcile_lab(lab, with_anchors=not a.no_anchors, policy=load_policy(a.policy))
    sys.stdout.write(render(case))
    return 0


def main():
    ap = argparse.ArgumentParser(prog="evaluate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("false-alarms")
    p.add_argument("--labs", type=int, default=50)
    p.add_argument("--seats", type=int, default=6)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--profile", default="typical")
    p.add_argument("--duration", type=int, default=10800)
    p.add_argument("--policy")
    p.add_argument("--out", default="eval")
    p.add_argument("--lying-disk", action="store_true")
    p.add_argument("--real-json")
    p.set_defaults(fn=cmd_false_alarms)
    p = sub.add_parser("calibrate")
    p.add_argument("--per-cell", type=int, default=60)
    p.add_argument("--seats", type=int, default=6)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--duration", type=int, default=10800)
    p.add_argument("--baseline-ppm", type=int, default=150)
    p.add_argument("--target-noise", type=float, default=0.001)
    p.add_argument("--out", default="eval")
    p.set_defaults(fn=cmd_calibrate)
    p = sub.add_parser("real")
    p.add_argument("--roster", required=True)
    p.add_argument("--assessor-pub", required=True)
    p.add_argument("--policy")
    p.add_argument("--out", required=True)
    p.add_argument("dirs", nargs="+")
    p.set_defaults(fn=cmd_real)
    p = sub.add_parser("replay")
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--seats", type=int, default=6)
    p.add_argument("--profile", default="typical")
    p.add_argument("--duration", type=int, default=10800)
    p.add_argument("--policy")
    p.add_argument("--lying-disk", action="store_true")
    p.add_argument("--no-anchors", action="store_true")
    p.set_defaults(fn=cmd_replay)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
