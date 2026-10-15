"""Determinism self-check: same inputs, any order, any duplicates, same case hash.

  python tools/shuffle_check.py --roster roster.json --assessor-pub <pub> [--runs 200] PATH...

Shuffles every input list, sprinkles in duplicates, runs reconcile() again and compares
the case hash with the first run. Exit 1 on the first difference.
"""
import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable.reconcile import reconcile
from immutable.roster import Roster


def load(paths):
    batches, anchors, manifests, blobs = [], [], [], set()
    for root in paths:
        files = [Path(root)] if Path(root).is_file() else \
            [p for p in sorted(Path(root).rglob("*")) if p.is_file()]
        for p in files:
            if p.name.endswith(".batch.json"):
                batches.append(p.read_bytes())
            elif p.name.endswith(".anchor.json"):
                anchors.append(p.read_bytes())
            elif p.name == "manifest.json":
                manifests.append(p.read_bytes())
            elif p.parent.name == "blobs":
                blobs.add(p.name)
    return batches, anchors, manifests, blobs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roster", required=True)
    ap.add_argument("--assessor-pub", required=True)
    ap.add_argument("--runs", type=int, default=200)
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    roster = Roster.parse(Path(a.roster).read_bytes(), trusted_assessor=a.assessor_pub)
    batches, anchors, manifests, blobs = load(a.paths)
    has_blob = (lambda sha: sha in blobs) if blobs else None

    def run(rng=None):
        b, an, m = list(batches), list(anchors), list(manifests)
        if rng:
            for lst in (b, an, m):
                rng.shuffle(lst)
                lst += rng.choices(lst, k=len(lst) // 10) if lst else []
                rng.shuffle(lst)
        return reconcile(b, roster, anchors=an, manifests=m, has_blob=has_blob).hash

    base = run()
    for seed in range(a.runs):
        h = run(random.Random(seed))
        if h != base:
            print(f"DIFFERENT at seed {seed}: {h} vs {base}")
            return 1
    print(f"OK: {a.runs} shuffles with duplicates, one case hash: {base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
