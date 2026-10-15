"""The assessor's console.

  python tools/assessor.py ingest --store ./case --roster roster.json --assessor-pub <pub> [--live] PATH...
  python tools/assessor.py case   --store ./case --roster roster.json --assessor-pub <pub> [--json] [--out case.json]
  python tools/assessor.py verify --roster roster.json --assessor-pub <pub> [--json] [--out case.json] PATH...

PATH is an evidence directory copied off a workstation (outbox/, submission/), an
anchor file, or a flat folder of *.batch.json. `verify` is a one-shot: it builds a
throwaway store, ingests, and prints the case note. Exit code 1 means at least one
session needs human review.
"""
import argparse
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable.report import render
from immutable.roster import Roster, RosterError
from immutable.store import Store


def load_roster(a) -> Roster:
    try:
        return Roster.parse(Path(a.roster).read_bytes(), trusted_assessor=a.assessor_pub)
    except RosterError as e:
        sys.exit(f"roster rejected: {e}")


def emit(case, a) -> int:
    if a.out:
        Path(a.out).write_bytes(case.to_bytes())
        print(f"wrote {a.out}  (case hash {case.hash})")
    sys.stdout.write(case.to_bytes().decode() + "\n" if a.json else render(case))
    return 1 if case.body["summary"]["tamper_suspected"] else 0


def main() -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--roster", required=True)
    common.add_argument("--assessor-pub", required=True)
    ap = argparse.ArgumentParser(prog="assessor")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", parents=[common])
    p.add_argument("--store", required=True)
    p.add_argument("--live", action="store_true", help="batches arrived over the LAN just now")
    p.add_argument("paths", nargs="+")

    p = sub.add_parser("case", parents=[common])
    p.add_argument("--store", required=True)
    p.add_argument("--json", action="store_true")
    p.add_argument("--out")

    p = sub.add_parser("verify", parents=[common])
    p.add_argument("--json", action="store_true")
    p.add_argument("--out")
    p.add_argument("paths", nargs="+")

    a = ap.parse_args()
    roster = load_roster(a)

    if a.cmd == "ingest":
        store = Store(a.store, roster)
        for path in a.paths:
            print(path, store.ingest_path(path, live=a.live))
        return 0
    if a.cmd == "case":
        return emit(Store(a.store, roster).case(), a)
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(tmp, roster)
        for path in a.paths:
            store.ingest_path(path)
        case = store.case()
        store.close()
        return emit(case, a)


if __name__ == "__main__":
    sys.exit(main())
