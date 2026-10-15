"""Check a student receipt. Offline: needs only the receipt and the pinned roster.

  python tools/validate_receipt.py --roster roster.json --assessor-pub <pub> "IMR1...."
  python tools/validate_receipt.py --roster roster.json --assessor-pub <pub> -f slip.txt \
         --evidence ./evidence-copy

Exit 0: every required check passed. 1: one failed. 2: could not run.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable import receipt
from immutable.roster import Roster, RosterError


def main() -> int:
    ap = argparse.ArgumentParser(prog="validate_receipt")
    ap.add_argument("--roster", required=True)
    ap.add_argument("--assessor-pub", required=True)
    ap.add_argument("--evidence", action="append", default=[], metavar="DIR",
                    help="evidence copied off the workstation; repeatable")
    ap.add_argument("-f", "--file", help="a saved receipt slip (the IMR1 text must be last)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("token", nargs="?", help="the IMR1. text, or - for stdin")
    a = ap.parse_args()
    try:
        roster = Roster.parse(Path(a.roster).read_bytes(), trusted_assessor=a.assessor_pub)
    except (OSError, RosterError) as e:
        print(f"roster rejected: {e}", file=sys.stderr)
        return 2
    if a.file:
        text = Path(a.file).read_text(encoding="utf-8")
    elif a.token and a.token != "-":
        text = a.token
    else:
        text = sys.stdin.read()

    res = receipt.validate(text, roster, evidence=a.evidence)
    if a.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        d = res.to_dict()
        if d["receipt"]:
            r = d["receipt"]
            print(f"Receipt {r['receipt_id']}  exam {r['exam_id']}  seat {r['ws_id']}  "
                  f"events 0..{r['upto_seq']}\n  final event {receipt.groups(r['head'])}\n"
                  f"  signed {r['signed_at']} by that computer's own clock\n")
        for c in res.checks:
            tag = "ok  " if c.ok else ("FAIL" if c.required else "note")
            print(f"  [{tag}] {c.text}")
        print("\n" + ("RECEIPT VALID" if res.valid else "RECEIPT NOT VALID"))
        if not res.against_log:
            print("Checked offline only. Re-run with --evidence DIR to compare it with the log.")
        print(receipt.LIMITS)
    return 0 if res.valid else 1


if __name__ == "__main__":
    sys.exit(main())
