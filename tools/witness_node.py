"""The lab witness.

  python tools/witness_node.py init   --out witness.key
        prints the public key; give it to the exam office:
        roster_tool.py build ... --witness W1=<pub>
  python tools/witness_node.py run    --roster roster.json --assessor-pub <pub> --key witness.key \
        --id W1 --dir ./witness --port 9443
  python tools/witness_node.py report --roster roster.json --assessor-pub <pub> --key witness.key \
        --id W1 --dir ./witness

Run it on a machine students cannot touch (a spare laptop, a Pi). After the exam copy
<dir>/anchors and <dir>/batches to the assessor: `assessor.py ingest` reads both.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable import keys
from immutable.net import WitnessServer
from immutable.roster import Roster, RosterError
from immutable.witness import Witness, WitnessError


def g4(h: str) -> str:
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def build(a) -> Witness:
    try:
        roster = Roster.parse(Path(a.roster).read_bytes(), trusted_assessor=a.assessor_pub)
        return Witness(roster, keys.load_seed(a.key), a.id, directory=a.dir)
    except (RosterError, WitnessError, OSError) as e:
        sys.exit(f"cannot start witness: {e}")


def main() -> int:
    ap = argparse.ArgumentParser(prog="witness_node")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--out", required=True)
    for name in ("run", "report"):
        p = sub.add_parser(name)
        for f in ("--roster", "--assessor-pub", "--key", "--id", "--dir"):
            p.add_argument(f, required=True)
        if name == "run":
            p.add_argument("--host", default="0.0.0.0")
            p.add_argument("--port", type=int, default=9443)
    a = ap.parse_args()

    if a.cmd == "init":
        s = keys.Signer.generate()
        keys.save_seed(a.out, s)
        print(f"public key  : {s.pub_hex}\nfingerprint : {g4(keys.key_id(s.pub_hex)[:32])}")
        return 0

    w = build(a)
    if a.cmd == "report":
        r = w.report()
        print(f"witness {r['witness']}   exam {r['exam_id']}   roster {g4(r['roster_id'][:32])}")
        for s in r["seats"]:
            print(f"  {s['session']:<14} {s['ws']:<8} held up to {s['held_upto']:>6} "
                  f"({s['events_held']} events), {s['contacts']} contacts, "
                  f"longest silence {s['longest_contact_gap_ms'] // 1000} s")
        for x in r["refusals"]:
            print(f"  REFUSED {x['session']}/{x['ws']} [{x['code']}] {x['detail']}")
        if not r["refusals"]:
            print("  no refusals")
        return 0

    srv = WitnessServer(w, a.host, a.port)
    print(f"witness {a.id} listening on {a.host}:{srv.port}   key {g4(keys.key_id(w._signer.pub_hex)[:32])}")
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        while True:
            time.sleep(60)
            r = w.report()
            print(f"{time.strftime('%H:%M:%S')}  seats {len(r['seats'])}  "
                  f"events {sum(s['events_held'] for s in r['seats'])}  refusals {len(r['refusals'])}",
                  flush=True)
    except KeyboardInterrupt:
        srv.shutdown()
        w.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
