"""The exam office's ceremony tool. Everything is a file; nothing needs a network.

  python tools/roster_tool.py assessor-init --out assessor.key
  python tools/roster_tool.py request  --exam EX1 --ws WS01 --key evidence/ws.key --out WS01.req.json
  python tools/roster_tool.py build    --assessor-key assessor.key --exam EX1 --paper paper.pdf \
         --requests ./reqs --candidates candidates.txt --witness W1=<pub> --out roster.json
  python tools/roster_tool.py verify   roster.json --assessor-pub <pub> [--paper paper.pdf]
  python tools/roster_tool.py show     roster.json
  python tools/roster_tool.py transfer --assessor-key assessor.key --roster roster.json \
         --session S1 --from WS01 --last-seq 41 --head <hash> --to-request WS07.req.json --out t.json

candidates.txt: one "WS_ID CANDIDATE_PSEUDONYM" per line, '#' comments. Requests with no
line become spare seats. Real names never go anywhere near this tool.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable import hashing, keys
from immutable.roster import (Roster, RosterError, Seat, Witness, make_request,
                                parse_request)
from immutable.transfer import issue


def group4(h: str) -> str:
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def fingerprint(pub: str) -> str:
    return group4(keys.key_id(pub)[:32])


def cmd_assessor_init(a):
    s = keys.Signer.generate()
    keys.save_seed(a.out, s)
    print(f"assessor key written to {a.out}  (guard it; it signs rosters and transfers)")
    print(f"public key  : {s.pub_hex}")
    print(f"fingerprint : {fingerprint(s.pub_hex)}   <- print this on the exam envelope")


def cmd_request(a):
    s = keys.load_seed(a.key)
    Path(a.out).write_bytes(make_request(s, a.exam, a.ws))
    print(f"wrote {a.out}  (seat {a.ws}, key {fingerprint(s.pub_hex)})")


def _candidates(path):
    out = {}
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            sys.exit(f"{path}:{n}: expected 'WS_ID CANDIDATE'")
        if parts[0] in out:
            sys.exit(f"{path}:{n}: seat {parts[0]} listed twice")
        out[parts[0]] = parts[1]
    return out


def cmd_build(a):
    assessor = keys.load_seed(a.assessor_key)
    cands = _candidates(a.candidates) if a.candidates else {}
    seats = []
    for p in sorted(Path(a.requests).glob("*.req.json")):
        try:
            b = parse_request(p.read_bytes())
        except RosterError as e:
            sys.exit(f"{p.name}: {e}")
        if b["exam_id"] != a.exam:
            sys.exit(f"{p.name}: request is for exam {b['exam_id']}, not {a.exam}")
        seats.append(Seat(b["ws_id"], b["pub"], cands.pop(b["ws_id"], None)))
    if cands:
        sys.exit(f"candidates listed for seats with no enrollment request: {sorted(cands)}")
    wits = []
    for w in a.witness or []:
        wid, _, pub = w.partition("=")
        wits.append(Witness(wid, pub))
    try:
        r = Roster.build(assessor, exam_id=a.exam,
                         paper_sha256=hashing.file_sha256(a.paper),
                         seats=seats, witnesses=wits)
    except RosterError as e:
        sys.exit(f"cannot build roster: {e}")
    Path(a.out).write_bytes(r.raw)
    spares = sum(1 for s in r.seats if s.candidate is None)
    print(f"roster {a.out}: {len(r.seats)} seats ({spares} spare), "
          f"{len(r.witnesses)} witness(es)")
    print(f"roster id   : {group4(r.id[:32])}")
    print(f"assessor    : {fingerprint(r.assessor)}")


def _load(path, pub):
    try:
        return Roster.parse(Path(path).read_bytes(), trusted_assessor=pub)
    except RosterError as e:
        sys.exit(f"roster rejected: {e}")


def cmd_verify(a):
    r = _load(a.roster, a.assessor_pub)
    ok = True
    if a.paper and hashing.file_sha256(a.paper) != r.paper_sha256:
        print("FAIL: that paper is not the one this roster was issued for")
        ok = False
    print(f"{'OK' if ok else 'PROBLEM'}: roster {group4(r.id[:32])} for exam {r.exam_id}, "
          f"{len(r.seats)} seats, signed by {fingerprint(r.assessor)}")
    sys.exit(0 if ok else 1)


def cmd_show(a):
    r = Roster.parse(Path(a.roster).read_bytes())          # signature only, not trust
    print(f"exam {r.exam_id}   roster {group4(r.id[:32])}   assessor {fingerprint(r.assessor)}")
    print(f"paper {r.paper_sha256}")
    for s in r.seats:
        print(f"  {s.ws_id:<12} {s.candidate or '(spare)':<14} {fingerprint(s.pub)}")
    for w in r.witnesses:
        print(f"  witness {w.witness_id:<8} {fingerprint(w.pub)}")


def cmd_transfer(a):
    assessor = keys.load_seed(a.assessor_key)
    r = _load(a.roster, assessor.pub_hex)
    if r.seat(a.from_ws) is None:
        print(f"warning: {a.from_ws} is not a roster seat (fine only if it was itself a transfer target)")
    try:
        req = parse_request(Path(a.to_request).read_bytes())
        if req["exam_id"] != r.exam_id:
            sys.exit("the new machine's request is for a different exam")
        tok = issue(assessor, exam_id=r.exam_id, session_id=a.session,
                    from_ws_id=a.from_ws, from_last_seq=a.last_seq, from_head=a.head,
                    to_ws_id=req["ws_id"], to_pub=req["pub"])
    except Exception as e:
        sys.exit(f"cannot issue transfer: {e}")
    Path(a.out).write_bytes(tok)
    print(f"wrote {a.out}: session {a.session} moves {a.from_ws} (ends at seq {a.last_seq}) "
          f"-> {req['ws_id']} ({fingerprint(req['pub'])})")


def main():
    ap = argparse.ArgumentParser(prog="roster_tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("assessor-init"); p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_assessor_init)

    p = sub.add_parser("request")
    for f in ("--exam", "--ws", "--key", "--out"):
        p.add_argument(f, required=True)
    p.set_defaults(fn=cmd_request)

    p = sub.add_parser("build")
    for f in ("--assessor-key", "--exam", "--paper", "--requests", "--out"):
        p.add_argument(f, required=True)
    p.add_argument("--candidates"); p.add_argument("--witness", action="append")
    p.set_defaults(fn=cmd_build)

    p = sub.add_parser("verify"); p.add_argument("roster")
    p.add_argument("--assessor-pub", required=True); p.add_argument("--paper")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("show"); p.add_argument("roster"); p.set_defaults(fn=cmd_show)

    p = sub.add_parser("transfer")
    for f in ("--assessor-key", "--roster", "--session", "--from", "--head",
              "--to-request", "--out"):
        p.add_argument(f, required=True)
    p.add_argument("--last-seq", type=int, required=True)
    p.set_defaults(fn=cmd_transfer)

    a = ap.parse_args()
    if a.cmd == "transfer":
        a.from_ws = getattr(a, "from")
    a.fn(a)


if __name__ == "__main__":
    main()
