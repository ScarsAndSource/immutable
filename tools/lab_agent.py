"""Terminal lab agent. Every event prints as a ledger line the moment it is logged.

  python tools/lab_agent.py --exam EX1 --session S1 --ws WS01 \
      --workspace ./student_files --evidence ./evidence --paper ./paper.pdf

Commands at the prompt:  run <file.py>   status   flush   submit   quit
First start creates evidence/ws.key and prints the public key for enrollment (B4).
Killing the process (or pulling the plug) and starting it again with the same
arguments resumes the same session and logs a RECOVERY.
"""
import argparse
import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable import hashing, keys
from immutable.agent import Agent, AgentError
from immutable.events import Event
from immutable.roster import Roster, RosterError, preflight
from immutable.runner import run_python
from immutable.wal import WalError


def ledger(ev: Event) -> None:
    print(f"\r{ev.seq:>6}  {ev.type:<13} {ev.hash()[:8]}  "
          f"{ev.data.get('path', '')}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(prog="lab_agent")
    ap.add_argument("--exam", required=True)
    ap.add_argument("--session", required=True)
    ap.add_argument("--ws", required=True)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--paper", required=True, help="exam paper file; its hash is recorded")
    ap.add_argument("--roster", help="roster file; omit before B4 (recorded as all zeros)")
    ap.add_argument("--key", help="seed file (default: <evidence>/ws.key)")
    ap.add_argument("--heartbeat", type=float, default=30.0)
    ap.add_argument("--assessor-pub", help="trusted assessor public key (from the exam office)")
    ap.add_argument("--transfer", help="assessor-signed transfer token, if this machine replaces another")
    a = ap.parse_args()

    ev_dir = Path(a.evidence)
    ev_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path = Path(a.key) if a.key else ev_dir / "ws.key"
    if key_path.exists():
        signer = keys.load_seed(key_path)
    else:
        signer = keys.Signer.generate()
        keys.save_seed(key_path, signer)
        print(f"new key written to {key_path}")
    print(f"public key : {signer.pub_hex}\nkey id     : {keys.key_id(signer.pub_hex)}\n")

    paper_sha = hashing.file_sha256(a.paper)
    roster_sha = hashing.ZERO
    if a.roster:
        if not a.assessor_pub:
            sys.exit("--roster needs --assessor-pub (the key the exam office gave you)")
        raw = Path(a.roster).read_bytes()
        try:
            roster = Roster.parse(raw, trusted_assessor=a.assessor_pub)
        except RosterError as e:
            sys.exit(f"roster rejected: {e}")
        problems = preflight(roster, exam_id=a.exam, ws_id=a.ws, pub=signer.pub_hex,
                             paper_sha256=paper_sha, as_transfer=bool(a.transfer))
        if problems:
            sys.exit("cannot start:\n  " + "\n  ".join(problems))
        roster_sha = hashing.sha256_hex(raw)
        print(f"roster ok  : {roster_sha[:16]}…  seat {a.ws} is enrolled for this key")
    token = Path(a.transfer).read_bytes() if a.transfer else None
    try:
        agent = Agent.open(
            evidence_dir=ev_dir, workspace=a.workspace, exam_id=a.exam,
            session_id=a.session, ws_id=a.ws, signer=signer,
            paper_sha256=paper_sha, roster_sha256=roster_sha,
            heartbeat_s=a.heartbeat, transfer_token=token, assessor_pub=a.assessor_pub)
    except AgentError as e:
        sys.exit(f"cannot start: {e}")

    agent.listeners.append(ledger)
    print("seq     type           hash      detail")
    for e in agent._wal.events:
        ledger(e)

    stop = threading.Event()

    def ticker():
        while not stop.wait(1.0):
            try:
                agent.tick()
            except AgentError:
                return
            except WalError as e:
                print(f"\nLOG FAILED, stopping: {e}", flush=True)
                os._exit(2)

    threading.Thread(target=ticker, daemon=True).start()

    try:
        while True:
            try:
                line = input("immutable> ").strip()
            except EOFError:
                break
            cmd, _, arg = line.partition(" ")
            if cmd == "run" and arg:
                try:
                    r = run_python(agent, arg.strip())
                    sys.stdout.write(r.stdout.decode("utf-8", "replace"))
                    sys.stderr.write(r.stderr.decode("utf-8", "replace"))
                    print(f"[exit {r.exit_code}{' (timed out)' if r.timed_out else ''}, "
                          f"{r.duration_ms} ms]")
                except (AgentError, ValueError) as e:
                    print(f"cannot run: {e}")
            elif cmd == "status":
                print(agent.status())
            elif cmd == "flush":
                print(f"sealed {len(agent.flush())} batch(es)")
            elif cmd == "submit":
                res = agent.submit()
                print(f"submitted {res.file_count} file(s), manifest {res.manifest_sha256[:16]}…, "
                      f"final seq {res.last_seq}, head {res.head}")
                for s in res.skipped:
                    print(f"  NOT RECORDED: {s}")
                stop.set()
                return 0
            elif cmd in ("quit", "exit"):
                break
            elif cmd:
                print("commands: run <file.py> | status | flush | submit | quit")
    finally:
        stop.set()
        try:
            agent.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
