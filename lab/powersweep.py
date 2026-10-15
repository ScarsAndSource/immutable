"""powersweep.py: truncate the WAL at every byte and check the recovery invariant.

The invariant: no event that was acknowledged (i.e. that was in wal.events
at the time of the call) may be lost to a truncation that Wal.recover accepts
without raising WalCorrupt.

Results dict:
    ok              truncation points where recovery succeeded and nothing was lost
    lost_acked      recovery succeeded but some acked event was lost (BUG)
    corrupt_refused recovery raised WalCorrupt (the intended behaviour for bad cuts)
    errors          list of unexpected exceptions
"""
from __future__ import annotations

import shutil
from pathlib import Path

from . import adapter, run as run_mod
from .world import World


def sweep(world: World, root: Path, rng, n_ops: int = 10) -> dict:
    results: dict = {"ok": 0, "lost_acked": 0, "corrupt_refused": 0, "errors": []}

    seat = rng.choice(world.seat_ids)
    signer = world.seats[seat]
    session_id = f"SWP{rng.getrandbits(24):06X}"
    ev_dir = root / "orig"

    ops = run_mod.make_ops(rng, n_ops, submit=False)
    r = run_mod.Run.start(world, ev_dir, ws_id=seat, signer=signer,
                          session_id=session_id)
    r.play(ops)

    # acked: seq -> hash of every event the WAL has accepted
    acked = r.partial()
    acked_hashes = {seq: e.hash() for seq, e in acked.items()}

    wal_path = adapter.find_wal(ev_dir)
    full_bytes = wal_path.read_bytes()

    for cut in range(0, len(full_bytes) + 1):
        cut_dir = root / f"cut_{cut:06d}"
        try:
            shutil.copytree(ev_dir, cut_dir, dirs_exist_ok=True)
            cwal = adapter.find_wal(cut_dir)
            cwal.write_bytes(full_bytes[:cut])

            from immutable.fsys import RealFS
            from immutable.wal import Wal, WalCorrupt

            try:
                rec = Wal.recover(RealFS(), str(cwal), world.exam, session_id, seat)
                recovered = {e.seq: e.hash() for e in rec.wal.events}
                lost = [
                    seq for seq, h in acked_hashes.items()
                    if seq not in recovered or recovered[seq] != h
                ]
                if lost:
                    results["lost_acked"] += 1
                    results["errors"].append(f"cut={cut}: lost acked seqs {lost[:5]}")
                else:
                    results["ok"] += 1
            except WalCorrupt:
                results["corrupt_refused"] += 1
            except Exception as exc:
                results["errors"].append(f"cut={cut}: {type(exc).__name__}: {exc}")
        finally:
            shutil.rmtree(cut_dir, ignore_errors=True)

    return results
