"""Random writes, random power cuts, recover, check one invariant:
every acknowledged event survives. Run: python tools/crash_fuzz.py [N] [--lie]
--lie turns on a disk that ignores fsync; losses then SHOULD appear (that is the
point: they show up as a shorter chain, never as a silent one).
"""
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable.fsys import FaultFS
from immutable.keys import Signer
from immutable.wal import Wal

A64 = "a" * 64
IDS = ("EX1", "S1", "WS1")
START = {"paper_sha256": A64, "roster_sha256": A64, "agent_ver": "fuzz"}


def one(seed: int, lie: bool) -> str:
    rng = random.Random(seed)
    fs = FaultFS(rng, lie_about_fsync=lie)
    wal = Wal.create(fs, "s.wal", *IDS)
    wal.append("SESSION_START", START)
    for _ in range(rng.randint(1, 80)):
        wal.append("HEARTBEAT", sync=rng.random() < 0.8)
        if rng.random() < 0.1:
            wal.commit()
    acked = wal.durable_seq
    fs.crash()

    rep = Wal.recover(fs, "s.wal", *IDS, signer=Signer.generate())
    ok = rep.last_good_seq >= acked
    fs.crash()                                        # cut power again mid-life
    Wal.recover(fs, "s.wal", *IDS)                    # must still recover cleanly
    if not ok:
        return "LOST_ACKED" if lie else f"BUG seed={seed} acked={acked} got={rep.last_good_seq}"
    return "torn" if rep.discarded_bytes else "clean"


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 2000
    lie = "--lie" in sys.argv
    tally = Counter(one(s, lie) for s in range(n))
    print(dict(tally))
    bugs = [k for k in tally if k.startswith("BUG")]
    sys.exit(1 if bugs or (not lie and "LOST_ACKED" in tally) else 0)
