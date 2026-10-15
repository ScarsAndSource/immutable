"""Writes vectors/v1.json: golden outputs for the JS side to match byte for byte.

Run from the repo root after `pip install -e .`. Ed25519 is deterministic, so the
signature vector is stable. Commit the output and never edit it by hand.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from immutable import canon, hashing, keys, merkle
from immutable.events import Event

SEED = bytes(range(32)).hex()

canon_cases = [
    {"b": 1, "a": [True, None, "x"]},
    {"é": "\u00e9", "k": -7},
    {"nested": {"z": 0, "y": {"x": 2**53 - 1}}},
]
signer = keys.Signer.from_seed_hex(SEED)
ev = Event("EX1", "S1", "WS1", 0, hashing.ZERO, "HEARTBEAT", 1700000000000,
           5_000_000_000, "bootaaaa", {})
hashes = [hashing.hx("event", bytes([i])) for i in range(8)]

out = {
    "canon": [{"in": c, "out": canon.dumps(c).decode()} for c in canon_cases],
    "domains": {d: hashing.hx(d, b"abc") for d in sorted(hashing.DOMAINS)},
    "merkle": {str(n): merkle.root(hashes[:n]) for n in range(0, 9)},
    "merkle_proof_5_of_8": {"index": 5, "path": merkle.prove(hashes, 5),
                            "root": merkle.root(hashes)},
    "event": {"body": ev.body(), "hash": ev.hash()},
    "sign": {"seed": SEED, "pub": signer.pub_hex,
             "sig": signer.sign("batch", b"hello")},
}
Path("vectors").mkdir(exist_ok=True)
Path("vectors/v1.json").write_text(json.dumps(out, indent=2, sort_keys=True))
print("wrote vectors/v1.json")
