"""evidence.py: low-level surgery on batch files.

We never forge signatures here. We tamper with raw bytes after the fact,
which breaks signatures in predictable ways that the verifier is supposed
to catch. All helpers return bytes so callers can pass them directly to
Store.ingest_batch or write them to disk.
"""
from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from pathlib import Path

from immutable import canon
from immutable.batch import verify_batch


@dataclass
class BatchInfo:
    path: Path
    raw: bytes
    first_seq: int
    last_seq: int
    session_id: str
    ws_id: str

    @property
    def name(self) -> str:
        return self.path.name


def batch_infos(outbox: Path) -> list[BatchInfo]:
    """Return all valid batch files in outbox/, sorted by first_seq."""
    infos = []
    for p in sorted(outbox.glob("*.batch.json")):
        raw = p.read_bytes()
        b, _ = verify_batch(raw)
        if b is None:
            continue
        h = b.header
        infos.append(BatchInfo(p, raw, h["first_seq"], h["last_seq"],
                               h["session_id"], h["ws_id"]))
    infos.sort(key=lambda x: x.first_seq)
    return infos


def events_of(info: BatchInfo) -> list[dict]:
    """Parse the events list out of a batch file (canonical JSON)."""
    obj = json.loads(info.raw)
    return obj.get("events", [])


def contiguous(infos: list[BatchInfo]) -> bool:
    """True if the batch list covers a gapless seq range starting at 0."""
    if not infos:
        return True
    if infos[0].first_seq != 0:
        return False
    for a, b in zip(infos, infos[1:]):
        if a.last_seq + 1 != b.first_seq:
            return False
    return True


def mutate_event_data(raw: bytes, target_seq: int,
                      mutate: "Callable[[dict], dict]") -> bytes:
    """Replace the data payload of one event (by seq) and return new raw bytes.

    The batch signature will no longer verify after this — that is the point.
    """
    obj = json.loads(raw)
    for ev in obj.get("events", []):
        if ev.get("seq") == target_seq:
            ev["data"] = mutate(ev.get("data") or {})
            break
    return canon.dumps(obj)


def flip_hex_anywhere(raw: bytes, rng: random.Random) -> bytes:
    """Find a hex run of length >= 8 and flip one nibble.

    This corrupts a hash or signature without making the JSON invalid.
    """
    text = raw.decode()
    # find all runs of 8+ hex chars that aren't part of longer words
    spans = [(m.start(), m.end()) for m in re.finditer(r'(?<![0-9a-f])[0-9a-f]{8,}(?![0-9a-f])', text)]
    if not spans:
        # fallback: flip a random byte in the middle
        mid = len(raw) // 2
        ba = bytearray(raw)
        ba[mid] ^= 0x01
        return bytes(ba)
    start, end = rng.choice(spans)
    pos = rng.randint(start, end - 1)
    nibble = text[pos]
    # flip to a different hex char
    hexchars = "0123456789abcdef"
    others = [c for c in hexchars if c != nibble]
    new_nibble = rng.choice(others)
    return (text[:pos] + new_nibble + text[pos + 1:]).encode()


def rewrite_strings(raw: bytes, find: str, replace: str) -> bytes:
    """Simple string replacement in the raw bytes (for swapping IDs etc.)."""
    return raw.replace(find.encode(), replace.encode())
