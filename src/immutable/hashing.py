"""hashing.py: every hash and signature is wearing a name tag.

A hash of event bytes must never be confusable with a hash of batch bytes, a
Merkle node, or anything else. The domain tag goes in front of the data, always.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

PREFIX = b"immutable/v1/"
ZERO = "0" * 64                      # genesis prev

DOMAINS = frozenset({
    "event", "batch", "merkle.leaf", "merkle.node", "merkle.empty",
    "key", "checkpoint", "roster", "receipt", "cosign", "transfer", "enroll", "ping", "final",
})

EVENT, BATCH, KEY = "event", "batch", "key"
CHECKPOINT, ROSTER, RECEIPT = "checkpoint", "roster", "receipt"
COSIGN, TRANSFER = "cosign", "transfer"
ENROLL = "enroll"
PING = "ping"
FINAL = "final"



def tagged(domain: str, data: bytes) -> bytes:
    if domain not in DOMAINS:
        raise ValueError(f"unknown domain: {domain!r}")
    return PREFIX + domain.encode("ascii") + b"\x00" + data


def h(domain: str, data: bytes) -> bytes:
    return hashlib.sha256(tagged(domain, data)).digest()


def hx(domain: str, data: bytes) -> str:
    return h(domain, data).hex()


def sha256_hex(data: bytes) -> str:
    """Plain SHA-256. For artifact bytes only, so sha256sum can check them."""
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: str | Path, chunk: int = 1 << 20) -> str:
    d = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            d.update(block)
    return d.hexdigest()


def is_hex(s: object, n: int) -> bool:
    return (isinstance(s, str) and len(s) == n
            and all(c in "0123456789abcdef" for c in s))


def is_hash(s: object) -> bool:
    return is_hex(s, 64)
