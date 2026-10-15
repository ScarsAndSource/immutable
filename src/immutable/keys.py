"""keys.py: Ed25519 behind a tiny door.

The private seed is the whole secret. A student with root can read it; that
limit is in the threat model (T4), and the witness is how we bound it.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from . import hashing
from .hashing import is_hex

_RAW = dict(encoding=serialization.Encoding.Raw)


class Signer:
    def __init__(self, sk: Ed25519PrivateKey):
        self._sk = sk

    @classmethod
    def generate(cls) -> "Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "Signer":
        if not is_hex(seed_hex, 64):
            raise ValueError("seed must be 64 lowercase hex chars")
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)))

    def seed_hex(self) -> str:
        return self._sk.private_bytes(
            **_RAW, format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()).hex()

    @property
    def pub_hex(self) -> str:
        return self._sk.public_key().public_bytes(
            **_RAW, format=serialization.PublicFormat.Raw).hex()

    def sign(self, domain: str, data: bytes) -> str:
        return self._sk.sign(hashing.tagged(domain, data)).hex()


def verify(domain: str, pub_hex: str, data: bytes, sig_hex: str) -> bool:
    """True only for a valid signature. Never raises on garbage input."""
    try:
        if not (is_hex(pub_hex, 64) and is_hex(sig_hex, 128)):
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), hashing.tagged(domain, data))
        return True
    except (InvalidSignature, ValueError):
        return False


def key_id(pub_hex: str) -> str:
    """Stable fingerprint for a public key (used in rosters and duplicate checks)."""
    return hashing.hx(hashing.KEY, bytes.fromhex(pub_hex))


def save_seed(path: str | Path, signer: Signer) -> None:
    """Create the seed file, 0600, refusing to overwrite an existing key."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(signer.seed_hex())


def load_seed(path: str | Path) -> Signer:
    return Signer.from_seed_hex(Path(path).read_text().strip())
