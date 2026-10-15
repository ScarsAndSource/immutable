"""merkle.py: RFC 6962 tree over event hashes.

The split rule (largest power of two strictly below n) is what keeps proofs
short and the root unambiguous for any n. Leaves and nodes are domain-separated
so a leaf can never be passed off as an interior node.
"""
from __future__ import annotations

from .hashing import h


def _leaf(item_hex: str) -> bytes:
    return h("merkle.leaf", bytes.fromhex(item_hex))


def _node(left: bytes, right: bytes) -> bytes:
    return h("merkle.node", left + right)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root(lh: list[bytes]) -> bytes:
    n = len(lh)
    if n == 1:
        return lh[0]
    k = _split(n)
    return _node(_root(lh[:k]), _root(lh[k:]))


def root(items_hex: list[str]) -> str:
    """Merkle root over hex hashes, in order."""
    if not items_hex:
        return h("merkle.empty", b"").hex()
    return _root([_leaf(x) for x in items_hex]).hex()


def _proof(lh: list[bytes], m: int) -> list[bytes]:
    n = len(lh)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return _proof(lh[:k], m) + [_root(lh[k:])]
    return _proof(lh[k:], m - k) + [_root(lh[:k])]


def prove(items_hex: list[str], index: int) -> list[str]:
    """Inclusion proof (bottom-up siblings) for items_hex[index]."""
    if not 0 <= index < len(items_hex):
        raise IndexError("index out of range")
    return [p.hex() for p in _proof([_leaf(x) for x in items_hex], index)]


def _rebuild(leaf: bytes, m: int, n: int, path: list[bytes]) -> bytes | None:
    if n == 1:
        return leaf if not path else None
    if not path:
        return None
    k = _split(n)
    sib, rest = path[-1], path[:-1]
    if m < k:
        left = _rebuild(leaf, m, k, rest)
        return None if left is None else _node(left, sib)
    right = _rebuild(leaf, m - k, n - k, rest)
    return None if right is None else _node(sib, right)


def verify(item_hex: str, index: int, size: int, path_hex: list[str],
           expected_root_hex: str) -> bool:
    try:
        if not 0 <= index < size:
            return False
        got = _rebuild(_leaf(item_hex), index, size,
                       [bytes.fromhex(p) for p in path_hex])
        return got is not None and got.hex() == expected_root_hex
    except ValueError:
        return False
