"""canon.py: one and only one way to write a value down.

Two machines (a Python agent, a JS receipt page) must produce the same bytes for
the same value, or every signature breaks. So we make the format small enough to
get right: strings, ints, bools, null, lists, dicts. No floats, no ambiguity.
We refuse to guess: non-NFC text is rejected, never quietly rewritten.
"""
from __future__ import annotations

import json
import unicodedata
from typing import Any

MAX_INT = 2**53 - 1          # largest integer a JS Number holds exactly
MAX_DEPTH = 32
DEFAULT_MAX_BYTES = 1 << 20  # 1 MiB per document unless a caller says otherwise


class CanonError(ValueError):
    """The value or document is outside the canonical subset."""


def _check_str(s: str) -> None:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonError("lone surrogate in string") from None
    if not unicodedata.is_normalized("NFC", s):
        raise CanonError("string is not NFC-normalized")


def _check(o: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonError("nesting too deep")
    if o is None or isinstance(o, bool):        # bool before int: bool is an int
        return
    if isinstance(o, int):
        if abs(o) > MAX_INT:
            raise CanonError("integer outside JS-safe range")
        return
    if isinstance(o, str):
        _check_str(o)
        return
    if isinstance(o, (list, tuple)):
        for item in o:
            _check(item, depth + 1)
        return
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise CanonError("object keys must be strings")
            _check_str(k)
            _check(v, depth + 1)
        return
    raise CanonError(f"type {type(o).__name__} is not allowed (floats never are)")


def dumps(o: Any) -> bytes:
    """Canonical bytes for o. Raises CanonError if o is outside the subset."""
    _check(o)
    return json.dumps(
        o, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def loads(raw: bytes, *, max_bytes: int = DEFAULT_MAX_BYTES,
          require_canonical: bool = False) -> Any:
    """Strict parse. Hostile input fails with CanonError, nothing else."""
    if len(raw) > max_bytes:
        raise CanonError("document too large")

    def pairs(items):
        d = {}
        for k, v in items:
            if k in d:
                raise CanonError("duplicate key")
            d[k] = v
        return d

    def no_float(_s):
        raise CanonError("floats are not allowed")

    def no_const(_s):
        raise CanonError("NaN/Infinity are not allowed")

    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                         parse_float=no_float, parse_constant=no_const)
    except CanonError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise CanonError(f"unparseable: {e.__class__.__name__}") from None
    _check(obj)
    if require_canonical and dumps(obj) != raw:
        raise CanonError("document is valid JSON but not in canonical form")
    return obj
