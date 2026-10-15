"""policy.py: the line we promised not to cross, enforced in code.

Immutable records fingerprints and coarse milestones. It never records
keystrokes, screens, cameras or biometrics. The guarantee is structural: an
event type that is not listed here cannot exist, and a field that is not listed
for its type cannot be carried. There is no free-text escape hatch.
"""
from __future__ import annotations

import unicodedata

from .hashing import is_hash, is_hex


class PolicyError(ValueError):
    pass


def _relpath(v) -> bool:
    return (isinstance(v, str) and 0 < len(v) <= 256
            and unicodedata.is_normalized("NFC", v)
            and "\\" not in v and "\x00" not in v
            and not v.startswith("/")
            and all(p not in ("", ".", "..") for p in v.split("/")))


is_relpath = _relpath


def _uint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2**53


def _sint(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and -2**31 <= v < 2**31


def _ident(v) -> bool:
    return (isinstance(v, str) and 0 < len(v) <= 64
            and all(c.isascii() and (c.isalnum() or c in "._-") for c in v))


def _short(v) -> bool:
    return isinstance(v, str) and 0 < len(v) <= 32 and v.isascii() and v.isprintable()


def _enum(*allowed):
    return lambda v: v in allowed


def _sig(v) -> bool:
    return is_hex(v, 128)


SCHEMAS: dict[str, dict] = {
    "SESSION_START": {"paper_sha256": is_hash, "roster_sha256": is_hash,
                      "agent_ver": _short},
    "BOOT":          {"reason": _enum("start", "resume")},
    "FILE_SAVE":     {"path": _relpath, "sha256": is_hash, "size": _uint},
    "RUN_START":     {"path": _relpath, "sha256": is_hash},
    "RUN_END":       {"exit_code": _sint, "stdout_sha256": is_hash,
                      "duration_ms": _uint},
    "SUBMIT":        {"manifest_sha256": is_hash, "file_count": _uint},
    "CHECKPOINT":    {"merkle_root": is_hash, "upto_seq": _uint},
    "HEARTBEAT":     {},
    "RECOVERY":      {"last_good_seq": _uint, "discarded_bytes": _uint},
    "TRANSFER":      {"from_ws_id": _ident, "from_last_seq": _uint,
                      "from_head": is_hash, "assessor_sig": _sig},
    "SESSION_END":   {"reason": _enum("submitted", "timeout", "aborted")},
    "SYNC_STATE":    {"state": _enum("synced", "probing", "locked", "resynced"),
                      "last_confirmed_seq": _uint},
}


def validate(etype: str, data: object) -> None:
    schema = SCHEMAS.get(etype)
    if schema is None:
        raise PolicyError(f"event type not on the allow-list: {etype!r}")
    if not isinstance(data, dict):
        raise PolicyError("event data must be an object")
    extra = set(data) - set(schema)
    if extra:
        raise PolicyError(f"fields not allowed for {etype}: {sorted(extra)}")
    for name, ok in schema.items():
        if name not in data:
            raise PolicyError(f"{etype} is missing field {name!r}")
        if not ok(data[name]):
            raise PolicyError(f"{etype}.{name} fails its check")
