"""findings.py: the verifier speaks in codes, humans read the sentences.

Codes are stable (tests, UI copy and reports key off them). A finding says what
is inconsistent and where. It never says who is guilty.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Code(str, Enum):
    MALFORMED = "MALFORMED"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    SIGNER_MISMATCH = "SIGNER_MISMATCH"
    WRONG_CONTEXT = "WRONG_CONTEXT"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    SEQ_GAP = "SEQ_GAP"
    CHAIN_BREAK = "CHAIN_BREAK"
    HEADER_MISMATCH = "HEADER_MISMATCH"


@dataclass(frozen=True)
class Finding:
    code: Code
    seq: int | None
    detail: str

    def __str__(self) -> str:
        where = f" at seq {self.seq}" if self.seq is not None else ""
        return f"{self.code.value}{where}: {self.detail}"
