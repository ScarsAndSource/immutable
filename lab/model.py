"""model.py: data types that every lab module shares.

Outcome   what a trial's result was
Expect    what the scenario author claims it should be
Inputs    the actual bytes given to Store.ingest
Obs       what we observed in the Case for one victim chain
Scenario  a named, self-describing test with a declared outcome
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable


class Outcome(str, Enum):
    DETECTED    = "DETECTED"     # verifier raised a SUSPECT finding
    NEUTRALIZED = "NEUTRALIZED"  # hostile input rejected or ignored; verdict unchanged
    BY_DESIGN   = "BY_DESIGN"    # not provable; report must say so, must not show clean
    CLEAN       = "CLEAN"        # a control stayed clean
    MISSED      = "MISSED"       # attack got through or report was silent   -- gate fails
    FALSE_ALARM = "FALSE_ALARM"  # clean control raised SUSPECT               -- gate fails


@dataclass
class Expect:
    outcome: Outcome
    # for DETECTED: at least one of these codes must appear in obs.suspect
    codes: set[str] = field(default_factory=set)
    # for CLEAN: all of these must appear in obs.notes (not suspect)
    notes: set[str] = field(default_factory=set)
    # for CLEAN: verdict must be in this set (if non-empty)
    verdicts: set[str] = field(default_factory=set)
    # for BY_DESIGN: at least one of these must appear in obs.unprov
    unprovable: set[str] = field(default_factory=set)
    # for CLEAN + NEUTRALIZED: Case.hash must equal baseline Case.hash
    same_hash: bool = False
    # human note (never checked by the gate)
    why: str = ""


def E(outcome: Outcome, *, codes: set[str] | None = None,
      notes: set[str] | None = None, verdicts: set[str] | None = None,
      unprovable: set[str] | None = None, same_hash: bool = False,
      why: str = "") -> Expect:
    return Expect(outcome,
                  codes=codes or set(),
                  notes=notes or set(),
                  verdicts=verdicts or set(),
                  unprovable=unprovable or set(),
                  same_hash=same_hash,
                  why=why)


@dataclass
class Inputs:
    """The byte-level inputs that will be handed to Store.ingest."""
    paths: list[Path] = field(default_factory=list)          # directories or files
    raw_batches: list[bytes] = field(default_factory=list)   # already-serialised batches
    anchors: list[bytes] = field(default_factory=list)       # already-serialised anchors

    victim: tuple[str, str] = ("", "")   # (session_id, ws_id) to observe
    baseline: "Inputs | None" = None     # honest version for same_hash checks

    refused: str | None = None           # if agent.open() raised, the message
    integrity_error: bool = False        # scenario build failed (scenario is MISSED)


@dataclass
class Obs:
    """What the case file says about one victim chain."""
    verdict: str
    assurance: str
    suspect: set[str]
    notes: set[str]
    ign: set[str]
    rej: set[str]
    unprov: set[str]
    hash: str                            # Case.hash (for same_hash checks)


class Inapplicable(Exception):
    """Raise from a scenario build function if the scenario cannot run for this seed."""


@dataclass
class Scenario:
    id: str
    group: str
    title: str
    threat: str
    expect: Expect
    build: Callable[["Ctx"], Inputs]     # Ctx defined in scenarios.py
