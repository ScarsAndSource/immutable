"""adapter.py: the only file in the lab that knows how agent.py is built.

All coupling to Agent internals lives here. Every other lab file goes through
the Handle returned by open_agent().

FLUSH auto-detection: the lab needs to force a batch-seal so evidence appears
in the outbox. Agent.flush() is the right method; we find it by name.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from immutable.agent import Agent
from immutable.wal import Wal

# Methods tried in order when looking for the flush / seal operation.
FLUSH_CANDIDATES = (
    "flush", "_flush",
    "cut_batch", "_cut_batch",
    "ship", "_ship",
    "checkpoint", "_checkpoint",
)
CHECKPOINT_EVERY = 8
HEARTBEAT_S = 3600  # effectively disable automatic heartbeats during lab runs


@dataclass
class Handle:
    agent: Agent
    evidence_dir: Path

    def flush(self) -> None:
        """Force all durable events into the outbox as signed batches."""
        for name in FLUSH_CANDIDATES:
            fn = getattr(self.agent, name, None)
            if callable(fn):
                fn()
                return
        raise RuntimeError(
            "Cannot find a flush/seal method on Agent. "
            f"Tried: {FLUSH_CANDIDATES}. "
            "Set FLUSH in lab/adapter.py."
        )

    def tick(self) -> None:
        """Advance the agent's observation loop by one tick."""
        if callable(getattr(self.agent, "tick", None)):
            self.agent.tick()

    def submit(self):
        """Submit the session and return the SubmitResult."""
        return self.agent.submit()

    def close(self) -> None:
        """Close the agent cleanly (no submit)."""
        if callable(getattr(self.agent, "close", None)):
            self.agent.close()


def open_agent(world, evidence_dir: Path, ws_id: str, signer,
               session_id: str,
               transfer_token: bytes | None = None) -> Handle:
    """Open an Agent for one seat in the lab world."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    # workspace dir: a sibling of evidence
    ws_dir = evidence_dir.parent / "workspace"
    ws_dir.mkdir(parents=True, exist_ok=True)

    agent = Agent.open(
        evidence_dir=evidence_dir,
        workspace=ws_dir,
        exam_id=world.exam,
        session_id=session_id,
        ws_id=ws_id,
        signer=signer,
        paper_sha256=world.paper_sha,
        roster_sha256=world.roster.id,
        heartbeat_s=HEARTBEAT_S,
        checkpoint_every=CHECKPOINT_EVERY,
        transfer_token=transfer_token,
        assessor_pub=world.assessor.pub_hex if transfer_token else None,
    )
    return Handle(agent, evidence_dir)


def flush(h: Handle) -> None:
    """Convenience: force outbox seal on a Handle."""
    h.flush()


def find_wal(evidence_dir: Path) -> Path:
    """Return the WAL file path for an evidence directory."""
    return evidence_dir / "session.wal"


def describe(agent: Agent) -> Iterator[str]:
    """Yield human-readable lines describing the agent's public API."""
    for name in sorted(dir(agent)):
        if name.startswith("__"):
            continue
        obj = getattr(agent, name)
        if callable(obj):
            yield f"method  {name}"
        elif not name.startswith("_"):
            yield f"attr    {name} = {obj!r}"
