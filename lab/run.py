"""run.py: orchestrate a simulated student session.

Sim     = one Agent session driven by a script of operations
Run     = a Sim plus helpers to produce tampered copies
Played  = the result of a completed Sim (outbox paths, final head, etc.)

Operation script
    Each "op" is a string from the set {"save", "run", "submit", "tick"}.
    make_ops() produces a realistic mix. replay_state() replays a subset of
    ops onto an evidence directory to rebuild state at an arbitrary point.

FILES   = the filenames that saves touch (rotated round-robin)
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import adapter
from .clock import FakeClock
from .world import World

FILES = ("main.py", "util.py", "notes.txt")

_SAVE_CONTENT = {
    "main.py":   b"# main\nprint('hello')\n",
    "util.py":   b"# util\ndef helper(): pass\n",
    "notes.txt": b"scratch notes\n",
}


def make_ops(rng, n: int = 12, *, submit: bool = True) -> list[str]:
    """Return a reproducible list of ops.  Always ends with 'submit' if requested."""
    ops = []
    for i in range(n):
        ops.append(rng.choice(["save", "save", "save", "run", "tick"]))
    if submit:
        ops.append("submit")
    return ops


@dataclass
class Played:
    evidence_dir: Path
    outbox: Path
    session_id: str
    ws_id: str
    final_head: str
    last_seq: int
    submitted: bool


@dataclass
class Run:
    h: adapter.Handle
    ws_dir: Path
    session_id: str
    ws_id: str
    _file_idx: int = 0
    _acked: dict = field(default_factory=dict)   # seq -> Event (from WAL)
    _result: object = None

    @classmethod
    def start(cls, world: World, evidence_dir: Path, *,
              ws_id: str, signer, session_id: str,
              transfer_token: bytes | None = None) -> "Run":
        h = adapter.open_agent(world, evidence_dir, ws_id, signer, session_id,
                               transfer_token=transfer_token)
        ws_dir = evidence_dir.parent / "workspace"
        return cls(h=h, ws_dir=ws_dir, session_id=session_id, ws_id=ws_id)

    def _write_file(self) -> None:
        fname = FILES[self._file_idx % len(FILES)]
        self._file_idx += 1
        content = _SAVE_CONTENT[fname] + f"\n# rev {self._file_idx}\n".encode()
        (self.ws_dir / fname).write_bytes(content)

    def _do_save(self) -> None:
        self._write_file()
        self.h.tick()

    def _do_run(self) -> None:
        # just tick; in a real lab the runner would execute the file
        self.h.tick()

    def _do_tick(self) -> None:
        self.h.tick()

    def play(self, ops: list[str]) -> "Played | None":
        """Execute the operation script. Returns Played only after submit."""
        for op in ops:
            if op == "save":
                self._do_save()
            elif op == "run":
                self._do_run()
            elif op == "tick":
                self._do_tick()
            elif op == "submit":
                self.h.flush()
                res = self.h.submit()
                self._result = res
                outbox = self.h.evidence_dir / "outbox"
                return Played(
                    evidence_dir=self.h.evidence_dir,
                    outbox=outbox,
                    session_id=self.session_id,
                    ws_id=self.ws_id,
                    final_head=res.head,
                    last_seq=res.last_seq,
                    submitted=True,
                )
        # no submit: flush and close
        self.h.flush()
        self.h.close()
        outbox = self.h.evidence_dir / "outbox"
        wal = self.h.evidence_dir / "session.wal"
        last_seq = -1
        head = ""
        if wal.exists():
            from immutable.wal import Wal
            from immutable.fsys import RealFS
            try:
                rec = Wal.recover(RealFS(), str(wal), self.h.agent._wal._w.exam_id,
                                  self.session_id, self.ws_id)
                if rec.wal.events:
                    last_seq = rec.wal.events[-1].seq
                    head = rec.wal.events[-1].hash()
            except Exception:
                pass
        return Played(
            evidence_dir=self.h.evidence_dir,
            outbox=outbox,
            session_id=self.session_id,
            ws_id=self.ws_id,
            final_head=head,
            last_seq=last_seq,
            submitted=False,
        )

    def partial(self) -> dict:
        """Return a seq->Event dict of events acknowledged so far (via WAL)."""
        try:
            evs = self.h.agent._wal.events
            return {e.seq: e for e in evs}
        except Exception:
            return {}


def replay_state(world: World, dst: Path, ops: list[str], *, ws_id: str,
                 signer, session_id: str,
                 clock: FakeClock | None = None) -> Played:
    """Run ops on a fresh evidence directory and return the Played result."""
    dst.mkdir(parents=True, exist_ok=True)
    if clock:
        with clock.installed():
            r = Run.start(world, dst, ws_id=ws_id, signer=signer,
                          session_id=session_id)
            result = r.play(ops)
    else:
        r = Run.start(world, dst, ws_id=ws_id, signer=signer,
                      session_id=session_id)
        result = r.play(ops)
    return result
