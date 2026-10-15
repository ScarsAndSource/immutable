"""rules.py: what an unmodified agent can and cannot have written.

Every rule here is an impossibility or a protocol break, not a hunch. Benign faults
(a restart, a crash mid-run) only ever produce NOTEs.
"""
from __future__ import annotations

from . import hashing, merkle
from .events import Event
from .findings import Code, Finding
from .roster import Roster

_AFTER_SUBMIT = frozenset({"RECOVERY", "BOOT", "HEARTBEAT", "CHECKPOINT", "SESSION_END"})


def check(trunk: list[Event], roster: Roster) -> tuple[list[Finding], dict]:
    f: list[Finding] = []
    stats: dict = {"checkpoints_ok": 0, "saves_at_submit": None, "events": {}}
    saves: dict[str, str] = {}
    hashes: list[str] = []
    open_run: int | None = None
    ended = submitted = False
    last_boot: str | None = None
    transfers = 0
    counts: dict[str, int] = {}

    def add(code: Code, ev: Event, detail: str) -> None:
        f.append(Finding(code, ev.seq, detail))

    for i, ev in enumerate(trunk):
        t, d = ev.type, ev.data
        counts[t] = counts.get(t, 0) + 1

        if i == 0 and t != "SESSION_START":
            add(Code.BAD_START, ev, "the log does not open with SESSION_START")
        if i > 0 and t == "SESSION_START":
            add(Code.BAD_START, ev, "a second SESSION_START appears in the same log")
        if ended:
            add(Code.EVENT_AFTER_END, ev, f"{t} appears after SESSION_END")
        elif submitted and t not in _AFTER_SUBMIT:
            add(Code.EVENT_AFTER_SUBMIT, ev, f"{t} appears after SUBMIT")
        if last_boot is not None and ev.boot_id != last_boot and t != "RECOVERY":
            add(Code.BOOT_UNMARKED, ev, "the machine changed boot without a recovery record")
        last_boot = ev.boot_id

        if t == "SESSION_START":
            if d["roster_sha256"] == hashing.ZERO:
                add(Code.ROSTER_MISMATCH, ev, "the session started without a roster check, so it is not tied to the enrolled seat list")
            elif d["roster_sha256"] != roster.id:
                add(Code.ROSTER_MISMATCH, ev, "the session started against a different roster than the one issued for this exam")
            if d["paper_sha256"] != roster.paper_sha256:
                add(Code.PAPER_MISMATCH, ev, "the exam paper recorded at the start is not the one the roster was issued for")
        elif t == "FILE_SAVE":
            saves[d["path"]] = d["sha256"]
        elif t == "RUN_START":
            if saves.get(d["path"]) != d["sha256"]:
                add(Code.RUN_UNSAVED, ev, f"a run of {d['path']} used contents with no matching recorded save")
            if open_run is not None:
                f.append(Finding(Code.RUN_OPEN, open_run, "a program run started here has no recorded end"))
            open_run = ev.seq
        elif t == "RUN_END":
            if open_run is None:
                add(Code.RUN_ORPHAN, ev, "a program run ended that never started")
            open_run = None
        elif t == "CHECKPOINT":
            ok = d["upto_seq"] == ev.seq - 1 and \
                merkle.root(hashes[: d["upto_seq"] + 1]) == d["merkle_root"]
            if ok:
                stats["checkpoints_ok"] += 1
            else:
                add(Code.CHECKPOINT_BAD, ev, f"checkpoint claims to cover events up to {d['upto_seq']} but does not match them")
        elif t == "RECOVERY":
            if d["last_good_seq"] != ev.seq - 1:
                add(Code.RECOVERY_INCONSISTENT, ev, f"recovery claims the log ended at {d['last_good_seq']} but sits at {ev.seq}")
            if open_run is not None:
                f.append(Finding(Code.RUN_OPEN, open_run, "a program run started here was cut off by a restart"))
                open_run = None
            f.append(Finding(Code.RECOVERED, ev.seq,
                             f"the agent restarted; {d['discarded_bytes']} bytes of unacknowledged data were dropped"))
        elif t == "TRANSFER":
            transfers += 1
            if transfers > 1:
                add(Code.TRANSFER_INVALID, ev, "more than one transfer in the same log")
        elif t == "SUBMIT":
            submitted = True
            stats["saves_at_submit"] = dict(saves)
        elif t == "SESSION_END":
            ended = True
        hashes.append(ev.hash())

    if open_run is not None and not ended:
        f.append(Finding(Code.RUN_OPEN, open_run, "a program run started here has no recorded end"))
    stats["events"] = dict(sorted(counts.items()))
    return f, stats
