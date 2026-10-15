"""clockcheck.py: the only honest questions about time.

The machine writes two clocks into every event: wall time (can be set, stepped or
simply wrong) and boot time (never goes backwards within a boot, keeps counting
through suspend). We only ever judge impossibilities as SUSPECT:
  * boot time going backwards inside one boot
  * a boot id coming back after another boot
Everything else is a NOTE: wall-clock steps, long silences, and offsets against an
outside holder's clock (a dead clock battery shows up as a big constant offset).
Absolute wall time is never judged.

Outside holders give the one hard time fact available: events up to `upto_seq`
existed before the holder's `seen_ms`. That bound is reported, never inflated.

Defaults are placeholders until B8 calibrates them against benign-fault runs.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .anchor import Anchor
from .events import Event
from .findings import Code, Finding


@dataclass(frozen=True)
class ClockPolicy:
    step_note_ms: int = 2_000
    silence_note_ms: int = 300_000
    offset_note_ms: int = 120_000

    def to_dict(self) -> dict:
        return asdict(self)


def check(trunk: list[Event], anchors: list[Anchor], policy: ClockPolicy
          ) -> tuple[list[Finding], dict]:
    f: list[Finding] = []
    info: dict = {"boots": 0, "steps": [], "offsets": [], "longest_silence_ms": 0}
    seen: set[str] = set()
    prev: Event | None = None
    for ev in trunk:
        if prev is None or ev.boot_id != prev.boot_id:
            if ev.boot_id in seen:
                f.append(Finding(Code.BOOT_REVISIT, ev.seq,
                                 "a boot identifier appears again after a different boot"))
            seen.add(ev.boot_id)
            info["boots"] = len(seen)
        else:
            if ev.boot_ns < prev.boot_ns:
                f.append(Finding(Code.CLOCK_BACKWARD, ev.seq,
                                 f"the uptime clock went backwards between events {prev.seq} and {ev.seq}"))
            else:
                dboot = (ev.boot_ns - prev.boot_ns) // 1_000_000
                disc = (ev.wall_ms - prev.wall_ms) - dboot
                if abs(disc) > policy.step_note_ms:
                    way = "forward" if disc > 0 else "back"
                    f.append(Finding(Code.CLOCK_STEP, ev.seq,
                                     f"the wall clock moved {abs(disc)} ms {way} against the uptime clock "
                                     f"between events {prev.seq} and {ev.seq}"))
                    if len(info["steps"]) < 50:
                        info["steps"].append({"seq": ev.seq, "ms": disc})
                if dboot > policy.silence_note_ms:
                    f.append(Finding(Code.SILENCE, ev.seq,
                                     f"no events for {dboot // 1000} s before this one"))
                info["longest_silence_ms"] = max(info["longest_silence_ms"], dboot)
        prev = ev

    for a in anchors:
        off = a.seen_ms - trunk[a.upto_seq].wall_ms
        info["offsets"].append({"upto_seq": a.upto_seq, "holder": a.holder, "offset_ms": off})
        if abs(off) > policy.offset_note_ms:
            side = "behind" if off > 0 else "ahead of"
            f.append(Finding(Code.CLOCK_OFFSET, a.upto_seq,
                             f"the machine's clock is {abs(off) // 1000} s {side} {a.holder}'s clock at this point; "
                             "read this session's times against the outside clock"))
    return f, info
