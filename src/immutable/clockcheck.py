"""clockcheck.py: the only honest questions about time.

Every event carries wall time (can be set, stepped or just wrong) and boot time (never
goes backwards inside one boot, counts through suspend). We only call SUSPECT on
impossibilities: boot time going backwards inside a boot, or a boot id returning.
Everything else is a NOTE:
  CLOCK_STEP    one event-to-event jump of wall vs boot time bigger than step_note_ms
  CLOCK_DRIFT   many small discrepancies adding up inside one boot (sustained rate,
                in ppm). Steps already noted are excluded so nothing is double counted.
  SILENCE       a long gap between events
  CLOCK_OFFSET  the machine clock differs from an outside holder's clock

What this cannot see: wall-clock error smaller than step_note_ms per gap AND slower
than drift_note_ppm overall. tools/evaluate.py calibrate states that bound in seconds.
Absolute wall time is never judged. All info values are integers (case file is hashed).
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
    drift_note_ppm: int = 2_000
    drift_min_boot_ms: int = 120_000

    def to_dict(self) -> dict:
        return asdict(self)


def check(trunk: list[Event], anchors: list[Anchor], policy: ClockPolicy
          ) -> tuple[list[Finding], dict]:
    f: list[Finding] = []
    info: dict = {"boots": 0, "steps": [], "offsets": [], "offset_min_ms": None,
                  "offset_max_ms": None, "drift_ppm": [], "longest_silence_ms": 0}
    seen: set[str] = set()
    prev: Event | None = None
    seg_boot = seg_drift = 0
    seg_last = -1

    def close_segment() -> None:
        nonlocal seg_boot, seg_drift
        if seg_boot >= policy.drift_min_boot_ms:
            ppm = seg_drift * 1_000_000 // seg_boot
            info["drift_ppm"].append(ppm)
            if abs(ppm) > policy.drift_note_ppm:
                way = "fast" if ppm > 0 else "slow"
                f.append(Finding(Code.CLOCK_DRIFT, seg_last,
                                 f"the wall clock ran {abs(ppm)} ppm {way} against the uptime clock "
                                 f"over {seg_boot // 1000} s ending here"))
        seg_boot = seg_drift = 0

    for ev in trunk:
        if prev is None or ev.boot_id != prev.boot_id:
            close_segment()
            if ev.boot_id in seen:
                f.append(Finding(Code.BOOT_REVISIT, ev.seq,
                                 "a boot identifier appears again after a different boot"))
            seen.add(ev.boot_id)
            info["boots"] = len(seen)
        elif ev.boot_ns < prev.boot_ns:
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
            else:
                seg_drift += disc
            seg_boot += dboot
            if dboot > policy.silence_note_ms:
                f.append(Finding(Code.SILENCE, ev.seq, f"no events for {dboot // 1000} s before this one"))
            info["longest_silence_ms"] = max(info["longest_silence_ms"], dboot)
        seg_last = ev.seq
        prev = ev
    close_segment()

    for a in anchors:
        off = a.seen_ms - trunk[a.upto_seq].wall_ms
        if info["offset_min_ms"] is None or off < info["offset_min_ms"]:
            info["offset_min_ms"] = off
        if info["offset_max_ms"] is None or off > info["offset_max_ms"]:
            info["offset_max_ms"] = off
        if len(info["offsets"]) < 20:
            info["offsets"].append({"upto_seq": a.upto_seq, "holder": a.holder, "offset_ms": off})
        if abs(off) > policy.offset_note_ms:
            side = "behind" if off > 0 else "ahead of"
            f.append(Finding(Code.CLOCK_OFFSET, a.upto_seq,
                             f"the machine's clock is {abs(off) // 1000} s {side} {a.holder}'s clock "
                             "at this point; read this session's times against the outside clock"))
    return f, info
