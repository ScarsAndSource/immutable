"""clock.py: the two clocks every event carries.

Wall time can be set, stepped or wrong (dead RTC battery, NTP). Boot-time cannot
go backwards inside one boot and keeps counting through suspend. An event that
carries both lets the verifier ask the only honest question: do these two agree
within this boot? Absolute wall time is never judged.
"""
from __future__ import annotations

import secrets
import time

_BOOT_ID: str | None = None


def boot_id() -> str:
    """Per-boot identifier. Cached for the life of the process.

    Linux gives us the kernel's. Elsewhere we fall back to a random id per
    process, which is conservative: a process restart then looks like a reboot.
    """
    global _BOOT_ID
    if _BOOT_ID is None:
        try:
            with open("/proc/sys/kernel/random/boot_id") as f:
                _BOOT_ID = f.read().strip().replace("-", "")[:64] or None
        except OSError:
            _BOOT_ID = None
        if _BOOT_ID is None:
            _BOOT_ID = "proc" + secrets.token_hex(12)
    return _BOOT_ID


def boottime_ns() -> int:
    clk = getattr(time, "CLOCK_BOOTTIME", None)
    if clk is not None:
        return time.clock_gettime_ns(clk)
    return time.monotonic_ns()           # Windows/macOS: best effort


def wall_ms() -> int:
    return time.time_ns() // 1_000_000


def stamp() -> tuple[int, int]:
    """(wall_ms, boot_ns), read as close together as we can."""
    return wall_ms(), boottime_ns()
