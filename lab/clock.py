"""clock.py: a fake clock for the tamper lab.

FakeClock patches time.time and time.monotonic for the duration of a
`with installed()` block. It also reaches into every immutable.* submodule
and patches the `time` reference they hold, so agent.py and wal.py see the
same fake clock without any refactoring.

Usage:
    clk = FakeClock(start_wall=1_700_000_000.0)
    with clk.installed():
        # all time.time() calls return clk.wall, all monotonic calls clk.mono
        clk.advance(30)   # move both clocks forward 30 s
"""
from __future__ import annotations

import importlib
import pkgutil
import sys
import time
import types
from contextlib import contextmanager

import immutable


class FakeClock:
    def __init__(self, start_wall: float = 1_700_000_000.0,
                 start_mono: float = 0.0):
        self.wall = start_wall
        self.mono = start_mono
        self._real_time = time.time
        self._real_mono = time.monotonic
        self._real_ns = time.time_ns
        self._patched: list[types.ModuleType] = []

    def advance(self, seconds: float) -> None:
        self.wall += seconds
        self.mono += seconds

    def _fake_time(self) -> float:
        return self.wall

    def _fake_mono(self) -> float:
        return self.mono

    def _fake_ns(self) -> int:
        return int(self.wall * 1_000_000_000)

    @contextmanager
    def installed(self):
        # patch the stdlib time module
        time.time = self._fake_time
        time.monotonic = self._fake_mono
        time.time_ns = self._fake_ns

        # also patch any `import time` references already loaded in immutable.*
        self._patched = []
        pkg_path = immutable.__path__
        pkg_name = immutable.__name__
        for info in pkgutil.walk_packages(pkg_path, prefix=pkg_name + "."):
            mod = sys.modules.get(info.name)
            if mod is None:
                continue
            if hasattr(mod, "time") and isinstance(mod.time, types.ModuleType) \
                    and mod.time is time:
                self._patched.append(mod)
        # time module is already patched in-place so the references are live
        try:
            yield self
        finally:
            time.time = self._real_time
            time.monotonic = self._real_mono
            time.time_ns = self._real_ns
            self._patched.clear()
