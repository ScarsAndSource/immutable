"""board_demo.py: a simulated class for demos of the teacher board.

NOT EVIDENCE. Every row carries simulated=True, the board tags those seats, and nothing
here touches the witness, the store or any log. It is a deterministic script over a 9-minute
loop so a demo can show, on cue: a lab-wide switch failure (same boot), one machine being
power-cycled, a lab-wide power cut with restarts, one frozen machine, three submissions and
one no-show.
"""
from __future__ import annotations

import time

PING_MS = 10_000
BOOT_S = 12                      # seconds a power-cycled machine takes to come back
CYCLE_S = 540
ACTIONS = ("FILE_SAVE", "RUN_START", "RUN_END", "FILE_SAVE", "FILE_SAVE")
SUBMIT_AT = {2: 360, 14: 420, 20: 480}


def _merge(spans: list[tuple]) -> list[tuple]:
    out: list[tuple] = []
    for a, b, r in sorted(spans):
        if out and a <= out[-1][1]:
            pa, pb, pr = out[-1]
            out[-1] = (pa, max(pb, b), pr or r)
        else:
            out.append((a, b, r))
    return out


class SimClass:
    def __init__(self, n: int = 27, t0_ms: int | None = None):
        self.n = n
        self.t0 = int(time.time() * 1000) if t0_ms is None else t0_ms
        self._dark = [self._spans(i) for i in range(n)]

    def _spans(self, i: int) -> list[tuple]:
        s: list[tuple] = []
        if i % 9 != 0:
            s.append((90, 150, False))                  # lab-wide switch failure, same boot
        if i % 3 != 0:
            s.append((240, 300 + BOOT_S, True))         # lab-wide power cut, then restart
        if i == 5:
            s.append((120, 200 + BOOT_S, True))         # one machine power-cycled
        if i == 11:
            s.append((60, 100, False))                  # a network blip
        if i == 7:
            s.append((400, CYCLE_S + 60, False))        # frozen: silent to the end of the loop
        return _merge(s)

    # -- identity
    def _index(self, ws: str) -> int | None:
        if not (isinstance(ws, str) and ws.startswith("SIM-")):
            return None
        try:
            i = int(ws[4:]) - 1
        except ValueError:
            return None
        return i if 0 <= i < self.n else None

    def owns(self, ws: str) -> bool:
        return self._index(ws) is not None

    def _clock(self, now_ms: int) -> tuple[int, float]:
        ph = (now_ms - self.t0) % (CYCLE_S * 1000)
        return now_ms - ph, ph / 1000.0

    # -- rows
    def raw(self, now_ms: int) -> list[dict]:
        start, e = self._clock(now_ms)
        return [self._seat(i, start, e) for i in range(self.n)]

    def _seat(self, i: int, start: int, e: float) -> dict:
        ws, ses = f"SIM-{i + 1:02d}", f"SIM-S{i + 1:02d}"
        base = {"session": ses, "ws": ws, "candidate": f"CNTR-{9000 + i}",
                "enrolled": True, "simulated": True}
        if i == self.n - 1:                              # the no-show
            return {**base, "session": None, "events_held": 0, "held_upto": -1}
        sub = SUBMIT_AT.get(i)
        if sub is not None and e >= sub:
            t = start + sub * 1000
            return {**base, "events_held": 40 + i, "held_upto": 39 + i, "contacts": 60,
                    "first_contact_ms": start, "last_contact_ms": t, "last_contact_kind": "batch",
                    "restarts": 0, "last_restart": None, "submitted": True, "ended": True,
                    "end_reason": "submitted",
                    "last_action": {"type": "SUBMIT", "seen_ms": t, "wall_ms": t},
                    "last_event": {"type": "SESSION_END", "seq": 40 + i, "seen_ms": t, "wall_ms": t}}
        off = (i * 1337) % PING_MS
        dark = next((s for s in self._dark[i] if s[0] <= e < s[1]), None)
        if dark:
            eff = dark[0] - off / 1000.0                 # last contact just before it went dark
        else:
            eff = e - ((e * 1000 - off) % PING_MS) / 1000.0
        done = [s for s in self._dark[i] if s[2] and s[1] <= e]
        last = start + int(eff * 1000)
        restart = None
        if done:
            seen = start + done[-1][1] * 1000
            restart = {"seen_ms": seen, "gap_before_ms": (done[-1][1] - done[-1][0]) * 1000}
            if not dark:
                last = max(last, seen)
        step = 25 + i % 13
        bucket = int(eff // step)
        act_t = start + bucket * step * 1000
        held = int(eff // 7) + 3
        waiting = (3 + i % 5) if dark else (i % 3)
        ev = {"type": "HEARTBEAT", "seq": held, "seen_ms": last, "wall_ms": last}
        if restart and not dark and e - done[-1][1] < 20:
            ev["type"] = "BOOT"
        return {**base, "events_held": held + 1, "held_upto": held, "agent_last_seq": held + waiting,
                "contacts": int(eff // 10), "first_contact_ms": start, "last_contact_ms": last,
                "last_contact_kind": "ping", "restarts": len(done), "last_restart": restart,
                "last_action": {"type": ACTIONS[(bucket + i) % len(ACTIONS)],
                                "seen_ms": act_t, "wall_ms": act_t},
                "last_event": ev}

    # -- detail drawer
    def trail(self, session: str, ws: str, now_ms: int) -> dict | None:
        i = self._index(ws)
        if i is None or i == self.n - 1:
            return None
        start, e = self._clock(now_ms)
        off = (i * 1337) % PING_MS / 1000.0
        spans = [s for s in self._dark[i] if s[1] <= e]
        gap_rows = [{"from_ms": start + int((a - off) * 1000), "to_ms": start + int(b * 1000),
                     "gap_ms": int((b - a + off) * 1000)} for a, b, _ in spans]
        boots = [{"seen_ms": start, "gap_before_ms": None, "first_seq": 0}]
        boots += [{"seen_ms": start + int(b * 1000), "gap_before_ms": int((b - a) * 1000),
                   "first_seq": 0} for a, b, r in spans if r]
        return {"session": session, "ws": ws, "candidate": f"CNTR-{9000 + i}", "now_ms": now_ms,
                "contacts_seen": int(e // 10), "first_contact_ms": start, "gaps": gap_rows,
                "boots": boots, "longest_gap_ms": max((g["gap_ms"] for g in gap_rows), default=0)}
