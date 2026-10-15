"""board.py: the teacher's view of a lab, computed at read time and never stored.

A teacher with 20 to 30 students needs one answer fast: is anyone's machine in trouble,
and is it one machine or the whole room? This module turns raw per-seat facts (from the
witness, or from Supabase) into that answer.

WHAT IT SHOWS
  liveness     active / quiet / offline, from the age of the last contact
  restart      a new boot id appeared: the machine was power-cycled or the agent restarted
  last action  the TYPE of the last FILE_SAVE / RUN_START / RUN_END / SUBMIT and when the
               witness learned of it
  lab-wide     many seats going quiet together (or restarting together) is one incident,
               not many; it is reported once

WHAT IT NEVER SHOWS
  File names, contents, code, hashes, keystrokes, screens. Event TYPES and times only. This
  is the line policy.py draws for the evidence log, enforced here by construction:
  classify() copies named fields, so an extra field in a raw row never reaches the board.

The board states facts about contact, not judgements about the student. Silence has many
causes (power, switch, router, a frozen agent, the witness itself). It never says "cheating"
or even "power cut"; it only separates "same boot" from "new boot". It is not evidence and
nothing here feeds the verifier or the case file.
"""
from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass

ACTIVE, QUIET, OFFLINE, RESTARTED = "active", "quiet", "offline", "restarted"
SUBMITTED, ENDED, UNSUBMITTED = "submitted", "ended", "unsubmitted"
NOT_STARTED, TRANSFERRED = "not_started", "transferred"

# Lower = more urgent = earlier on the board.
SEVERITY = {OFFLINE: 0, UNSUBMITTED: 1, ENDED: 1, QUIET: 2, RESTARTED: 3, ACTIVE: 4,
            NOT_STARTED: 5, SUBMITTED: 6, TRANSFERRED: 7}
STATUSES = tuple(SEVERITY)
LIVE = (ACTIVE, QUIET, OFFLINE, RESTARTED, UNSUBMITTED)

_TYPE_RE = re.compile(r"^[A-Z][A-Z_]{0,31}$")
_REASONS = ("submitted", "timeout", "aborted", "window_end", "grace_expired")


def _int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


@dataclass(frozen=True)
class BoardPolicy:
    ping_every_ms: int = 10_000          # courier default
    active_ms: int = 25_000              # heard within 2.5 pings = active
    offline_ms: int = 60_000             # silent longer than this = offline
    restart_show_ms: int = 300_000       # how long "back after restart" stays on a card
    lab_min_seats: int = 4               # smallest group that can be a lab-wide event
    lab_fraction_pct: int = 60           # ... and it must be this % of the seats still working
    lab_window_ms: int = 45_000          # seats that went quiet within this of each other
    lab_recovery_window_ms: int = 120_000
    window_end_ms: int | None = None     # set when the exam window is known

    def __post_init__(self) -> None:
        if not (0 < self.active_ms < self.offline_ms):
            raise ValueError("need 0 < active_ms < offline_ms")
        if self.lab_min_seats < 2 or not (1 <= self.lab_fraction_pct <= 100):
            raise ValueError("lab-wide thresholds out of range")
        if min(self.ping_every_ms, self.restart_show_ms,
               self.lab_window_ms, self.lab_recovery_window_ms) <= 0:
            raise ValueError("durations must be positive")

    @classmethod
    def from_exam(cls, heartbeat_ms: int, outage_threshold_ms: int,
                  end_ms: int | None = None) -> "BoardPolicy":
        """Derive the limits from an exam config (the Supabase path)."""
        active = heartbeat_ms * 5 // 2
        return cls(ping_every_ms=heartbeat_ms, active_ms=active,
                   offline_ms=max(outage_threshold_ms, active + 1), window_end_ms=end_ms)


# --------------------------------------------------------------------------- classify
def _ev(d: object) -> dict | None:
    if not isinstance(d, dict):
        return None
    t = d.get("type")
    return {"type": t if isinstance(t, str) and _TYPE_RE.match(t) else "UNKNOWN",
            "seen_ms": d.get("seen_ms") if _int(d.get("seen_ms")) else None,
            "wall_ms": d.get("wall_ms") if _int(d.get("wall_ms")) else None}


def _restart(d: object) -> dict | None:
    if isinstance(d, dict) and _int(d.get("seen_ms")):
        gap = d.get("gap_before_ms")
        return {"seen_ms": d["seen_ms"], "gap_before_ms": gap if _int(gap) else None}
    return None


def _budget(d: object) -> dict | None:
    if isinstance(d, dict) and all(_int(d.get(k)) for k in ("used_ms", "remaining_ms", "total_ms")):
        return {"used_ms": d["used_ms"], "remaining_ms": d["remaining_ms"],
                "total_ms": d["total_ms"],
                "outages": d["outages"] if _int(d.get("outages")) else 0}
    return None


def classify(raw: dict, now_ms: int, pol: BoardPolicy) -> dict:
    """One raw per-seat fact row in, one board row out. Copies named fields only."""
    last = raw.get("last_contact_ms")
    last = last if _int(last) else None
    age = None if last is None else max(0, now_ms - last)
    restart = _restart(raw.get("last_restart"))

    if raw.get("transferred"):
        status = TRANSFERRED
    elif raw.get("submitted"):
        status = SUBMITTED
    elif raw.get("ended"):
        status = ENDED
    elif last is None:
        status = NOT_STARTED
    elif age > pol.offline_ms:
        status = OFFLINE
    elif pol.window_end_ms is not None and now_ms > pol.window_end_ms:
        status = UNSUBMITTED
    elif age > pol.active_ms:
        status = QUIET
    elif restart is not None and now_ms - restart["seen_ms"] <= pol.restart_show_ms:
        status = RESTARTED
    else:
        status = ACTIVE

    held, agent = raw.get("held_upto"), raw.get("agent_last_seq")
    waiting = max(0, agent - held) if _int(held) and _int(agent) and status in LIVE else None
    kind = raw.get("last_contact_kind")
    reason = raw.get("end_reason")
    return {
        "key": f"{raw.get('session') or '-'}/{raw['ws']}",
        "ws": raw["ws"], "session": raw.get("session"), "candidate": raw.get("candidate"),
        "status": status, "severity": SEVERITY[status],
        "age_ms": age, "last_contact_ms": last,
        "last_contact_kind": kind if kind in ("ping", "batch") else None,
        "last_action": _ev(raw.get("last_action")), "last_event": _ev(raw.get("last_event")),
        "restarts": int(raw.get("restarts") or 0), "last_restart": restart,
        "held_upto": held if _int(held) else None, "waiting": waiting,
        "events_held": raw.get("events_held") if _int(raw.get("events_held")) else None,
        "contacts": raw.get("contacts") if _int(raw.get("contacts")) else None,
        "end_reason": reason if reason in _REASONS else None,
        "budget": _budget(raw.get("budget")),
        "simulated": bool(raw.get("simulated")),
    }


def _natural(s: str) -> list:
    return [int(p) if i % 2 else p for i, p in enumerate(re.split(r"(\d+)", s))]


# ----------------------------------------------------------------------- lab-wide events
def _cluster(rows: list, key, window: int) -> list:
    """Largest run of rows (sorted ascending by key) whose keys fit inside one window."""
    best: list = []
    j = 0
    for i, r in enumerate(rows):
        while key(r) - key(rows[j]) > window:
            j += 1
        if i - j + 1 > len(best):
            best = rows[j:i + 1]
    return best


def lab_events(seats: list[dict], now_ms: int, pol: BoardPolicy) -> list[dict]:
    """Many seats failing together is one incident about the room, reported once."""
    live = [s for s in seats if s["status"] in LIVE]
    base = len(live)
    out: list[dict] = []

    def big(n: int) -> bool:
        return n >= pol.lab_min_seats and n * 100 >= pol.lab_fraction_pct * base

    stale = sorted((s for s in live if s["age_ms"] is not None and s["age_ms"] > pol.active_ms),
                   key=lambda s: s["last_contact_ms"])
    grp = _cluster(stale, lambda s: s["last_contact_ms"], pol.lab_window_ms)
    if big(len(grp)):
        out.append({"kind": "dropout", "count": len(grp), "of": base,
                    "since_ms": grp[0]["last_contact_ms"], "until_ms": grp[-1]["last_contact_ms"],
                    "ws": [s["ws"] for s in grp]})

    rec = sorted((s for s in live if s.get("last_restart")
                  and now_ms - s["last_restart"]["seen_ms"] <= 3 * pol.restart_show_ms),
                 key=lambda s: s["last_restart"]["seen_ms"])
    grp = _cluster(rec, lambda s: s["last_restart"]["seen_ms"], pol.lab_recovery_window_ms)
    if big(len(grp)):
        out.append({"kind": "recovery", "count": len(grp), "of": base,
                    "since_ms": grp[0]["last_restart"]["seen_ms"],
                    "until_ms": grp[-1]["last_restart"]["seen_ms"],
                    "ws": [s["ws"] for s in grp]})
    return out


def build(raw_seats: list[dict], now_ms: int, pol: BoardPolicy, **meta) -> dict:
    seats = [classify(r, now_ms, pol) for r in raw_seats]
    # Urgent seats first, longest silence first among them. Calm seats keep a stable,
    # natural order so cards do not shuffle on every poll.
    seats.sort(key=lambda s: (s["severity"],
                              -(s["age_ms"] or 0) if s["severity"] <= 2 else 0,
                              _natural(s["ws"])))
    counts = {k: 0 for k in STATUSES}
    for s in seats:
        counts[s["status"]] += 1
    counts["total"] = len(seats)
    return {"v": 1, "now_ms": now_ms, "policy": asdict(pol), "counts": counts,
            "lab": lab_events(seats, now_ms, pol), "seats": seats, **meta}


# --------------------------------------------------------------------------- seat trail
def gaps(ts: list[int], min_gap_ms: int, limit: int = 20) -> list[dict]:
    """Silences between consecutive contacts that were longer than min_gap_ms."""
    out = [{"from_ms": a, "to_ms": b, "gap_ms": b - a}
           for a, b in zip(ts, ts[1:]) if b - a > min_gap_ms]
    return out[-limit:]


def annotate(gap_list: list[dict], boots: list[dict], tol_ms: int = 2_000) -> list[dict]:
    """A silence that ended with a new boot id was a restart; otherwise same boot."""
    starts = [b["seen_ms"] for b in boots[1:]]
    return [{**g, "cause": "restart" if any(abs(t - g["to_ms"]) <= tol_ms for t in starts)
             else "same_boot"} for g in gap_list]


class BoardService:
    """Glue: a source of raw facts (the Witness) plus an optional demo extra."""

    def __init__(self, source, policy: BoardPolicy | None = None, *, extra=None):
        self.source, self.policy, self.extra = source, policy or BoardPolicy(), extra

    def snapshot(self, now_ms: int | None = None, include_extra: bool = True) -> dict:
        raw = self.source.board_raw(now_ms)
        now, rows, sim = raw["now_ms"], list(raw["seats"]), False
        if include_extra and self.extra is not None:
            rows += self.extra.raw(now)
            sim = True
        return build(rows, now, self.policy, source="witness", witness=raw.get("witness"),
                     exam_id=raw.get("exam_id"), has_simulated=sim)

    def seat(self, session: str, ws: str, now_ms: int | None = None) -> dict | None:
        if not session or not ws:
            return None
        if self.extra is not None and self.extra.owns(ws):
            now = self.source.clock_ms() if now_ms is None else now_ms
            trail = self.extra.trail(session, ws, now)
        else:
            trail = self.source.seat_trail(session, ws, min_gap_ms=self.policy.active_ms,
                                           now_ms=now_ms)
        if trail is None:
            return None
        trail["gaps"] = annotate(trail.get("gaps", []), trail.get("boots", []))
        return trail
