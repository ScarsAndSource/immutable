"""coverage.py (B9): how much of this log did an outside holder pin, and how long
was work ever held by the workstation alone?

PINNED PREFIX   the highest position any consistent outside anchor covers. Nothing at
                or below it can be rewritten without conflicting with that anchor.
EXPOSURE        for each batch of events, the span (by the machine's OWN clock
                differences) between its first event and the anchor that first covered
                it. This is how long that work sat only on the workstation. Differences
                are used, not absolute times, so a dead clock battery does not distort it.
ANCHOR GAP      the longest stretch, by the OUTSIDE clock, between consecutive anchors:
                the operational view of "how long was the witness out of touch".

All values are integers (they go into the hashed case file).
"""
from __future__ import annotations


def compute(trunk: list, anchors: list) -> dict:
    n = len(trunk)
    out = {"anchors": 0, "holders": [], "total_events": n, "pinned_events": 0,
           "tail_events": n, "max_unprotected_ms": 0, "windows": 0, "max_anchor_gap_ms": 0}
    outside = [a for a in anchors if a.kind != "receipt" and 0 <= a.upto_seq < n]
    if not outside:
        return out
    seq = sorted(outside, key=lambda a: (a.seen_ms, a.upto_seq, a.holder, a.kind))
    pinned, windows, worst = -1, 0, 0
    for a in seq:
        if a.upto_seq > pinned:
            worst = max(worst, trunk[a.upto_seq].wall_ms - trunk[pinned + 1].wall_ms)
            pinned, windows = a.upto_seq, windows + 1
    out.update({
        "anchors": len(seq), "holders": sorted({a.holder for a in seq}),
        "pinned_events": pinned + 1, "tail_events": n - 1 - pinned,
        "max_unprotected_ms": max(0, worst), "windows": windows,
        "max_anchor_gap_ms": max((b.seen_ms - a.seen_ms for a, b in zip(seq, seq[1:])), default=0),
    })
    return out
