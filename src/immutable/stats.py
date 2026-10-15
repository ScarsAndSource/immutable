"""stats.py: honest numbers from small counts. No scipy."""
from __future__ import annotations

import math


def _cdf(k: int, n: int, p: float) -> float:
    total = 0.0
    for i in range(k + 1):
        total += math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                          + i * math.log(p) + (n - i) * math.log1p(-p))
    return total


def upper_bound(k: int, n: int, alpha: float = 0.05) -> float:
    """One-sided Clopper-Pearson upper bound: with confidence 1-alpha the true rate is
    below this, given k events in n independent trials. k=0 gives 1 - alpha**(1/n),
    the 'rule of three' (about 3/n)."""
    if n <= 0 or k >= n:
        return 1.0
    lo, hi = k / n, 1.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if mid <= 0:
            lo = mid
        elif _cdf(k, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi


def percentile(values: list, q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, max(0, math.ceil(q * len(s)) - 1))]
