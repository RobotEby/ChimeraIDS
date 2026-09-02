"""
Shared, in-memory dynamic baseline store for the rule-based detection engine.

This holds the sliding-window counters (packets/sec, bytes/sec, unique
destination ports, SYN-without-ACK counts) keyed by source IP, plus the two
small helper functions used to maintain and summarize them:

- `corta` (trim): drops entries older than the sliding window from a deque
  of `(timestamp, value)` pairs.
- `calc_stats`: returns `(mean, stdev)` for the values currently in the
  window. With fewer than 2 samples, stdev is undefined, so both `mean` and
  `stdev` are treated as `0.0`.

Previously, `rules/rules_detection_engine.py` imported `pps`, `bps`, `uniq`,
`syn_counter`, `μ_pps`, `σ_pps`, `μ_uniq`, `σ_uniq` from itself — none of
those names were ever defined anywhere in the codebase, so importing that
module raised an ImportError. The real baseline-tracking logic only existed
inside the standalone `examples/mini_ids.py` script. This module extracts
that logic into a real, shared, importable place so the "modular" rule
engine can actually use it instead of referencing undefined names.
"""

import statistics
from collections import defaultdict, deque

# Learning/window size, in seconds, for the sliding-window baseline.
JANELA_SEGUNDOS = 60

baseline = {
    # packets per second, per source IP: deque of (timestamp, 1)
    "pps": defaultdict(deque),
    # bytes per second, per source IP: deque of (timestamp, packet_len)
    "bps": defaultdict(deque),
    # unique destination ports seen in the current window, per source IP:
    # deque of (timestamp, port) so it can be time-trimmed the same way as
    # pps/bps (a bare growing set, as used originally, never shrinks, which
    # made port-scan detection structurally unable to fire — see
    # rules/rules_detection_engine.py for details).
    "uniq": defaultdict(deque),
}

# Consecutive SYN-without-ACK counter, per source IP (reset on any ACK).
syn_counter = defaultdict(int)


def corta(dq, limite):
    """Drop entries from the left of `dq` whose timestamp is older than `limite`."""
    while dq and dq[0][0] < limite:
        dq.popleft()


def calc_stats(dq):
    """Return (mean, stdev) of the values in a deque of (timestamp, value) pairs."""
    vals = [v for _, v in dq]
    if len(vals) > 1:
        return statistics.mean(vals), statistics.stdev(vals)
    return 0.0, 0.0
