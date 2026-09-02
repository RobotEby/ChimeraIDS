from collections import deque

from base.baseline_dynamic_store import calc_stats, corta


def test_corta_removes_entries_older_than_cutoff():
    dq = deque([(0.0, 1), (5.0, 1), (10.0, 1), (15.0, 1)])
    corta(dq, 10.0)
    assert list(dq) == [(10.0, 1), (15.0, 1)]


def test_corta_leaves_deque_untouched_when_nothing_expired():
    dq = deque([(10.0, 1), (15.0, 1)])
    corta(dq, 5.0)
    assert list(dq) == [(10.0, 1), (15.0, 1)]


def test_corta_handles_empty_deque():
    dq = deque()
    corta(dq, 100.0)
    assert list(dq) == []


def test_calc_stats_with_no_samples_returns_zero():
    assert calc_stats(deque()) == (0.0, 0.0)


def test_calc_stats_with_one_sample_returns_zero_stdev():
    # A single sample has no defined stdev, so this returns (0.0, 0.0)
    # rather than raising, matching the original single-file behavior.
    assert calc_stats(deque([(0.0, 42)])) == (0.0, 0.0)


def test_calc_stats_computes_mean_and_stdev():
    dq = deque([(0.0, 2), (1.0, 4), (2.0, 4), (3.0, 4), (4.0, 5), (5.0, 5), (6.0, 7), (7.0, 9)])
    mean, stdev = calc_stats(dq)
    assert mean == 5.0
    assert round(stdev, 4) == 2.1381
