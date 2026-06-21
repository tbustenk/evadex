"""Unit tests for `evadex benchmark` internals."""
from __future__ import annotations

import statistics

import pytest

from evadex.cli.commands.benchmark import _RunStats


# ── _RunStats dataclass ───────────────────────────────────────────────────────

def test_run_stats_avg_empty_returns_zero():
    s = _RunStats(label="test")
    assert s.avg() == 0.0


def test_run_stats_avg_single_value():
    s = _RunStats(label="test", times=[2.5])
    assert s.avg() == 2.5


def test_run_stats_avg_multiple_values():
    s = _RunStats(label="test", times=[1.0, 2.0, 3.0])
    assert s.avg() == pytest.approx(2.0)


def test_run_stats_stdev_single_value_returns_zero():
    s = _RunStats(label="test", times=[1.0])
    assert s.stdev() == 0.0


def test_run_stats_stdev_multiple_values():
    s = _RunStats(label="test", times=[1.0, 2.0, 3.0])
    expected = statistics.pstdev([1.0, 2.0, 3.0])
    assert s.stdev() == pytest.approx(expected)
