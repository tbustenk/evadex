"""Cron parsing + is_due + export format tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from evadex.profiles.schema import Profile
from evadex.profiles.schedule import (
    cron_matches,
    export_cron,
    export_schedule,
    export_windows_task,
    is_due,
    parse_cron,
    write_schedule_to_profile,
)


# ── parse_cron ─────────────────────────────────────────────────────────────


def test_parse_wildcards_cover_full_range():
    spec = parse_cron("* * * * *")
    assert len(spec["minute"]) == 60
    assert len(spec["hour"]) == 24
    assert len(spec["day"]) == 31
    assert len(spec["month"]) == 12
    assert len(spec["weekday"]) == 7


def test_parse_specific_values():
    spec = parse_cron("0 6 * * *")
    assert spec["minute"] == {0}
    assert spec["hour"] == {6}
    assert spec["weekday"] == set(range(0, 7))


@pytest.mark.parametrize("expr", [
    "*/5 * * * *",  # step
    "1-5 * * * *",  # range
    "1,15 * * * *",  # list
])
def test_parse_rejects_complex_expressions(expr):
    with pytest.raises(ValueError):
        parse_cron(expr)


@pytest.mark.parametrize("expr,msg", [
    ("0 6 * *", "5 fields"),            # too few
    ("0 6 * * * *", "5 fields"),        # too many
    ("99 6 * * *", "out of range"),     # bad minute
    ("0 6 99 * *", "out of range"),     # bad day
])
def test_parse_surfaces_clear_errors(expr, msg):
    with pytest.raises(ValueError, match=msg):
        parse_cron(expr)


def test_weekday_sunday_accepts_both_0_and_7():
    assert parse_cron("0 0 * * 0")["weekday"] == {6}
    assert parse_cron("0 0 * * 7")["weekday"] == {6}


# ── cron_matches ───────────────────────────────────────────────────────────


def test_cron_matches_specific_minute_hour():
    # 2026-04-20 06:00 UTC is a Monday.
    t = datetime(2026, 4, 20, 6, 0, tzinfo=timezone.utc)
    assert cron_matches("0 6 * * *", t)
    assert not cron_matches("0 7 * * *", t)
    assert not cron_matches("30 6 * * *", t)


def test_cron_matches_monday_only():
    mon = datetime(2026, 4, 20, 6, 0, tzinfo=timezone.utc)   # Monday
    tue = datetime(2026, 4, 21, 6, 0, tzinfo=timezone.utc)   # Tuesday
    assert cron_matches("0 6 * * 1", mon)
    assert not cron_matches("0 6 * * 1", tue)


# ── is_due ─────────────────────────────────────────────────────────────────


def test_profile_without_schedule_is_never_due():
    p = Profile(name="x", scan={"tool": "siphon-cli"})
    assert not is_due(p)


def test_profile_firing_now_is_due():
    p = Profile(
        name="x",
        scan={"tool": "siphon-cli"},
        schedule={"cron": "0 6 * * *"},
    )
    # Exactly on the minute
    t = datetime(2026, 4, 20, 6, 0, 30, tzinfo=timezone.utc)
    assert is_due(p, now=t, window_minutes=5)


def test_recent_last_run_prevents_reentry():
    p = Profile(
        name="x",
        scan={"tool": "siphon-cli"},
        schedule={"cron": "0 6 * * *"},
        last_run="2026-04-20T06:01:00Z",
    )
    t = datetime(2026, 4, 20, 6, 3, 0, tzinfo=timezone.utc)
    # Cron fired at 06:00, ran at 06:01, now it's 06:03 → within 5-min window,
    # so we must NOT fire again.
    assert not is_due(p, now=t, window_minutes=5)


def test_old_last_run_does_not_prevent_fire():
    p = Profile(
        name="x",
        scan={"tool": "siphon-cli"},
        schedule={"cron": "0 6 * * *"},
        last_run="2026-04-19T06:00:00Z",
    )
    t = datetime(2026, 4, 20, 6, 0, 30, tzinfo=timezone.utc)
    assert is_due(p, now=t, window_minutes=5)


# ── export formats ─────────────────────────────────────────────────────────


def test_export_cron_includes_profile_name():
    p = Profile(
        name="banking-daily",
        scan={"tool": "siphon-cli"},
        schedule={"cron": "0 6 * * *"},
    )
    line = export_cron(p)
    assert line.startswith("0 6 * * *")
    assert "profile run banking-daily" in line


def test_export_cron_without_schedule_errors():
    p = Profile(name="x", scan={"tool": "siphon-cli"})
    with pytest.raises(ValueError, match="no schedule.cron"):
        export_cron(p)


def test_export_windows_task_from_daily_cron():
    p = Profile(
        name="pci-daily",
        scan={"tool": "siphon-cli"},
        schedule={"cron": "15 7 * * *"},
    )
    xml = export_windows_task(p)
    assert "<Task" in xml
    assert "T07:15:00" in xml
    assert "profile run pci-daily" in xml


def test_export_windows_task_from_frequency_time():
    p = Profile(
        name="x",
        scan={"tool": "siphon-cli"},
        schedule={"frequency": "daily", "time": "03:45"},
    )
    xml = export_windows_task(p)
    assert "T03:45:00" in xml


def test_export_windows_task_refuses_weekday_cron():
    p = Profile(
        name="x",
        scan={"tool": "siphon-cli"},
        schedule={"cron": "0 6 * * 1"},
    )
    with pytest.raises(ValueError, match="daily"):
        export_windows_task(p)


def test_export_dispatch_by_format():
    p = Profile(
        name="x",
        scan={"tool": "siphon-cli"},
        schedule={"cron": "0 6 * * *"},
    )
    assert export_schedule(p, "cron").startswith("0 6 * * *")
    assert "<Task" in export_schedule(p, "windows-task")


# ── write_schedule_to_profile ──────────────────────────────────────────────


def test_write_schedule_validates_cron_before_persisting():
    p = Profile(name="x", scan={"tool": "siphon-cli"})
    with pytest.raises(ValueError):
        write_schedule_to_profile(p, "not a cron")


def test_write_schedule_preserves_other_schedule_fields():
    p = Profile(
        name="x",
        scan={"tool": "siphon-cli"},
        schedule={"frequency": "daily", "time": "06:00"},
    )
    updated = write_schedule_to_profile(p, "0 6 * * *")
    assert updated.schedule["cron"] == "0 6 * * *"
    assert updated.schedule["frequency"] == "daily"
