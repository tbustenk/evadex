"""Scheduling support for profiles.

Philosophy: evadex does **not** touch the system scheduler. The
``evadex schedule`` commands manage the ``schedule:`` section of a
profile and emit ready-to-use cron lines or Windows Task Scheduler XML.
Installing the emitted artefact is the user's call — that keeps the
blast radius confined to a single YAML file and avoids giving the tool
root-level side effects it can't test or reverse.

Cron support is minimal on purpose: we parse enough of a 5-field cron
expression to decide whether a schedule is *due* right now, and we
reject expressions with ranges, steps, or lists (``1-5``, ``*/15``,
``1,15``). Users who need those can run the exported cron line through
system cron directly.
"""
from __future__ import annotations

import shlex
import sys
from datetime import datetime, timezone
from typing import Optional
from xml.sax.saxutils import escape

from evadex.profiles.schema import Profile


_CRON_FIELDS = ("minute", "hour", "day", "month", "weekday")

_CRON_RANGES = {
    "minute": (0, 59),
    "hour": (0, 23),
    "day": (1, 31),
    "month": (1, 12),
    # cron weekday 0 = Sunday, 7 also = Sunday, 1-6 = Mon-Sat.
    "weekday": (0, 7),
}


def parse_cron(expr: str) -> dict:
    """Parse a 5-field cron expression into a dict of field → allowed Python values.

    Supports ``*`` and bare integers. Rejects ranges, steps, and lists with
    a :class:`ValueError` — those require real cron.

    Weekday values are stored as Python ``datetime.weekday()`` integers
    (Mon=0..Sun=6) so matching is a straight set membership test.
    """
    if not isinstance(expr, str):
        raise ValueError(f"cron expression must be a string, got {type(expr).__name__}")
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError(
            f"cron expression must have 5 fields, got {len(parts)}: {expr!r}"
        )
    out: dict = {}
    for field, part in zip(_CRON_FIELDS, parts):
        lo, hi = _CRON_RANGES[field]
        if part == "*":
            if field == "weekday":
                out[field] = set(range(0, 7))  # all Python weekdays
            else:
                out[field] = set(range(lo, hi + 1))
            continue
        if any(c in part for c in "-/,"):
            raise ValueError(
                f"evadex cron parser only supports '*' or a single integer per field. "
                f"Got {part!r} in {field!r}. Use system cron for complex expressions."
            )
        try:
            v = int(part)
        except ValueError:
            raise ValueError(f"cron field {field!r} must be an integer or '*', got {part!r}")
        if not (lo <= v <= hi):
            raise ValueError(
                f"cron {field!r} value {v} out of range [{lo}, {hi}]"
            )
        if field == "weekday":
            # cron: Sun=0 or 7, Mon=1, ..., Sat=6  →  Python: Mon=0, ..., Sun=6
            out[field] = {_cron_weekday_to_python(v)}
        else:
            out[field] = {v}
    return out


def _cron_weekday_to_python(v: int) -> int:
    if v in (0, 7):
        return 6  # Sunday
    return v - 1  # Mon..Sat → 0..5


def cron_matches(expr: str, when: datetime) -> bool:
    """Return True if *when* matches the cron *expr*.

    *when* must be timezone-aware or naive-UTC — cron in this module
    operates in UTC to keep behaviour reproducible across machines.
    """
    spec = parse_cron(expr)
    w = when.astimezone(timezone.utc) if when.tzinfo else when.replace(tzinfo=timezone.utc)
    return (
        w.minute in spec["minute"]
        and w.hour in spec["hour"]
        and w.day in spec["day"]
        and w.month in spec["month"]
        and w.weekday() in spec["weekday"]
    )


def is_due(profile: Profile, now: Optional[datetime] = None, window_minutes: int = 5) -> bool:
    """Return True if *profile*'s schedule fires within *window_minutes* of *now*.

    A cron entry firing at ``06:00`` will match any ``run-due`` invocation
    between 06:00 and 06:04 so cron-like polling loops catch the tick even
    if the polling interval drifts. Profiles without a ``schedule.cron`` are
    never due.
    """
    cron = (profile.schedule or {}).get("cron")
    if not cron:
        return False
    now = now or datetime.now(timezone.utc)
    # If last_run is within the window, skip — we already ran this tick.
    last = (profile.last_run or "").strip()
    if last:
        try:
            last_dt = _parse_iso(last)
            if (now - last_dt).total_seconds() < window_minutes * 60:
                return False
        except ValueError:
            pass  # malformed last_run → treat as never run
    base = now.astimezone(timezone.utc).replace(second=0, microsecond=0)
    for offset in range(window_minutes):
        check = datetime.fromtimestamp(base.timestamp() - offset * 60, tz=timezone.utc)
        if cron_matches(cron, check):
            return True
    return False


def _parse_iso(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


# ── Export formats ─────────────────────────────────────────────────────────


def export_cron(profile: Profile, evadex_command: Optional[str] = None) -> str:
    """Emit a cron line that runs ``evadex profile run <name>``.

    *evadex_command* lets callers override the invocation (e.g. use a venv's
    absolute path). When omitted we use ``sys.executable -m evadex``, which
    is what ``evadex profile run`` does internally.
    """
    cron = (profile.schedule or {}).get("cron")
    if not cron:
        raise ValueError(
            f"Profile {profile.name!r} has no schedule.cron — set one before exporting."
        )
    # Sanity-check the cron expression parses (even if we allow ranges in the
    # exported line, since system cron handles them).
    _validate_exportable_cron(cron)

    invoke = evadex_command or f"{_quote(sys.executable)} -m evadex"
    return f"{cron} {invoke} profile run {profile.name}"


def _validate_exportable_cron(expr: str) -> None:
    """Loose validation for exported cron lines — accept any 5-field spec."""
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError(
            f"cron expression must have 5 fields, got {len(parts)}: {expr!r}"
        )


def _quote(path: str) -> str:
    """Quote a path for inclusion in a cron/shell command."""
    return shlex.quote(path)


def export_windows_task(profile: Profile, evadex_command: Optional[str] = None) -> str:
    """Emit a Windows Task Scheduler XML document for *profile*.

    Supported cadences: ``schedule.frequency`` = ``daily`` (uses
    ``schedule.time`` as ``HH:MM`` local) or an explicit ``cron`` with
    a single hour + minute and ``*`` for day/month/weekday, which we
    map to a Daily trigger.
    """
    sched = profile.schedule or {}
    cron = sched.get("cron")
    hour, minute = _extract_daily_hm(sched)
    if (hour, minute) == (None, None) and cron:
        try:
            hm = _cron_to_daily_hm(cron)
        except ValueError as e:
            raise ValueError(
                f"Cannot export Task Scheduler XML for complex cron "
                f"{cron!r}: {e}. Use a daily schedule (frequency: daily, "
                f"time: HH:MM) instead."
            )
        hour, minute = hm
    if hour is None or minute is None:
        raise ValueError(
            f"Profile {profile.name!r} schedule has no exportable trigger. "
            f"Set 'schedule.frequency: daily' + 'schedule.time: HH:MM' or a "
            f"simple daily cron (e.g. '0 6 * * *')."
        )

    start = f"2026-01-01T{hour:02d}:{minute:02d}:00"
    invoke = evadex_command or f'"{sys.executable}" -m evadex profile run {profile.name}'
    description = profile.description or f"evadex profile: {profile.name}"
    return _TASK_SCHEDULER_XML.format(
        description=escape(description),
        start=start,
        argument=escape(invoke),
    )


def _extract_daily_hm(sched: dict) -> tuple[Optional[int], Optional[int]]:
    if sched.get("frequency") != "daily":
        return (None, None)
    t = sched.get("time")
    if not isinstance(t, str) or ":" not in t:
        return (None, None)
    hh, mm = t.split(":", 1)
    try:
        return (int(hh), int(mm))
    except ValueError:
        return (None, None)


def _cron_to_daily_hm(expr: str) -> tuple[int, int]:
    spec = parse_cron(expr)
    if (
        len(spec["minute"]) == 1
        and len(spec["hour"]) == 1
        and spec["day"] == set(range(1, 32))
        and spec["month"] == set(range(1, 13))
        and spec["weekday"] == set(range(0, 7))
    ):
        return (next(iter(spec["hour"])), next(iter(spec["minute"])))
    raise ValueError("cron expression is not a simple daily trigger")


_TASK_SCHEDULER_XML = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{argument}</Command>
    </Exec>
  </Actions>
</Task>
"""


def export_schedule(profile: Profile, fmt: str) -> str:
    """Dispatch to the right exporter. *fmt* is ``cron`` or ``windows-task``."""
    fmt = (fmt or "").lower()
    if fmt == "cron":
        return export_cron(profile)
    if fmt in ("windows-task", "windows_task", "task-scheduler"):
        return export_windows_task(profile)
    raise ValueError(
        f"Unknown schedule format {fmt!r}. Valid: cron, windows-task"
    )


def write_schedule_to_profile(profile: Profile, cron: str) -> Profile:
    """Return a copy of *profile* with ``schedule.cron`` set to *cron*."""
    parse_cron(cron)  # validate before writing
    new_schedule = dict(profile.schedule or {})
    new_schedule["cron"] = cron
    return Profile(
        name=profile.name,
        description=profile.description,
        created=profile.created,
        last_run=profile.last_run,
        scan=profile.scan,
        falsepos=profile.falsepos,
        c2=profile.c2,
        schedule=new_schedule,
        output=profile.output,
        source_path=profile.source_path,
        builtin=profile.builtin,
    )
