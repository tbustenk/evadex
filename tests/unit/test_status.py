"""Unit tests for evadex status command."""

import json
import pytest
from click.testing import CliRunner
from unittest.mock import patch

from evadex.cli.app import main
from evadex.cli.commands.status import _human_age, _bridge_status


# ── _human_age ─────────────────────────────────────────────────────────────────

def test_human_age_seconds():
    from datetime import datetime, timezone, timedelta
    ts = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
    result = _human_age(ts)
    assert "s ago" in result


def test_human_age_hours():
    from datetime import datetime, timezone, timedelta
    ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    result = _human_age(ts)
    assert "h ago" in result


def test_human_age_days():
    from datetime import datetime, timezone, timedelta
    ts = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    result = _human_age(ts)
    assert "d ago" in result


def test_human_age_invalid_returns_unknown():
    result = _human_age("not-a-timestamp")
    assert result == "unknown"


# ── CLI ────────────────────────────────────────────────────────────────────────

def test_status_runs_without_error():
    runner = CliRunner()
    with patch("evadex.cli.commands.status._bridge_status", return_value=(False, "http://localhost:8081")):
        result = runner.invoke(main, ["status"])
    assert result.exit_code == 0


def test_status_json_output():
    runner = CliRunner()
    with patch("evadex.cli.commands.status._bridge_status", return_value=(False, "http://localhost:8081")):
        result = runner.invoke(main, ["status", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "version" in data
    assert "scanner_label" in data
    assert "cache_entries" in data
    assert "bridge_reachable" in data
