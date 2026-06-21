"""Unit tests for `evadex ci` — CI/CD quality gate command."""
from __future__ import annotations

import json
from subprocess import CompletedProcess
from unittest.mock import patch

from click.testing import CliRunner

from evadex.cli.app import main


def _make_proc(
    pass_rate: float = 35.0,
    fp_rate: float = 5.0,
    returncode: int = 0,
    stdout: bytes | None = None,
) -> CompletedProcess:
    if stdout is None:
        data = json.dumps(
            {"meta": {"pass_rate": pass_rate, "false_positive_rate": fp_rate}}
        ).encode()
    else:
        data = stdout
    return CompletedProcess(args=[], returncode=returncode, stdout=data, stderr=b"")


def _invoke_ci(args: list[str]) -> object:
    runner = CliRunner()
    with runner.isolated_filesystem():
        return runner.invoke(main, ["ci", *args])


# ── Exit-code contract ────────────────────────────────────────────────────────


def test_ci_exits_0_when_detection_meets_threshold():
    with patch("evadex.cli.commands.ci.subprocess.run", return_value=_make_proc(pass_rate=35.0)):
        result = _invoke_ci(["--min-detection", "30"])
    assert result.exit_code == 0


def test_ci_exits_1_when_detection_below_threshold():
    with patch("evadex.cli.commands.ci.subprocess.run", return_value=_make_proc(pass_rate=20.0)):
        result = _invoke_ci(["--min-detection", "30"])
    assert result.exit_code == 1


def test_ci_exits_2_when_subprocess_throws():
    with patch("evadex.cli.commands.ci.subprocess.run", side_effect=OSError("no such file")):
        result = _invoke_ci(["--min-detection", "30"])
    assert result.exit_code == 2


def test_ci_exits_2_when_subprocess_returns_error_code():
    proc = _make_proc(returncode=127)
    with patch("evadex.cli.commands.ci.subprocess.run", return_value=proc):
        result = _invoke_ci(["--min-detection", "30"])
    assert result.exit_code == 2


def test_ci_exits_2_when_stdout_empty():
    proc = _make_proc(returncode=0, stdout=b"")
    with patch("evadex.cli.commands.ci.subprocess.run", return_value=proc):
        result = _invoke_ci(["--min-detection", "30"])
    assert result.exit_code == 2


def test_ci_exits_2_when_stdout_is_not_json():
    proc = _make_proc(returncode=0, stdout=b"not json at all")
    with patch("evadex.cli.commands.ci.subprocess.run", return_value=proc):
        result = _invoke_ci(["--min-detection", "30"])
    assert result.exit_code == 2


def test_ci_exits_1_when_fp_rate_exceeds_max():
    with patch(
        "evadex.cli.commands.ci.subprocess.run",
        return_value=_make_proc(pass_rate=40.0, fp_rate=25.0),
    ):
        result = _invoke_ci(["--min-detection", "30", "--max-fp", "20"])
    assert result.exit_code == 1


def test_ci_exits_0_when_fp_rate_within_limit():
    with patch(
        "evadex.cli.commands.ci.subprocess.run",
        return_value=_make_proc(pass_rate=40.0, fp_rate=10.0),
    ):
        result = _invoke_ci(["--min-detection", "30", "--max-fp", "20"])
    assert result.exit_code == 0


def test_ci_passes_tier_to_scan_command():
    captured: dict = {}

    def _capture(cmd, **kwargs):
        captured["cmd"] = cmd
        return _make_proc()

    with patch("evadex.cli.commands.ci.subprocess.run", side_effect=_capture):
        _invoke_ci(["--tier", "core", "--min-detection", "10"])

    assert "--tier" in captured["cmd"]
    assert "core" in captured["cmd"]


def test_ci_fast_flag_forwarded():
    captured: dict = {}

    def _capture(cmd, **kwargs):
        captured["cmd"] = cmd
        return _make_proc()

    with patch("evadex.cli.commands.ci.subprocess.run", side_effect=_capture):
        _invoke_ci(["--fast", "--min-detection", "10"])

    assert "--fast" in captured["cmd"]
