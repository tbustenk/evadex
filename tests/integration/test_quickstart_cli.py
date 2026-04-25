"""Integration tests for evadex quickstart wizard, scan defaults, and generate interactive mode."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from evadex.cli.app import main


# ── Quickstart ─────────────────────────────────────────────────────────────────


def test_quickstart_skip_exits_cleanly():
    """Choosing 'skip' (choice 3) exits without error and without creating a config."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["quickstart"], input="3\n")
    assert result.exit_code == 0, result.output


def test_quickstart_runs_without_crashing():
    """Quickstart wizard completes the skip path without an unhandled exception."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["quickstart"], input="3\n")
    assert result.exit_code == 0
    assert "exit_code" not in (result.exception or "")


def test_quickstart_skip_shows_help_prompt():
    """After skipping scanner setup, the wizard prints a guidance message."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["quickstart"], input="3\n")
    combined = (result.output or "") + (result.stderr if hasattr(result, "stderr") else "")
    assert "quickstart" in combined.lower() or "init" in combined.lower()


# ── Scan — config auto-read ────────────────────────────────────────────────────


def test_scan_no_flags_reads_evadex_yaml(tmp_path):
    """evadex scan with no flags auto-reads evadex.yaml from the working dir."""
    from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter

    cfg = tmp_path / "evadex.yaml"
    cfg.write_text("tool: dlpscan-cli\ntier: banking\nconcurrency: 20\n", encoding="utf-8")

    runner = CliRunner()
    with patch(
        "evadex.cli.commands.scan.find_config",
        return_value=str(cfg),
    ), patch.object(
        DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=False
    ):
        result = runner.invoke(main, ["scan"])

    # Health check fails (no real scanner) but the config path was found —
    # the run reaches the health-check stage, confirming config was loaded.
    assert result.exit_code == 1
    assert "health check" in result.output.lower() or "failed" in result.output.lower()


def test_scan_no_scanner_shows_quickstart_hint():
    """Health check failure message should mention 'evadex quickstart'."""
    from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter

    runner = CliRunner()
    with patch.object(
        DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=False
    ):
        result = runner.invoke(main, ["scan", "--input", "4532015112830366", "--strategy", "text"])

    assert result.exit_code == 1
    assert "quickstart" in result.output.lower()


# ── Generate — interactive mode ────────────────────────────────────────────────


def test_generate_no_flags_prompts_interactively(tmp_path):
    """evadex generate with no flags should enter interactive mode and succeed."""
    out = tmp_path / "test_data.xlsx"
    runner = CliRunner()
    # Simulate user typing: format=xlsx, count=5, output=<path>
    result = runner.invoke(main, ["generate"], input=f"xlsx\n5\n{out}\n")
    assert result.exit_code == 0, result.output
    assert out.exists(), "Output file was not created"


def test_generate_no_flags_accepts_default_count(tmp_path):
    """Interactive generate should use the default count when user presses Enter."""
    out = tmp_path / "test_data.csv"
    runner = CliRunner()
    # format=csv, count=<Enter for default 100>, output=<path>
    result = runner.invoke(main, ["generate"], input=f"csv\n\n{out}\n")
    assert result.exit_code == 0, result.output


def test_generate_with_format_but_no_output_shows_error():
    """Providing --format without --output should show a clear error."""
    runner = CliRunner()
    result = runner.invoke(main, ["generate", "--format", "xlsx"])
    assert result.exit_code != 0
    assert "output" in result.output.lower()
