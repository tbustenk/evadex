"""Integration tests for evadex config file feature."""

import json
import os
import pytest
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import patch, AsyncMock
from evadex.cli.app import main
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory
from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter


def _mock_result():
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")
    v = Variant("4532015112830366", "structural", "no_delimiter", "No delimiter", strategy="text")
    return ScanResult(payload=p, variant=v, detected=True, duration_ms=5.0)


def _invoke_scan(runner, extra_args, mock_results=None):
    """Run 'evadex scan' with a mocked Engine and health check."""
    if mock_results is None:
        mock_results = [_mock_result()]
    with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = mock_results
        return runner.invoke(main, ["scan"] + extra_args, catch_exceptions=False)


# ── evadex init ───────────────────────────────────────────────────────────────

def test_init_creates_config(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["init"])
        created = Path("evadex.yaml")
        assert result.exit_code == 0, result.output
        assert created.exists()


def test_init_file_content_is_valid_yaml(tmp_path):
    from evadex.config import load_config
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        runner.invoke(main, ["init"])
        cfg = load_config(Path("evadex.yaml"))
    assert cfg.tool == "dlpscan-cli"
    assert cfg.format == "json"


def test_init_errors_if_file_already_exists(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path("evadex.yaml").write_text("tool: dlpscan-cli\n", encoding="utf-8")
        result = runner.invoke(main, ["init"])
        assert result.exit_code != 0


# ── --config flag ─────────────────────────────────────────────────────────────

def test_config_flag_loads_values(tmp_path):
    """Config file values (scanner_label, output) are used when not passed on CLI."""
    cfg_file = tmp_path / "evadex.yaml"
    out_file = tmp_path / "out.json"
    cfg_file.write_text(
        f"scanner_label: test-scanner\noutput: {out_file}\nstrategy: text\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = _invoke_scan(runner, ["--config", str(cfg_file), "--input", "4532015112830366"])
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["meta"]["scanner"] == "test-scanner"


def test_cli_flag_overrides_config(tmp_path):
    """CLI --scanner-label wins over config scanner_label."""
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text("scanner_label: from-config\nstrategy: text\n", encoding="utf-8")
    out_file = tmp_path / "out.json"
    runner = CliRunner()
    result = _invoke_scan(runner, [
        "--config", str(cfg_file),
        "--input", "4532015112830366",
        "--scanner-label", "from-cli",
        "--output", str(out_file),
    ])
    assert result.exit_code == 0, result.output
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["meta"]["scanner"] == "from-cli"


def test_cli_concurrency_overrides_config(tmp_path):
    """CLI --concurrency wins over config concurrency."""
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text("concurrency: 1\nstrategy: text\n", encoding="utf-8")
    runner = CliRunner()
    captured_concurrency = []
    original_engine_init = None

    import evadex.cli.commands.scan as scan_mod

    class CapturingEngine:
        def __init__(self, **kwargs):
            captured_concurrency.append(kwargs.get("concurrency"))
            self._results = [_mock_result()]
        def run(self, payloads):
            return self._results

    with patch("evadex.cli.commands.scan.Engine", CapturingEngine), \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        runner.invoke(main, [
            "scan",
            "--config", str(cfg_file),
            "--input", "4532015112830366",
            "--concurrency", "8",
        ], catch_exceptions=False)

    assert captured_concurrency == [8]


def test_config_concurrency_used_when_no_cli_flag(tmp_path):
    """Config concurrency is used when --concurrency is not on CLI."""
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text("concurrency: 3\nstrategy: text\n", encoding="utf-8")
    captured_concurrency = []

    class CapturingEngine:
        def __init__(self, **kwargs):
            captured_concurrency.append(kwargs.get("concurrency"))
            self._results = [_mock_result()]
        def run(self, payloads):
            return self._results

    runner = CliRunner()
    with patch("evadex.cli.commands.scan.Engine", CapturingEngine), \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        runner.invoke(main, [
            "scan",
            "--config", str(cfg_file),
            "--input", "4532015112830366",
        ], catch_exceptions=False)

    assert captured_concurrency == [3]


# ── --audit-log ───────────────────────────────────────────────────────────────

def test_audit_log_cli_flag_creates_file(tmp_path):
    """--audit-log writes one JSON line per scan."""
    log_file = tmp_path / "audit.jsonl"
    result = _invoke_scan(runner=CliRunner(), extra_args=[
        "--input", "4532015112830366",
        "--strategy", "text",
        "--audit-log", str(log_file),
    ])
    assert result.exit_code == 0, result.output
    assert log_file.exists()
    record = json.loads(log_file.read_text(encoding="utf-8"))
    assert record["tool"] == "dlpscan-cli"
    assert record["total"] >= 1
    assert "timestamp" in record
    assert "operator" in record


def test_audit_log_appends_across_runs(tmp_path):
    """Two successive scans produce two lines in the same file."""
    log_file = tmp_path / "audit.jsonl"
    runner = CliRunner()
    for _ in range(2):
        _invoke_scan(runner, [
            "--input", "4532015112830366",
            "--strategy", "text",
            "--audit-log", str(log_file),
        ])
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert all(json.loads(l)["tool"] == "dlpscan-cli" for l in lines)


def test_audit_log_from_config_file(tmp_path):
    """audit_log key in evadex.yaml is respected."""
    log_file = tmp_path / "audit.jsonl"
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text(
        f"strategy: text\naudit_log: {log_file}\n", encoding="utf-8"
    )
    result = _invoke_scan(runner=CliRunner(), extra_args=[
        "--input", "4532015112830366",
        "--config", str(cfg_file),
    ])
    assert result.exit_code == 0, result.output
    assert log_file.exists()


def test_audit_log_records_exit_code_1_on_gate_failure(tmp_path):
    """exit_code in the audit entry reflects the --min-detection-rate outcome."""
    log_file = tmp_path / "audit.jsonl"
    result = _invoke_scan(runner=CliRunner(), extra_args=[
        "--input", "4532015112830366",
        "--strategy", "text",
        "--min-detection-rate", "101",   # impossible threshold → always fails
        "--audit-log", str(log_file),
    ])
    assert result.exit_code == 1
    record = json.loads(log_file.read_text(encoding="utf-8"))
    assert record["exit_code"] == 1
    assert record["min_detection_rate"] == 101.0


def test_audit_log_silent_on_bad_path():
    """A write failure must not propagate — scan exit code must be 0."""
    result = _invoke_scan(runner=CliRunner(), extra_args=[
        "--input", "4532015112830366",
        "--strategy", "text",
        "--audit-log", "/proc/evadex_no_write_here.jsonl",
    ])
    assert result.exit_code == 0


# ── auto-discovery ────────────────────────────────────────────────────────────

def test_auto_discovery_loads_config(tmp_path):
    """evadex.yaml in cwd is loaded automatically when --config is not passed."""
    cfg_content = "scanner_label: auto-discovered\nstrategy: text\n"
    out_file = tmp_path / "out.json"
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path("evadex.yaml").write_text(cfg_content, encoding="utf-8")
        with patch("evadex.cli.commands.scan.Engine") as MockEngine, \
             patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
            MockEngine.return_value.run.return_value = [_mock_result()]
            result = runner.invoke(main, [
                "scan",
                "--input", "4532015112830366",
                "--output", str(out_file),
            ], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["meta"]["scanner"] == "auto-discovered"


def test_no_auto_discovery_without_file(tmp_path):
    """Scan works normally when no evadex.yaml is present in cwd."""
    out_file = tmp_path / "out.json"
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = _invoke_scan(runner, [
            "--input", "4532015112830366",
            "--strategy", "text",
            "--output", str(out_file),
        ])
    assert result.exit_code == 0, result.output


# ── validation errors surfaced through CLI ────────────────────────────────────

def test_config_invalid_strategy_exits(tmp_path):
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text("strategy: invalid_format\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--config", str(cfg_file), "--input", "4532015112830366",
    ])
    assert result.exit_code != 0
    assert "strategy" in result.output.lower() or "strategy" in (result.exception and str(result.exception) or "")


def test_config_unknown_key_exits(tmp_path):
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text("totally_unknown_key: oops\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--config", str(cfg_file), "--input", "4532015112830366",
    ])
    assert result.exit_code != 0


def test_config_missing_file_exits():
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--config", "/nonexistent/evadex.yaml", "--input", "4532015112830366",
    ])
    assert result.exit_code != 0


def test_config_invalid_min_detection_rate_exits(tmp_path):
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text("min_detection_rate: 150\nstrategy: text\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--config", str(cfg_file), "--input", "4532015112830366",
    ])
    assert result.exit_code != 0


def test_require_context_from_config_propagates(tmp_path):
    """require_context: true in evadex.yaml is applied to the adapter config."""
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text("require_context: true\nstrategy: text\ncmd_style: rust\n", encoding="utf-8")
    captured_config = {}

    def fake_adapter(tool, config):
        captured_config.update(config)
        from evadex.adapters.dlpscan_cli.adapter import DlpscanCliAdapter
        return DlpscanCliAdapter(config)

    runner = CliRunner()
    with patch("evadex.cli.commands.scan.get_adapter", side_effect=fake_adapter), \
         patch("evadex.cli.commands.scan.Engine") as MockEngine, \
         patch.object(DlpscanCliAdapter, "health_check", new_callable=AsyncMock, return_value=True):
        MockEngine.return_value.run.return_value = [_mock_result()]
        result = runner.invoke(main, [
            "scan", "--config", str(cfg_file), "--input", "4532015112830366",
        ], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    assert captured_config.get("require_context") is True


def test_require_context_config_invalid_type_exits(tmp_path):
    """require_context must be a boolean in evadex.yaml."""
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text("require_context: yes_please\nstrategy: text\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, [
        "scan", "--config", str(cfg_file), "--input", "4532015112830366",
    ])
    assert result.exit_code != 0
