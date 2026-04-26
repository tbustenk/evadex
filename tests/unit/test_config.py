"""Unit tests for evadex.config — loading, validation, and auto-discovery."""

import pytest
from pathlib import Path
from evadex.config import load_config, find_config, EvadexConfig, DEFAULT_CONFIG_YAML


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_yaml(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "evadex.yaml"
    f.write_text(content, encoding="utf-8")
    return f


# ── load_config: valid inputs ─────────────────────────────────────────────────

def test_load_full_valid_config(tmp_path):
    cfg_file = _write_yaml(tmp_path, """
tool: dlpscan-cli
strategy: text
min_detection_rate: 85
scanner_label: production
exe: null
cmd_style: python
categories:
  - credit_card
  - ssn
include_heuristic: false
concurrency: 5
timeout: 30.0
output: results.json
format: json
""")
    cfg = load_config(cfg_file)
    assert cfg.tool == "dlpscan-cli"
    assert cfg.strategy == ["text"]
    assert cfg.min_detection_rate == 85.0
    assert cfg.scanner_label == "production"
    assert cfg.exe is None
    assert cfg.cmd_style == "python"
    assert cfg.categories == ["credit_card", "ssn"]
    assert cfg.include_heuristic is False
    assert cfg.concurrency == 5
    assert cfg.timeout == 30.0
    assert cfg.output == "results.json"
    assert cfg.format == "json"


def test_load_strategy_as_list(tmp_path):
    cfg_file = _write_yaml(tmp_path, "strategy:\n  - text\n  - docx\n")
    cfg = load_config(cfg_file)
    assert cfg.strategy == ["text", "docx"]


def test_load_partial_config(tmp_path):
    """Only some keys set — rest should be None."""
    cfg_file = _write_yaml(tmp_path, "tool: dlpscan\nconcurrency: 10\n")
    cfg = load_config(cfg_file)
    assert cfg.tool == "dlpscan"
    assert cfg.concurrency == 10
    assert cfg.timeout is None
    assert cfg.format is None


def test_load_empty_config(tmp_path):
    """Empty YAML file returns an empty EvadexConfig."""
    cfg_file = _write_yaml(tmp_path, "")
    cfg = load_config(cfg_file)
    assert cfg == EvadexConfig()


def test_load_min_detection_rate_zero(tmp_path):
    cfg_file = _write_yaml(tmp_path, "min_detection_rate: 0\n")
    cfg = load_config(cfg_file)
    assert cfg.min_detection_rate == 0.0


def test_load_min_detection_rate_100(tmp_path):
    cfg_file = _write_yaml(tmp_path, "min_detection_rate: 100\n")
    cfg = load_config(cfg_file)
    assert cfg.min_detection_rate == 100.0


# ── load_config: file errors ──────────────────────────────────────────────────

def test_load_config_missing_file():
    import click
    with pytest.raises(click.UsageError, match="not found"):
        load_config("/nonexistent/path/evadex.yaml")


def test_load_config_not_a_mapping(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "- item1\n- item2\n")
    with pytest.raises(click.UsageError, match="mapping"):
        load_config(cfg_file)


# ── load_config: unknown keys ─────────────────────────────────────────────────

def test_load_unknown_key_raises(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "tool: dlpscan-cli\nbad_key: oops\n")
    with pytest.raises(click.UsageError, match="Unknown config key"):
        load_config(cfg_file)


def test_load_multiple_unknown_keys_listed(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "foo: 1\nbar: 2\n")
    with pytest.raises(click.UsageError, match="foo") as exc_info:
        load_config(cfg_file)
    assert "bar" in str(exc_info.value)


# ── load_config: validation errors ───────────────────────────────────────────

def test_invalid_tool_value(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "tool: bad-scanner\n")
    with pytest.raises(click.UsageError, match="tool"):
        load_config(cfg_file)


def test_empty_categories_list_raises(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "categories: []\n")
    with pytest.raises(click.UsageError, match="categories"):
        load_config(cfg_file)


def test_invalid_strategy_value(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "strategy: foobar\n")
    with pytest.raises(click.UsageError, match="Invalid strategy"):
        load_config(cfg_file)


def test_invalid_format(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "format: xml\n")
    with pytest.raises(click.UsageError, match="format"):
        load_config(cfg_file)


def test_invalid_cmd_style(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "cmd_style: go\n")
    with pytest.raises(click.UsageError, match="cmd_style"):
        load_config(cfg_file)


def test_min_detection_rate_too_high(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "min_detection_rate: 101\n")
    with pytest.raises(click.UsageError, match="min_detection_rate"):
        load_config(cfg_file)


def test_min_detection_rate_negative(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "min_detection_rate: -1\n")
    with pytest.raises(click.UsageError, match="min_detection_rate"):
        load_config(cfg_file)


def test_invalid_category(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "categories:\n  - credit_card\n  - notacategory\n")
    with pytest.raises(click.UsageError, match="Invalid category"):
        load_config(cfg_file)


def test_concurrency_zero_invalid(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "concurrency: 0\n")
    with pytest.raises(click.UsageError, match="concurrency"):
        load_config(cfg_file)


def test_concurrency_negative_invalid(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "concurrency: -3\n")
    with pytest.raises(click.UsageError, match="concurrency"):
        load_config(cfg_file)


def test_timeout_zero_invalid(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "timeout: 0\n")
    with pytest.raises(click.UsageError, match="timeout"):
        load_config(cfg_file)


def test_include_heuristic_not_bool(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "include_heuristic: yes_please\n")
    with pytest.raises(click.UsageError, match="include_heuristic"):
        load_config(cfg_file)


# ── require_context config key ──────────────────────────────────────────────

def test_require_context_true_is_accepted(tmp_path):
    cfg_file = _write_yaml(tmp_path, "require_context: true\n")
    cfg = load_config(cfg_file)
    assert cfg.require_context is True


def test_require_context_false_is_accepted(tmp_path):
    cfg_file = _write_yaml(tmp_path, "require_context: false\n")
    cfg = load_config(cfg_file)
    assert cfg.require_context is False


def test_require_context_wrong_type_raises(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "require_context: yes_please\n")
    with pytest.raises(click.UsageError, match="require_context"):
        load_config(cfg_file)


# ── audit_log config key ─────────────────────────────────────────────────────

def test_audit_log_string_is_accepted(tmp_path):
    cfg_file = _write_yaml(tmp_path, "audit_log: /var/log/evadex/audit.jsonl\n")
    cfg = load_config(cfg_file)
    assert cfg.audit_log == "/var/log/evadex/audit.jsonl"


def test_audit_log_null_is_accepted(tmp_path):
    cfg_file = _write_yaml(tmp_path, "audit_log: null\n")
    cfg = load_config(cfg_file)
    assert cfg.audit_log is None


def test_audit_log_wrong_type_raises(tmp_path):
    import click
    cfg_file = _write_yaml(tmp_path, "audit_log: 123\n")
    with pytest.raises(click.UsageError, match="audit_log"):
        load_config(cfg_file)


# ── find_config ───────────────────────────────────────────────────────────────

def test_find_config_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "evadex.yaml").write_text("tool: dlpscan-cli\n", encoding="utf-8")
    found = find_config()
    assert found is not None
    assert found.name == "evadex.yaml"


def test_find_config_absent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert find_config() is None


# ── DEFAULT_CONFIG_YAML is valid ──────────────────────────────────────────────

def test_default_config_yaml_is_valid(tmp_path):
    cfg_file = tmp_path / "evadex.yaml"
    cfg_file.write_text(DEFAULT_CONFIG_YAML, encoding="utf-8")
    cfg = load_config(cfg_file)
    assert cfg.tool == "dlpscan-cli"
    assert cfg.concurrency == 32
    assert cfg.format == "json"
