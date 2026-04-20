"""End-to-end CLI smoke tests for ``evadex profile`` and ``evadex schedule``.

These exercise the Click wiring (argument parsing, command registration,
stdout/stderr routing) without actually running a scanner subprocess —
``profile run --dry-run`` short-circuits before subprocess invocation.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner

from evadex.cli.app import main
from evadex.profiles.storage import list_profiles, profile_path, save_profile
from evadex.profiles.schema import Profile


@pytest.fixture(autouse=True)
def _isolate_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv("EVADEX_PROFILES_DIR", str(tmp_path))
    yield


def _run(*args):
    return CliRunner().invoke(main, list(args))


# ── profile list / show ────────────────────────────────────────────────────


def test_profile_list_shows_builtins_when_empty():
    res = _run("profile", "list")
    assert res.exit_code == 0
    assert "banking-daily" in res.stdout
    assert "quick-check" in res.stdout


def test_profile_show_dumps_yaml():
    res = _run("profile", "show", "quick-check")
    assert res.exit_code == 0
    assert "name: quick-check" in res.stdout
    assert "tool: siphon-cli" in res.stdout


def test_profile_show_missing_exits_nonzero():
    res = _run("profile", "show", "not-a-thing")
    assert res.exit_code != 0


# ── profile create / delete / import / export ──────────────────────────────


def test_profile_create_writes_user_profile():
    res = _run(
        "profile", "create", "smoke",
        "--tool", "siphon-cli", "--tier", "banking",
        "--description", "smoke test",
    )
    assert res.exit_code == 0, res.output
    assert "smoke" in list_profiles()
    # file exists
    assert profile_path("smoke").is_file()


def test_profile_delete_removes_user_profile():
    _run(
        "profile", "create", "gone",
        "--tool", "siphon-cli", "--tier", "banking",
    )
    assert "gone" in list_profiles()
    res = _run("profile", "delete", "gone", "--yes")
    assert res.exit_code == 0, res.output
    assert "gone" not in list_profiles()


def test_profile_delete_builtin_refused():
    res = _run("profile", "delete", "pci-dss", "--yes")
    assert res.exit_code != 0


def test_profile_export_writes_file(tmp_path):
    out = tmp_path / "exported.yaml"
    res = _run("profile", "export", "quick-check", "--output", str(out))
    assert res.exit_code == 0, res.output
    assert out.is_file()
    assert "name: quick-check" in out.read_text(encoding="utf-8")


def test_profile_import_roundtrip(tmp_path):
    out = tmp_path / "share.yaml"
    _run("profile", "export", "quick-check", "--output", str(out))
    res = _run("profile", "import", str(out), "--name", "shared-copy")
    assert res.exit_code == 0, res.output
    assert "shared-copy" in list_profiles()


# ── profile run (dry-run) ──────────────────────────────────────────────────


def test_profile_run_dry_run_prints_argv():
    res = _run("profile", "run", "quick-check", "--dry-run")
    assert res.exit_code == 0, res.output
    assert "evadex scan" in res.stdout
    assert "--tool siphon-cli" in res.stdout
    assert "--wrap-context" in res.stdout


def test_profile_run_unknown_exits_nonzero():
    res = _run("profile", "run", "nonexistent", "--dry-run")
    assert res.exit_code != 0


# ── schedule add / list / export ───────────────────────────────────────────


def test_schedule_add_rejects_bad_cron():
    _run("profile", "create", "sched", "--tool", "siphon-cli", "--tier", "banking")
    res = _run("schedule", "add", "sched", "--cron", "not a cron")
    assert res.exit_code != 0


def test_schedule_add_persists_cron_on_user_profile():
    _run("profile", "create", "sched", "--tool", "siphon-cli", "--tier", "banking")
    res = _run("schedule", "add", "sched", "--cron", "0 6 * * *")
    assert res.exit_code == 0, res.output
    # Reload and verify.
    import yaml
    data = yaml.safe_load(profile_path("sched").read_text(encoding="utf-8"))
    assert data["schedule"]["cron"] == "0 6 * * *"


def test_schedule_add_on_builtin_copies_to_user_dir():
    res = _run("schedule", "add", "quick-check", "--cron", "0 5 * * *")
    assert res.exit_code == 0, res.output
    # Copy now exists in user dir.
    assert profile_path("quick-check").is_file()


def test_schedule_list_shows_builtin_scheduled_profiles():
    # banking-daily ships with a schedule, so list should surface it even
    # when the user has no profiles of their own.
    res = _run("schedule", "list")
    assert res.exit_code == 0
    assert "banking-daily" in res.output
    assert "0 6 * * *" in res.output


def test_schedule_export_cron_emits_valid_line():
    _run("profile", "create", "daily", "--tool", "siphon-cli", "--tier", "banking")
    _run("schedule", "add", "daily", "--cron", "0 6 * * *")
    res = _run("schedule", "export", "daily", "--format", "cron")
    assert res.exit_code == 0, res.output
    assert res.stdout.startswith("0 6 * * *")
    assert "profile run daily" in res.stdout


def test_schedule_export_windows_task_xml_has_task_root():
    _run("profile", "create", "daily", "--tool", "siphon-cli", "--tier", "banking")
    _run("schedule", "add", "daily", "--cron", "0 6 * * *")
    res = _run("schedule", "export", "daily", "--format", "windows-task")
    assert res.exit_code == 0, res.output
    assert "<Task" in res.stdout
    assert "T06:00:00" in res.stdout


# ── schedule run-due ───────────────────────────────────────────────────────


def test_schedule_run_due_dry_run_only_lists():
    _run("profile", "create", "daily", "--tool", "siphon-cli", "--tier", "banking")
    _run("schedule", "add", "daily", "--cron", "* * * * *")
    res = _run("schedule", "run-due", "--dry-run")
    assert res.exit_code == 0, res.output
    # '* * * * *' always fires, so our profile must be listed.
    assert "daily" in (res.stderr or "") + (res.stdout or "")
