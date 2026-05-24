"""Profile → argv translation covers multi-value, boolean, and value flags
plus the env-var expansion hand-off."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from evadex.profiles.schema import Profile
from evadex.profiles.runner import (
    profile_to_falsepos_argv,
    profile_to_scan_argv,
    prune_old_results,
    scan_flags_to_profile_dict,
)


def _p(scan: dict, **kw) -> Profile:
    return Profile(name=kw.pop("name", "t"), scan=scan, **kw)


# ── scan argv ──────────────────────────────────────────────────────────────


def test_basic_value_flags():
    argv = profile_to_scan_argv(_p({"tool": "siphon-cli", "tier": "banking"}))
    assert "--tool" in argv and argv[argv.index("--tool") + 1] == "siphon-cli"
    assert "--tier" in argv and argv[argv.index("--tier") + 1] == "banking"


def test_boolean_flags_emit_when_truthy_only():
    argv = profile_to_scan_argv(_p({
        "tool": "siphon-cli",
        "require_context": True,
        "wrap_context": False,
    }))
    assert "--require-context" in argv
    assert "--wrap-context" not in argv


def test_multi_value_flags_repeat():
    argv = profile_to_scan_argv(_p({
        "tool": "siphon-cli",
        "strategy": ["text", "docx", "pdf"],
    }))
    assert argv.count("--strategy") == 3
    idxs = [i for i, a in enumerate(argv) if a == "--strategy"]
    vals = [argv[i + 1] for i in idxs]
    assert vals == ["text", "docx", "pdf"]


def test_categories_list_repeats_category_flag():
    argv = profile_to_scan_argv(_p({
        "tool": "siphon-cli",
        "categories": ["credit_card", "sin"],
    }))
    assert argv.count("--category") == 2


def test_c2_fields_become_flags():
    argv = profile_to_scan_argv(Profile(
        name="t",
        scan={"tool": "siphon-cli"},
        c2={"url": "http://c2:9090", "key": "KEY"},
    ))
    assert "--c2-url" in argv
    assert argv[argv.index("--c2-url") + 1] == "http://c2:9090"
    assert "--c2-key" in argv
    assert argv[argv.index("--c2-key") + 1] == "KEY"


def test_env_var_substitution_in_scan(monkeypatch):
    monkeypatch.setenv("MY_EXE", "/opt/siphon/bin/siphon")
    monkeypatch.setenv("MY_KEY", "s3cret")
    argv = profile_to_scan_argv(Profile(
        name="t",
        scan={"tool": "siphon-cli", "exe": "${MY_EXE}"},
        c2={"url": "http://c2", "key": "${MY_KEY}"},
    ))
    assert "/opt/siphon/bin/siphon" in argv
    assert "s3cret" in argv


def test_expand_false_preserves_placeholders():
    argv = profile_to_scan_argv(
        Profile(name="t", scan={"tool": "siphon-cli", "exe": "${MY_EXE}"}),
        expand=False,
    )
    assert "${MY_EXE}" in argv


# ── falsepos argv ──────────────────────────────────────────────────────────


def test_falsepos_disabled_returns_none():
    p = Profile(name="t", scan={"tool": "siphon-cli"}, falsepos={"enabled": False})
    assert profile_to_falsepos_argv(p) is None


def test_falsepos_inherits_scanner_config_from_scan():
    p = Profile(
        name="t",
        scan={"tool": "siphon-cli", "exe": "/bin/siphon", "cmd_style": "binary"},
        falsepos={"enabled": True, "count": 100, "wrap_context": True},
    )
    argv = profile_to_falsepos_argv(p)
    # Scanner identity must be inherited from scan so a single profile can
    # drive both runs without repeating config.
    assert argv is not None
    assert "--tool" in argv and argv[argv.index("--tool") + 1] == "siphon-cli"
    assert "--exe" in argv and argv[argv.index("--exe") + 1] == "/bin/siphon"
    assert "--cmd-style" in argv
    assert "--count" in argv
    assert "--wrap-context" in argv


def test_falsepos_own_config_overrides_scan_inheritance():
    p = Profile(
        name="t",
        scan={"tool": "siphon-cli", "timeout": 30},
        falsepos={"enabled": True, "count": 50, "timeout": 120},
    )
    argv = profile_to_falsepos_argv(p)
    assert argv is not None
    t_idx = argv.index("--timeout")
    assert argv[t_idx + 1] == "120"


# ── --save-as helper ───────────────────────────────────────────────────────


def test_scan_flags_to_profile_drops_empty_values():
    out = scan_flags_to_profile_dict({
        "tool": "siphon-cli",
        "tier": None,
        "strategies": (),
        "categories": (),
        "scanner_label": "",
        "wrap_context": False,
    })
    # None / empty-tuple / empty-string / False must all be dropped.
    assert out == {"tool": "siphon-cli"}


def test_scan_flags_to_profile_maps_click_names_to_profile_keys():
    out = scan_flags_to_profile_dict({
        "tool": "siphon-cli",
        "strategies": ("text", "docx"),
        "categories": ("credit_card",),
        "variant_groups": ("unicode_encoding",),
        "fmt": "json",
        "input_value": "4532015112830366",
        "executable": "/bin/siphon",
        "tier": "banking",
        "wrap_context": True,
    })
    assert out["strategy"] == ["text", "docx"]
    assert out["categories"] == ["credit_card"]
    assert out["variant_groups"] == ["unicode_encoding"]
    assert out["format"] == "json"
    assert out["input"] == "4532015112830366"
    assert out["exe"] == "/bin/siphon"
    assert out["wrap_context"] is True


def test_scan_flags_to_profile_drops_fast_mode():
    # --fast resolves to a machine-specific technique whitelist based on the
    # local audit-log history, so it must not be persisted by --save-as.
    out = scan_flags_to_profile_dict({
        "tool": "siphon-cli",
        "tier": "northam",
        "fast_mode": True,
    })
    assert "fast_mode" not in out
    assert "fast" not in out


# ── output.dir plumbing ────────────────────────────────────────────────────


def test_output_dir_emits_output_flag_for_scan():
    p = Profile(
        name="daily",
        scan={"tool": "siphon-cli", "tier": "northam"},
        output={"dir": "/tmp/evadex-results", "format": "json"},
    )
    argv = profile_to_scan_argv(p, timestamp="20260524T200000Z")
    assert "--output" in argv
    out_idx = argv.index("--output")
    val = argv[out_idx + 1]
    # Path uses platform separator; check filename pieces directly.
    assert "daily_20260524T200000Z_scan.json" in val.replace("\\", "/")
    assert "/tmp/evadex-results" in val.replace("\\", "/")


def test_output_dir_emits_output_flag_for_falsepos_with_same_timestamp():
    p = Profile(
        name="daily",
        scan={"tool": "siphon-cli"},
        falsepos={"enabled": True, "count": 50},
        output={"dir": "/tmp/evadex-results"},
    )
    argv = profile_to_falsepos_argv(p, timestamp="20260524T200000Z")
    assert argv is not None
    assert "--output" in argv
    val = argv[argv.index("--output") + 1]
    assert "daily_20260524T200000Z_falsepos.json" in val.replace("\\", "/")


def test_output_dir_not_set_no_output_flag():
    # Default behavior must be preserved: when output.dir is absent, the
    # runner does NOT inject --output (the scan command's own --output
    # default / auto-archive path applies).
    p = Profile(name="t", scan={"tool": "siphon-cli", "tier": "banking"})
    argv = profile_to_scan_argv(p)
    assert "--output" not in argv


def test_explicit_scan_output_wins_over_profile_output_dir():
    # If the user pinned scan.output explicitly, output.dir must not override.
    p = Profile(
        name="t",
        scan={"tool": "siphon-cli", "output": "/etc/specific.json"},
        output={"dir": "/tmp/should-be-ignored"},
    )
    argv = profile_to_scan_argv(p)
    assert argv.count("--output") == 1
    assert argv[argv.index("--output") + 1] == "/etc/specific.json"


def test_output_dir_expands_tilde():
    p = Profile(
        name="t",
        scan={"tool": "siphon-cli"},
        output={"dir": "~/evadex-results"},
    )
    argv = profile_to_scan_argv(p, timestamp="20260524T200000Z")
    val = argv[argv.index("--output") + 1].replace("\\", "/")
    # ~ must be expanded; "~" should NOT appear literally in the resolved path.
    assert "~" not in val
    assert val.endswith("evadex-results/t_20260524T200000Z_scan.json")


def test_output_dir_with_explicit_format_extension():
    # output.format is a hint for the file extension when output.dir resolves
    # the path. Only "json" is meaningful today, but the helper passes the
    # value through so future formats work without a code change.
    p = Profile(
        name="t",
        scan={"tool": "siphon-cli"},
        output={"dir": "/tmp/x", "format": "json"},
    )
    argv = profile_to_scan_argv(p, timestamp="20260524T200000Z")
    val = argv[argv.index("--output") + 1].replace("\\", "/")
    assert val.endswith(".json")


# ── prune_old_results ──────────────────────────────────────────────────────


def _write_result_file(tmp_path, name: str, age_days: float) -> "Path":  # noqa: F821
    """Helper: create a file with mtime set to (now - age_days)."""
    path = tmp_path / name
    path.write_text("{}", encoding="utf-8")
    target = (datetime.now(timezone.utc) - timedelta(days=age_days)).timestamp()
    os.utime(path, (target, target))
    return path


def test_prune_deletes_files_older_than_retain_days(tmp_path):
    old_scan = _write_result_file(tmp_path, "demo_20260101T000000Z_scan.json", age_days=45)
    old_fp = _write_result_file(tmp_path, "demo_20260101T000000Z_falsepos.json", age_days=45)
    p = Profile(
        name="demo",
        scan={"tool": "siphon-cli"},
        output={"dir": str(tmp_path), "retain_days": 30},
    )
    deleted = prune_old_results(p)
    deleted_set = {d.name for d in deleted}
    assert old_scan.name in deleted_set
    assert old_fp.name in deleted_set
    assert not old_scan.exists()
    assert not old_fp.exists()


def test_prune_keeps_files_newer_than_retain_days(tmp_path):
    fresh = _write_result_file(tmp_path, "demo_20260520T000000Z_scan.json", age_days=1)
    p = Profile(
        name="demo",
        scan={"tool": "siphon-cli"},
        output={"dir": str(tmp_path), "retain_days": 30},
    )
    deleted = prune_old_results(p)
    assert deleted == []
    assert fresh.exists()


def test_prune_is_noop_when_retain_days_not_set(tmp_path):
    ancient = _write_result_file(tmp_path, "demo_20240101T000000Z_scan.json", age_days=500)
    p = Profile(
        name="demo",
        scan={"tool": "siphon-cli"},
        output={"dir": str(tmp_path)},  # no retain_days
    )
    deleted = prune_old_results(p)
    assert deleted == []
    assert ancient.exists()


def test_prune_is_noop_when_no_output_dir(tmp_path):
    p = Profile(
        name="demo",
        scan={"tool": "siphon-cli"},
        output={"retain_days": 30},  # no dir
    )
    assert prune_old_results(p) == []


def test_prune_only_touches_files_matching_profile_name(tmp_path):
    # Files from a sibling profile in the same dir must not be deleted.
    mine_old = _write_result_file(tmp_path, "mine_20260101T000000Z_scan.json", age_days=45)
    other_old = _write_result_file(tmp_path, "other_20260101T000000Z_scan.json", age_days=45)
    p = Profile(
        name="mine",
        scan={"tool": "siphon-cli"},
        output={"dir": str(tmp_path), "retain_days": 30},
    )
    deleted = prune_old_results(p)
    assert {d.name for d in deleted} == {mine_old.name}
    assert not mine_old.exists()
    assert other_old.exists()


def test_prune_ignores_non_result_files(tmp_path):
    # Unrelated files in the same dir must be left alone even when matching age.
    sentinel = _write_result_file(tmp_path, "README.md", age_days=999)
    p = Profile(
        name="demo",
        scan={"tool": "siphon-cli"},
        output={"dir": str(tmp_path), "retain_days": 30},
    )
    prune_old_results(p)
    assert sentinel.exists()


def test_prune_invalid_retain_days_is_noop(tmp_path):
    old = _write_result_file(tmp_path, "demo_20260101T000000Z_scan.json", age_days=45)
    p = Profile(
        name="demo",
        scan={"tool": "siphon-cli"},
        output={"dir": str(tmp_path), "retain_days": "not-a-number"},
    )
    assert prune_old_results(p) == []
    assert old.exists()


def test_prune_zero_or_negative_retain_days_is_noop(tmp_path):
    old = _write_result_file(tmp_path, "demo_20260101T000000Z_scan.json", age_days=45)
    for value in (0, -1):
        p = Profile(
            name="demo",
            scan={"tool": "siphon-cli"},
            output={"dir": str(tmp_path), "retain_days": value},
        )
        assert prune_old_results(p) == []
    assert old.exists()


def test_prune_uses_caller_supplied_now_for_determinism(tmp_path):
    # File is 10 days old by mtime; with retain_days=5 and now pinned to today,
    # it should be deleted regardless of the wall clock when the test runs.
    f = _write_result_file(tmp_path, "demo_20260514T000000Z_scan.json", age_days=10)
    p = Profile(
        name="demo",
        scan={"tool": "siphon-cli"},
        output={"dir": str(tmp_path), "retain_days": 5},
    )
    deleted = prune_old_results(p, now=datetime.now(timezone.utc))
    assert [d.name for d in deleted] == [f.name]
    assert not f.exists()
