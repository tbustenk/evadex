"""Profile → argv translation covers multi-value, boolean, and value flags
plus the env-var expansion hand-off."""
from __future__ import annotations

import pytest

from evadex.profiles.schema import Profile
from evadex.profiles.runner import (
    profile_to_falsepos_argv,
    profile_to_scan_argv,
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
