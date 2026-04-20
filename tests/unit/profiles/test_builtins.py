"""Every built-in profile must parse cleanly and produce valid argv."""
from __future__ import annotations

import pytest

from evadex.profiles.schema import ProfileError
from evadex.profiles.storage import list_builtin_profiles, load_builtin_profile
from evadex.profiles.runner import profile_to_scan_argv, profile_to_falsepos_argv


EXPECTED_BUILTINS = {
    "banking-daily", "pci-dss", "canadian-ids", "full-evasion", "quick-check",
}


def test_every_expected_builtin_ships():
    assert set(list_builtin_profiles()) >= EXPECTED_BUILTINS


@pytest.mark.parametrize("name", sorted(EXPECTED_BUILTINS))
def test_builtin_parses_cleanly(name):
    p = load_builtin_profile(name)
    assert p.builtin is True
    assert p.name == name
    assert p.description  # every built-in has a description
    assert p.scan, f"built-in {name} must have a non-empty scan section"


@pytest.mark.parametrize("name", sorted(EXPECTED_BUILTINS))
def test_builtin_produces_argv(name):
    p = load_builtin_profile(name)
    argv = profile_to_scan_argv(p, expand=False)
    assert "--tool" in argv
    tool_idx = argv.index("--tool")
    assert argv[tool_idx + 1] == p.scan["tool"]


def test_builtins_with_falsepos_produce_falsepos_argv():
    # banking-daily, pci-dss, canadian-ids, full-evasion all enable falsepos.
    for name in ("banking-daily", "pci-dss", "canadian-ids", "full-evasion"):
        p = load_builtin_profile(name)
        argv = profile_to_falsepos_argv(p, expand=False)
        assert argv is not None, f"{name} should emit falsepos argv"
        assert "--count" in argv


def test_quick_check_has_no_falsepos_argv():
    p = load_builtin_profile("quick-check")
    assert profile_to_falsepos_argv(p, expand=False) is None


def test_load_builtin_unknown_raises():
    with pytest.raises(ProfileError, match="No built-in profile"):
        load_builtin_profile("does-not-exist")
