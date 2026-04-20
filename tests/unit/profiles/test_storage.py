"""CRUD tests for the profiles storage layer.

Each test points ``EVADEX_PROFILES_DIR`` at a pytest tmp_path so user-level
profiles are never touched.
"""
from __future__ import annotations

import pytest

from evadex.profiles.schema import Profile, ProfileError, parse_profile
from evadex.profiles.storage import (
    delete_profile,
    list_builtin_profiles,
    list_profiles,
    load_builtin_profile,
    load_profile,
    profile_path,
    save_profile,
    update_last_run,
)


@pytest.fixture(autouse=True)
def _isolate_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv("EVADEX_PROFILES_DIR", str(tmp_path))
    yield


def _mkprofile(name: str = "demo", **extra) -> Profile:
    scan = extra.pop("scan", {"tool": "siphon-cli", "tier": "banking"})
    return Profile(name=name, scan=scan, **extra)


def test_list_profiles_empty_to_start():
    assert list_profiles() == []


def test_save_and_load_roundtrip():
    p = _mkprofile("banking-today", description="hello")
    path = save_profile(p)
    assert path.is_file()
    assert list_profiles() == ["banking-today"]

    loaded = load_profile("banking-today")
    assert loaded.name == "banking-today"
    assert loaded.description == "hello"
    assert loaded.scan["tool"] == "siphon-cli"
    # save_profile stamps created at on first save.
    assert loaded.created is not None


def test_save_refuses_to_overwrite_without_flag():
    save_profile(_mkprofile("collide"))
    with pytest.raises(ProfileError, match="already exists"):
        save_profile(_mkprofile("collide"))
    # overwrite=True is allowed.
    save_profile(_mkprofile("collide", description="v2"), overwrite=True)
    assert load_profile("collide").description == "v2"


def test_save_refuses_builtin():
    p = _mkprofile("built")
    p.builtin = True
    with pytest.raises(ProfileError, match="built-in"):
        save_profile(p)


def test_delete_profile_removes_file():
    save_profile(_mkprofile("bye"))
    path = profile_path("bye")
    assert path.is_file()
    delete_profile("bye")
    assert not path.is_file()


def test_delete_missing_profile_raises():
    with pytest.raises(ProfileError, match="No user profile"):
        delete_profile("never-existed")


def test_user_profile_shadows_builtin(tmp_path):
    # `banking-daily` is a built-in; writing a user profile with the same
    # name must take priority.
    assert "banking-daily" in list_builtin_profiles()
    user_version = _mkprofile("banking-daily", description="overridden")
    save_profile(user_version)
    loaded = load_profile("banking-daily")
    assert loaded.builtin is False
    assert loaded.description == "overridden"


def test_load_falls_back_to_builtin_when_no_user_copy():
    p = load_profile("pci-dss")
    assert p.builtin is True
    assert p.name == "pci-dss"
    assert p.scan["tool"] == "siphon-cli"


def test_load_builtin_direct_ignores_user_copy():
    save_profile(_mkprofile("pci-dss", description="user override"))
    loaded = load_builtin_profile("pci-dss")
    assert loaded.builtin is True
    # Built-in descriptions start with "PCI-DSS focused check".
    assert loaded.description and loaded.description.lower().startswith("pci")


def test_update_last_run_stamps_iso_timestamp():
    save_profile(_mkprofile("nightly"))
    update_last_run("nightly")
    p = load_profile("nightly")
    assert p.last_run is not None
    assert p.last_run.endswith("Z")


def test_update_last_run_noop_on_builtin_only():
    # pci-dss is a built-in with no user copy; update should silently do
    # nothing rather than blow up.
    update_last_run("pci-dss")
    # Built-in file must not have been modified.
    loaded = load_builtin_profile("pci-dss")
    assert loaded.last_run is None


def test_parse_profile_rejects_missing_name():
    with pytest.raises(ProfileError, match="missing required 'name'"):
        parse_profile({"scan": {"tool": "siphon-cli"}})


def test_parse_profile_rejects_missing_scan():
    with pytest.raises(ProfileError, match="scan"):
        parse_profile({"name": "x"})


def test_parse_profile_rejects_unknown_top_level_key():
    with pytest.raises(ProfileError, match="unknown top-level keys"):
        parse_profile({"name": "x", "scan": {"tool": "x"}, "wat": True})


@pytest.mark.parametrize("bad_name", [
    "", "UPPERCASE", "has spaces", "dot.in.name", "-starts-with-dash",
])
def test_parse_profile_rejects_bad_names(bad_name):
    with pytest.raises(ProfileError, match="name"):
        parse_profile({"name": bad_name, "scan": {"tool": "x"}})
