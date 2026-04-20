"""Profile filesystem layout + CRUD.

User profiles live under the directory returned by :func:`profiles_dir`,
which defaults to ``~/.evadex/profiles`` and can be overridden with the
``EVADEX_PROFILES_DIR`` environment variable (primarily so tests can pin
the location to a temporary directory).

Built-in profiles ship alongside the package at
``evadex.profiles.builtins`` and are read-only — :func:`save_profile`
will not overwrite a built-in, and :func:`load_profile` falls back to the
built-ins only when no user profile with that name exists.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from evadex.profiles.schema import Profile, ProfileError, parse_profile


# Package-internal location of bundled profiles.
_BUILTINS_PACKAGE = Path(__file__).parent / "builtins"


def profiles_dir() -> Path:
    """Return the user profiles directory (created if it doesn't exist)."""
    override = os.environ.get("EVADEX_PROFILES_DIR")
    base = Path(override) if override else Path.home() / ".evadex" / "profiles"
    base.mkdir(parents=True, exist_ok=True)
    return base


def profile_path(name: str) -> Path:
    """Filesystem path a user profile with this name would live at."""
    return profiles_dir() / f"{name}.yaml"


def list_profiles() -> list[str]:
    """Names of user-saved profiles, alphabetical."""
    d = profiles_dir()
    return sorted(p.stem for p in d.glob("*.yaml"))


def list_builtin_profiles() -> list[str]:
    """Names of bundled profiles, alphabetical."""
    if not _BUILTINS_PACKAGE.is_dir():
        return []
    return sorted(p.stem for p in _BUILTINS_PACKAGE.glob("*.yaml"))


def _load_yaml(path: Path) -> dict:
    try:
        import yaml
    except ImportError as e:
        raise ProfileError(
            "PyYAML is required for profile support. pip install pyyaml"
        ) from e
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except OSError as e:
        raise ProfileError(f"Cannot read profile {path}: {e}") from e
    except yaml.YAMLError as e:
        raise ProfileError(f"Invalid YAML in {path}: {e}") from e
    if raw is None:
        raise ProfileError(f"Profile {path} is empty")
    return raw


def load_builtin_profile(name: str) -> Profile:
    """Load a built-in profile by name. Raises :class:`ProfileError` if missing."""
    path = _BUILTINS_PACKAGE / f"{name}.yaml"
    if not path.is_file():
        raise ProfileError(f"No built-in profile named {name!r}")
    raw = _load_yaml(path)
    return parse_profile(raw, source_path=str(path), builtin=True)


def load_profile(name: str) -> Profile:
    """Resolve *name* to a profile — user profiles shadow built-ins.

    Order:
    1. ``~/.evadex/profiles/<name>.yaml`` (or the ``EVADEX_PROFILES_DIR`` override)
    2. Bundled built-in with that name

    Raises :class:`ProfileError` if neither is found.
    """
    user = profile_path(name)
    if user.is_file():
        raw = _load_yaml(user)
        return parse_profile(raw, source_path=str(user), builtin=False)
    if (_BUILTINS_PACKAGE / f"{name}.yaml").is_file():
        return load_builtin_profile(name)
    raise ProfileError(
        f"No profile named {name!r}. Use 'evadex profile list' to see "
        f"available profiles."
    )


def save_profile(profile: Profile, overwrite: bool = False) -> Path:
    """Persist *profile* to the user profiles directory.

    Refuses to overwrite a built-in profile — users must rename instead.
    Refuses to overwrite an existing user profile unless ``overwrite=True``.
    """
    if profile.builtin:
        raise ProfileError(
            f"Cannot overwrite built-in profile {profile.name!r}. "
            "Save it under a different name first."
        )

    try:
        import yaml
    except ImportError as e:
        raise ProfileError(
            "PyYAML is required for profile support. pip install pyyaml"
        ) from e

    path = profile_path(profile.name)
    if path.is_file() and not overwrite:
        raise ProfileError(
            f"Profile {profile.name!r} already exists at {path}. "
            "Pass overwrite=True to replace it."
        )

    d = profile.to_dict()
    # Stamp 'created' if missing — first save wins.
    if "created" not in d or d["created"] is None:
        d["created"] = _utc_now_iso()

    path.write_text(yaml.safe_dump(d, sort_keys=False), encoding="utf-8")
    return path


def delete_profile(name: str) -> Path:
    """Remove a user profile. Raises :class:`ProfileError` if missing."""
    path = profile_path(name)
    if not path.is_file():
        raise ProfileError(
            f"No user profile named {name!r} at {path}. "
            "Built-in profiles cannot be deleted."
        )
    path.unlink()
    return path


def update_last_run(name: str, when: Optional[str] = None) -> None:
    """Stamp ``last_run`` on the user-saved copy of *name*.

    No-op if the profile is a built-in (we never write into the package
    directory). Callers that want to persist last-run for a built-in should
    copy it to the user dir first via :func:`save_profile`.
    """
    user = profile_path(name)
    if not user.is_file():
        return
    profile = load_profile(name)
    profile.last_run = when or _utc_now_iso()
    save_profile(profile, overwrite=True)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
