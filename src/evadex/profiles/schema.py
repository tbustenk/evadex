"""Profile schema + validation.

A Profile dict looks like::

    name: pci-dss-daily
    description: Daily PCI-DSS check
    created: 2026-04-20T10:00:00Z
    last_run: null

    scan:
      tool: siphon-cli
      tier: banking
      strategy: text
      ...

    falsepos:
      enabled: true
      count: 100

    c2:
      url: http://c2:9090
      key: ${EVADEX_C2_KEY}

    schedule:
      cron: "0 6 * * *"
      timezone: America/Toronto

    output:
      format: json
      dir: ~/.evadex/results

Only ``name`` and ``scan`` are required. Everything else is optional.

Validation is intentionally lenient in the nested ``scan`` / ``falsepos``
sections: we accept any key that ``evadex scan`` / ``evadex falsepos``
understands and let those commands surface their own errors. The profile
layer only validates structural concerns (required keys, correct types).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


class ProfileError(ValueError):
    """Raised when a profile document is malformed."""


_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Keys we accept inside ``scan:`` — aligned with evadex.config.KNOWN_KEYS
# plus ``variant_group``, ``evasion_mode``, ``input``, ``concurrency``,
# ``feedback_report``, ``audit_log`` which are scan-only flags.
VALID_SCAN_KEYS = {
    "tool", "strategy", "min_detection_rate", "scanner_label", "exe",
    "cmd_style", "categories", "include_heuristic", "concurrency",
    "timeout", "output", "format", "audit_log", "require_context",
    "wrap_context", "tier", "evasion_mode",
    "variant_groups", "input", "feedback_report", "url", "api_key",
}

VALID_FALSEPOS_KEYS = {
    "enabled", "categories", "count", "concurrency", "seed",
    "require_context", "wrap_context", "format", "output",
    "tool", "exe", "cmd_style", "url", "timeout",
}

VALID_C2_KEYS = {"url", "key"}

VALID_SCHEDULE_KEYS = {"cron", "frequency", "time", "timezone"}

VALID_OUTPUT_KEYS = {"format", "dir", "retain_days"}


@dataclass
class Profile:
    """In-memory representation of a profile YAML document.

    The raw dicts are kept as-is (including ``${ENV}`` placeholders) so that
    ``profile show`` displays exactly what's on disk. Environment variable
    substitution happens lazily in :func:`expand_env`.
    """

    name: str
    description: Optional[str] = None
    created: Optional[str] = None
    last_run: Optional[str] = None
    scan: dict = field(default_factory=dict)
    falsepos: dict = field(default_factory=dict)
    c2: dict = field(default_factory=dict)
    schedule: dict = field(default_factory=dict)
    output: dict = field(default_factory=dict)
    source_path: Optional[str] = None  # Path on disk (None for built-ins loaded from memory)
    builtin: bool = False

    def to_dict(self) -> dict:
        """Serialise to a YAML-friendly dict. Omits None-valued top-level keys."""
        d: dict = {"name": self.name}
        if self.description is not None:
            d["description"] = self.description
        if self.created is not None:
            d["created"] = self.created
        if self.last_run is not None:
            d["last_run"] = self.last_run
        if self.scan:
            d["scan"] = dict(self.scan)
        if self.falsepos:
            d["falsepos"] = dict(self.falsepos)
        if self.c2:
            d["c2"] = dict(self.c2)
        if self.schedule:
            d["schedule"] = dict(self.schedule)
        if self.output:
            d["output"] = dict(self.output)
        return d


def validate_name(name: Any) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ProfileError(
            f"Profile name must be lowercase alphanumeric with '-' or '_' "
            f"(1–64 chars), got: {name!r}"
        )
    return name


def parse_profile(raw: dict, source_path: Optional[str] = None,
                  builtin: bool = False) -> Profile:
    """Validate and parse a raw YAML dict into a Profile.

    Raises :class:`ProfileError` on any structural problem.
    """
    if not isinstance(raw, dict):
        raise ProfileError(
            f"Profile must be a YAML mapping, got: {type(raw).__name__}"
        )

    if "name" not in raw:
        raise ProfileError("Profile is missing required 'name' field")

    name = validate_name(raw["name"])

    def _dict_section(key: str, valid_keys: Optional[set] = None) -> dict:
        val = raw.get(key)
        if val is None:
            return {}
        if not isinstance(val, dict):
            raise ProfileError(
                f"Profile {key!r} must be a mapping, got: {type(val).__name__}"
            )
        if valid_keys is not None:
            unknown = set(val.keys()) - valid_keys
            if unknown:
                raise ProfileError(
                    f"Profile {key!r} has unknown keys: "
                    f"{', '.join(sorted(unknown))}. "
                    f"Valid: {', '.join(sorted(valid_keys))}"
                )
        return val

    unknown_top = set(raw.keys()) - {
        "name", "description", "created", "last_run",
        "scan", "falsepos", "c2", "schedule", "output",
    }
    if unknown_top:
        raise ProfileError(
            f"Profile has unknown top-level keys: {', '.join(sorted(unknown_top))}"
        )

    desc = raw.get("description")
    if desc is not None and not isinstance(desc, str):
        raise ProfileError("Profile 'description' must be a string")

    created = raw.get("created")
    if created is not None and not isinstance(created, str):
        raise ProfileError("Profile 'created' must be an ISO-8601 string")

    last_run = raw.get("last_run")
    if last_run is not None and not isinstance(last_run, str):
        raise ProfileError("Profile 'last_run' must be an ISO-8601 string")

    scan = _dict_section("scan", VALID_SCAN_KEYS)
    if not scan:
        raise ProfileError("Profile 'scan' section is required and must not be empty")

    falsepos = _dict_section("falsepos", VALID_FALSEPOS_KEYS)
    c2 = _dict_section("c2", VALID_C2_KEYS)
    schedule = _dict_section("schedule", VALID_SCHEDULE_KEYS)
    output = _dict_section("output", VALID_OUTPUT_KEYS)

    return Profile(
        name=name,
        description=desc,
        created=created,
        last_run=last_run,
        scan=scan,
        falsepos=falsepos,
        c2=c2,
        schedule=schedule,
        output=output,
        source_path=source_path,
        builtin=builtin,
    )


# ── Environment variable substitution ─────────────────────────────────────

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env(value: Any, env: Optional[dict] = None) -> Any:
    """Recursively substitute ``${VAR}`` placeholders inside *value*.

    Only strings are touched. Undefined variables are replaced with an empty
    string — callers (e.g. ``profile run``) should validate required values
    after expansion.
    """
    import os
    env = env if env is not None else dict(os.environ)

    def _sub(s: str) -> str:
        return _ENV_RE.sub(lambda m: env.get(m.group(1), ""), s)

    if isinstance(value, str):
        return _sub(value)
    if isinstance(value, dict):
        return {k: expand_env(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v, env) for v in value]
    return value


def expand_profile(profile: Profile, env: Optional[dict] = None) -> Profile:
    """Return a copy of *profile* with ``${ENV}`` placeholders substituted."""
    return Profile(
        name=profile.name,
        description=profile.description,
        created=profile.created,
        last_run=profile.last_run,
        scan=expand_env(profile.scan, env),
        falsepos=expand_env(profile.falsepos, env),
        c2=expand_env(profile.c2, env),
        schedule=profile.schedule,
        output=expand_env(profile.output, env),
        source_path=profile.source_path,
        builtin=profile.builtin,
    )
