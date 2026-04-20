"""Translate a Profile into an ``evadex scan`` / ``evadex falsepos`` argv.

The runner deliberately does not invoke the commands itself — the caller
(usually ``evadex profile run``) uses these argv lists with either
:func:`subprocess.run` or Click's :class:`CliRunner` for tests. Keeping
this layer side-effect-free makes argv construction trivial to unit test.
"""
from __future__ import annotations

from typing import Optional

from evadex.profiles.schema import Profile, expand_profile


# Scan flags that accept multiple values (Click ``multiple=True``).
_SCAN_MULTI_FLAGS = {"strategy": "--strategy",
                     "categories": "--category",
                     "variant_groups": "--variant-group"}

# Scan flags that are booleans (``is_flag=True``).
_SCAN_BOOL_FLAGS = {
    "include_heuristic": "--include-heuristic",
    "require_context": "--require-context",
    "wrap_context": "--wrap-context",
}

# Scan flags that take a single value.
_SCAN_VALUE_FLAGS = {
    "tool": "--tool",
    "min_detection_rate": "--min-detection-rate",
    "scanner_label": "--scanner-label",
    "exe": "--exe",
    "cmd_style": "--cmd-style",
    "concurrency": "--concurrency",
    "timeout": "--timeout",
    "output": "--output",
    "format": "--format",
    "audit_log": "--audit-log",
    "tier": "--tier",
    "evasion_mode": "--evasion-mode",
    "input": "--input",
    "feedback_report": "--feedback-report",
    "url": "--url",
    "api_key": "--api-key",
}


_FALSEPOS_MULTI_FLAGS = {"categories": "--category"}

_FALSEPOS_BOOL_FLAGS = {
    "require_context": "--require-context",
    "wrap_context": "--wrap-context",
}

_FALSEPOS_VALUE_FLAGS = {
    "tool": "--tool",
    "count": "--count",
    "concurrency": "--concurrency",
    "seed": "--seed",
    "format": "--format",
    "output": "--output",
    "exe": "--exe",
    "cmd_style": "--cmd-style",
    "timeout": "--timeout",
    "url": "--url",
}


def profile_to_scan_argv(
    profile: Profile,
    extra: Optional[list] = None,
    expand: bool = True,
) -> list[str]:
    """Convert a profile's ``scan`` section into an argv list for ``evadex scan``.

    If ``expand=True`` (default), ``${ENV}`` placeholders are substituted
    before argv construction — the argv list is the thing actually shipped
    to the scanner subprocess, so it needs concrete values.

    The profile's ``c2`` section is promoted to ``--c2-url`` / ``--c2-key``
    because those flags live on the scan command, not in ``scan:`` itself.
    """
    p = expand_profile(profile) if expand else profile
    argv: list[str] = []

    scan = p.scan or {}
    for key, flag in _SCAN_VALUE_FLAGS.items():
        if key in scan and scan[key] is not None:
            argv += [flag, str(scan[key])]

    for key, flag in _SCAN_BOOL_FLAGS.items():
        if scan.get(key):
            argv.append(flag)

    for key, flag in _SCAN_MULTI_FLAGS.items():
        vals = scan.get(key)
        if vals is None:
            continue
        if isinstance(vals, str):
            argv += [flag, vals]
        else:
            for v in vals:
                argv += [flag, str(v)]

    if p.c2:
        if p.c2.get("url"):
            argv += ["--c2-url", str(p.c2["url"])]
        if p.c2.get("key"):
            argv += ["--c2-key", str(p.c2["key"])]

    if extra:
        argv += list(extra)

    return argv


def profile_to_falsepos_argv(
    profile: Profile,
    extra: Optional[list] = None,
    expand: bool = True,
) -> Optional[list[str]]:
    """Convert a profile's ``falsepos`` section into ``evadex falsepos`` argv.

    Returns ``None`` when the profile does not have ``falsepos.enabled: true``.
    The scanner binary config (``tool``, ``exe``, ``cmd_style``, ``timeout``,
    ``url``) is inherited from the ``scan`` section when absent from
    ``falsepos`` so a single profile can drive both runs.
    """
    p = expand_profile(profile) if expand else profile
    fp = p.falsepos or {}
    if not fp.get("enabled"):
        return None

    argv: list[str] = []
    scan = p.scan or {}

    # Inherit scanner binary config from scan unless falsepos overrides.
    inherited = {}
    for key in ("tool", "exe", "cmd_style", "timeout", "url"):
        if key in scan and key not in fp:
            inherited[key] = scan[key]
    effective = {**inherited, **fp}

    for key, flag in _FALSEPOS_VALUE_FLAGS.items():
        if key in effective and effective[key] is not None:
            argv += [flag, str(effective[key])]

    for key, flag in _FALSEPOS_BOOL_FLAGS.items():
        if effective.get(key):
            argv.append(flag)

    for key, flag in _FALSEPOS_MULTI_FLAGS.items():
        vals = effective.get(key)
        if vals is None:
            continue
        if isinstance(vals, str):
            argv += [flag, vals]
        else:
            for v in vals:
                argv += [flag, str(v)]

    if p.c2:
        if p.c2.get("url"):
            argv += ["--c2-url", str(p.c2["url"])]
        if p.c2.get("key"):
            argv += ["--c2-key", str(p.c2["key"])]

    if extra:
        argv += list(extra)

    return argv


def scan_flags_to_profile_dict(flags: dict) -> dict:
    """Map an ``evadex scan`` flag dict to the profile ``scan`` section.

    Used by ``evadex scan --save-as``. ``flags`` is a dict of the keys Click
    exposes on the scan function (e.g. ``tool``, ``tier``, ``strategies``,
    ``cmd_style``). Values that are None, empty tuples, or empty strings are
    dropped so the saved profile mirrors only what the user actually specified.
    """
    mapped: dict = {}
    passthrough = {
        "tool", "tier", "min_detection_rate", "scanner_label", "exe",
        "cmd_style", "concurrency", "timeout", "format", "audit_log",
        "evasion_mode", "input", "feedback_report", "url", "api_key",
        "include_heuristic", "require_context", "wrap_context",
    }
    # Click's scan uses ``strategies`` (tuple) and ``categories`` (tuple)
    # and ``variant_groups`` (tuple) — profile uses singular / list form.
    if flags.get("strategies"):
        mapped["strategy"] = list(flags["strategies"])
    if flags.get("categories"):
        mapped["categories"] = list(flags["categories"])
    if flags.get("variant_groups"):
        mapped["variant_groups"] = list(flags["variant_groups"])
    if flags.get("fmt"):
        mapped["format"] = flags["fmt"]
    if flags.get("input_value"):
        mapped["input"] = flags["input_value"]
    if flags.get("executable"):
        mapped["exe"] = flags["executable"]
    if flags.get("output"):
        mapped["output"] = flags["output"]

    for key in passthrough:
        val = flags.get(key)
        if val is None or val == "" or val == () or val is False:
            # ``False`` on a boolean flag means the user didn't pass it; no
            # point in persisting the default.
            continue
        # Click's --exe variable is named ``executable`` above; don't collide.
        if key in ("exe",):
            continue
        mapped[key] = val

    return mapped
