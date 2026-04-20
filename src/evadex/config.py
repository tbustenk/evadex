"""Config file loading, validation, and default generation for evadex."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

CONFIG_FILENAME = "evadex.yaml"

VALID_TOOLS = {"dlpscan-cli", "dlpscan", "presidio"}
VALID_STRATEGIES = {"text", "docx", "pdf", "xlsx"}
VALID_FORMATS = {"json", "html"}
VALID_CMD_STYLES = {"python", "rust"}
VALID_CATEGORIES = {
    "credit_card", "ssn", "sin", "iban", "swift_bic", "aba_routing",
    "bitcoin", "ethereum", "us_passport", "au_tfn", "de_tax_id", "fr_insee",
    "email", "phone", "aws_key", "jwt", "github_token", "stripe_key",
    "slack_token", "classification", "unknown",
}
VALID_TIERS = {"banking", "core", "regional", "full"}
KNOWN_KEYS = {
    "tool", "strategy", "min_detection_rate", "scanner_label", "exe",
    "cmd_style", "categories", "include_heuristic", "concurrency",
    "timeout", "output", "format", "audit_log", "require_context",
    "wrap_context", "tier",
    # Siphon-C2 management-plane integration
    "c2_url", "c2_key",
    # Smart evasion selection (v3.13.0+)
    "evasion_mode",
}

DEFAULT_CONFIG_YAML = """\
# evadex configuration file
# Run 'evadex scan --config evadex.yaml' to use this file.
# CLI flags take precedence over values in this file.

tool: dlpscan-cli
strategy: text
min_detection_rate: 85
scanner_label: production
exe: null
cmd_style: python
# tier: banking   # banking (default) | core | regional | full
# categories:     # explicit category list — overrides tier when set
#   - credit_card
#   - ssn
#   - iban
include_heuristic: false
concurrency: 20
timeout: 30.0
output: results.json
format: json
# audit_log: evadex_audit.jsonl
# require_context: false  # Pass --require-context to dlpscan-rs (requires cmd_style: rust)
# wrap_context: false     # Embed every variant in a keyword sentence before submission.
#                         # Auto-enabled when cmd_style: rust. dlpscan-rs ignores bare
#                         # values without context — leave unset unless you need to override.

# Siphon-C2 management-plane integration — push scan / falsepos / compare
# results to an admin dashboard. Safe to leave disabled (commented out);
# C2 push never blocks or fails a scan even when the URL is unreachable.
# c2_url: http://localhost:9090
# c2_key: CHANGEME   # sent as x-api-key header (same auth as Siphon's API)

# Smart evasion selection (v3.13.0+).
# 'random' = uniform; 'exhaustive' = every applicable variant (scan default);
# 'weighted' = bias toward techniques that have evaded best in past runs;
# 'adversarial' = restrict to techniques with ≤ 50% historical detection.
# Reads history from audit_log above. Cold-start falls back to random.
# evasion_mode: random
"""


@dataclass
class EvadexConfig:
    tool: Optional[str] = None
    strategy: Optional[list[str]] = None
    min_detection_rate: Optional[float] = None
    scanner_label: Optional[str] = None
    exe: Optional[str] = None
    cmd_style: Optional[str] = None
    categories: Optional[list[str]] = None
    include_heuristic: Optional[bool] = None
    concurrency: Optional[int] = None
    timeout: Optional[float] = None
    output: Optional[str] = None
    format: Optional[str] = None
    audit_log: Optional[str] = None
    require_context: Optional[bool] = None
    wrap_context: Optional[bool] = None
    tier: Optional[str] = None
    # Siphon-C2 management-plane push. URL enables the integration;
    # key authenticates via the same `x-api-key` header Siphon's HTTP API
    # uses. Both may also come from EVADEX_C2_URL / EVADEX_C2_KEY.
    c2_url: Optional[str] = None
    c2_key: Optional[str] = None
    evasion_mode: Optional[str] = None


def find_config() -> Optional[Path]:
    """Return path to evadex.yaml in the current directory, or None."""
    candidate = Path.cwd() / CONFIG_FILENAME
    return candidate if candidate.is_file() else None


def load_config(path: "str | Path") -> EvadexConfig:
    """Load and validate an evadex.yaml config file.

    Raises click.UsageError with a clear message on any validation failure.
    """
    import click

    try:
        import yaml
    except ImportError:
        raise click.UsageError(
            "PyYAML is required for config file support. "
            "Install it with: pip install pyyaml"
        )

    path = Path(path)
    if not path.is_file():
        raise click.UsageError(f"Config file not found: {path}")

    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    if raw is None:
        return EvadexConfig()

    if not isinstance(raw, dict):
        raise click.UsageError(
            f"Config file must be a YAML mapping, got: {type(raw).__name__}"
        )

    unknown = set(raw.keys()) - KNOWN_KEYS
    if unknown:
        raise click.UsageError(
            f"Unknown config key(s): {', '.join(sorted(unknown))}. "
            f"Valid keys: {', '.join(sorted(KNOWN_KEYS))}"
        )

    cfg = EvadexConfig()

    if "tool" in raw:
        val = raw["tool"]
        if not isinstance(val, str) or val not in VALID_TOOLS:
            raise click.UsageError(
                f"Config 'tool' must be one of: {', '.join(sorted(VALID_TOOLS))}, "
                f"got: {val!r}"
            )
        cfg.tool = val

    if "strategy" in raw:
        val = raw["strategy"]
        if isinstance(val, str):
            strategies = [val]
        elif isinstance(val, list):
            strategies = val
        else:
            raise click.UsageError(
                f"Config 'strategy' must be a string or list, got: {type(val).__name__}"
            )
        bad = [s for s in strategies if s not in VALID_STRATEGIES]
        if bad:
            raise click.UsageError(
                f"Invalid strategy value(s): {', '.join(bad)}. "
                f"Valid: {', '.join(sorted(VALID_STRATEGIES))}"
            )
        cfg.strategy = strategies

    if "min_detection_rate" in raw:
        val = raw["min_detection_rate"]
        if val is not None:
            if not isinstance(val, (int, float)):
                raise click.UsageError(
                    f"Config 'min_detection_rate' must be a number from 0 to 100, got: {val!r}"
                )
            if not (0.0 <= val <= 100.0):
                raise click.UsageError(
                    f"Config 'min_detection_rate' must be from 0 to 100, got: {val}"
                )
            cfg.min_detection_rate = float(val)

    if "scanner_label" in raw:
        val = raw["scanner_label"]
        if val is not None and not isinstance(val, str):
            raise click.UsageError(
                f"Config 'scanner_label' must be a string, got: {type(val).__name__}"
            )
        cfg.scanner_label = str(val) if val is not None else None

    if "exe" in raw:
        val = raw["exe"]
        if val is not None and not isinstance(val, str):
            raise click.UsageError(
                f"Config 'exe' must be a string or null, got: {type(val).__name__}"
            )
        cfg.exe = val

    if "cmd_style" in raw:
        val = raw["cmd_style"]
        if val is not None:
            if not isinstance(val, str) or val not in VALID_CMD_STYLES:
                raise click.UsageError(
                    f"Config 'cmd_style' must be one of: {', '.join(sorted(VALID_CMD_STYLES))}, "
                    f"got: {val!r}"
                )
            cfg.cmd_style = val

    if "categories" in raw:
        val = raw["categories"]
        if val is not None:
            if not isinstance(val, list):
                raise click.UsageError(
                    f"Config 'categories' must be a list, got: {type(val).__name__}"
                )
            if len(val) == 0:
                raise click.UsageError(
                    "Config 'categories' must not be empty. "
                    "Remove the key to run all structured categories."
                )
            bad = [c for c in val if c not in VALID_CATEGORIES]
            if bad:
                raise click.UsageError(
                    f"Invalid category value(s): {', '.join(bad)}. "
                    f"Valid: {', '.join(sorted(VALID_CATEGORIES))}"
                )
            cfg.categories = list(val)

    if "include_heuristic" in raw:
        val = raw["include_heuristic"]
        if not isinstance(val, bool):
            raise click.UsageError(
                f"Config 'include_heuristic' must be true or false, got: {val!r}"
            )
        cfg.include_heuristic = val

    if "concurrency" in raw:
        val = raw["concurrency"]
        if not isinstance(val, int) or val < 1:
            raise click.UsageError(
                f"Config 'concurrency' must be a positive integer, got: {val!r}"
            )
        cfg.concurrency = val

    if "timeout" in raw:
        val = raw["timeout"]
        if not isinstance(val, (int, float)) or float(val) <= 0:
            raise click.UsageError(
                f"Config 'timeout' must be a positive number, got: {val!r}"
            )
        cfg.timeout = float(val)

    if "output" in raw:
        val = raw["output"]
        if val is not None and not isinstance(val, str):
            raise click.UsageError(
                f"Config 'output' must be a string or null, got: {type(val).__name__}"
            )
        cfg.output = val

    if "format" in raw:
        val = raw["format"]
        if val not in VALID_FORMATS:
            raise click.UsageError(
                f"Config 'format' must be one of: {', '.join(sorted(VALID_FORMATS))}, "
                f"got: {val!r}"
            )
        cfg.format = val

    if "audit_log" in raw:
        val = raw["audit_log"]
        if val is not None and not isinstance(val, str):
            raise click.UsageError(
                f"Config 'audit_log' must be a string or null, got: {type(val).__name__}"
            )
        cfg.audit_log = val

    if "require_context" in raw:
        val = raw["require_context"]
        if not isinstance(val, bool):
            raise click.UsageError(
                f"Config 'require_context' must be true or false, got: {val!r}"
            )
        cfg.require_context = val

    if "wrap_context" in raw:
        val = raw["wrap_context"]
        if not isinstance(val, bool):
            raise click.UsageError(
                f"Config 'wrap_context' must be true or false, got: {val!r}"
            )
        cfg.wrap_context = val

    if "tier" in raw:
        val = raw["tier"]
        if val is not None:
            if not isinstance(val, str) or val not in VALID_TIERS:
                raise click.UsageError(
                    f"Config 'tier' must be one of: {', '.join(sorted(VALID_TIERS))}, "
                    f"got: {val!r}"
                )
            cfg.tier = val

    for key in ("c2_url", "c2_key"):
        if key in raw:
            val = raw[key]
            if val is not None and not isinstance(val, str):
                raise click.UsageError(
                    f"Config {key!r} must be a string or null, got: {type(val).__name__}"
                )
            setattr(cfg, key, val)

    if "evasion_mode" in raw:
        val = raw["evasion_mode"]
        valid = {"random", "weighted", "adversarial", "exhaustive"}
        if val is not None and val not in valid:
            raise click.UsageError(
                f"Config 'evasion_mode' must be one of: {', '.join(sorted(valid))}, "
                f"got: {val!r}"
            )
        cfg.evasion_mode = val

    return cfg
