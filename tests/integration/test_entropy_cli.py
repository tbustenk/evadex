"""End-to-end tests for the `evadex entropy` command.

The DLP adapter is stubbed with SimpleAdapter (a minimal BaseAdapter
subclass) so these tests don't require a running Siphon server.
"""
import json

import pytest
from click.testing import CliRunner

from evadex.adapters.base import BaseAdapter
from evadex.cli.app import main
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, ScanResult, Variant


@register_adapter("entropy-stub")
class _EntropyStubAdapter(BaseAdapter):
    """Fake adapter: detects if the submitted text contains ``api_key`` OR ``=``.

    That mirrors a scanner running in EntropyMode::Gated+Assignment — it
    flags gated and assignment contexts but not bare values.
    """

    name = "entropy-stub"

    async def health_check(self) -> bool:
        return True

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        text = variant.value.lower()
        detected = ("api_key" in text) or ("secret_token=" in text.lower())
        return ScanResult(
            payload=payload, variant=variant, detected=detected,
            confidence=0.91 if detected else None,
        )


def _cli_run(args: list[str]) -> tuple[int, str]:
    runner = CliRunner()
    result = runner.invoke(main, args)
    return result.exit_code, result.output


def test_entropy_command_runs_and_emits_json(tmp_path):
    """The entropy command should run end to end and produce a valid JSON report."""
    out = tmp_path / "report.json"
    code, _ = _cli_run([
        "entropy",
        "--tool", "entropy-stub",
        "--url", "http://unused",
        "--no-evasion",
        "--format", "json",
        "--output", str(out),
    ])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"] == "entropy-stub"
    assert data["contexts"] == ["bare", "gated", "assignment"]
    assert isinstance(data["summary"], dict)
    # Every registered entropy category should appear in the summary
    from evadex.payloads.builtins import ENTROPY_CATEGORIES
    cats_reported = set(data["summary"].keys())
    cats_expected = {c.value for c in ENTROPY_CATEGORIES}
    assert cats_expected == cats_reported


def test_entropy_command_reports_context_split(tmp_path):
    """Stub adapter only flags gated + assignment → those buckets should sum up."""
    out = tmp_path / "report.json"
    _cli_run([
        "entropy", "--tool", "entropy-stub", "--url", "http://x",
        "--no-evasion", "-f", "json", "-o", str(out),
    ])
    data = json.loads(out.read_text(encoding="utf-8"))
    summary = data["summary"]
    # Aggregate across categories
    total = {"bare": 0, "gated": 0, "assignment": 0}
    hits = {"bare": 0, "gated": 0, "assignment": 0}
    for cat, buckets in summary.items():
        for ctx, stat in buckets.items():
            total[ctx] += stat["tested"]
            hits[ctx] += stat["detected"]
    # Bare never contains 'api_key' or '=' → zero hits
    assert hits["bare"] == 0
    # Both gated and assignment include the keyword → every one should hit
    assert hits["gated"] == total["gated"] > 0
    assert hits["assignment"] == total["assignment"] > 0


def test_entropy_command_mode_assessment(tmp_path):
    """Passing --mode gated should produce a coverage score for gated contexts only."""
    out = tmp_path / "report.json"
    _cli_run([
        "entropy", "--tool", "entropy-stub", "--url", "http://x",
        "--mode", "gated", "--no-evasion", "-f", "json", "-o", str(out),
    ])
    data = json.loads(out.read_text(encoding="utf-8"))
    assess = data["mode_assessment"]
    assert assess is not None
    assert assess["mode"] == "gated"
    assert assess["expected_contexts"] == ["gated"]
    # Stub flags gated → 100% coverage expected
    assert assess["coverage_pct"] == 100.0


def test_entropy_command_evasion_section(tmp_path):
    """With evasion enabled, the report includes entropy_evasion technique results."""
    out = tmp_path / "report.json"
    code, _ = _cli_run([
        "entropy", "--tool", "entropy-stub", "--url", "http://x",
        "-f", "json", "-o", str(out),
    ])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["evasion_results"], "evasion results should not be empty"
    techniques = {r["technique"] for r in data["evasion_results"]}
    assert techniques >= {
        "entropy_split",
        "entropy_comment",
        "entropy_concat",
        "entropy_low_mix",
        "entropy_encode",
        "entropy_space",
    }


def test_entropy_command_fails_when_adapter_unreachable():
    """Health check failure should exit non-zero with a clear message."""
    code, output = _cli_run([
        "entropy",
        "--tool", "siphon",
        "--url", "http://unreachable-host:1",
        "--timeout", "0.5",
        "--no-evasion",
    ])
    assert code != 0
    assert "Health check failed" in output or "unreachable" in output.lower()
