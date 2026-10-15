"""Unit tests for `evadex ci` — the scan and falsepos subprocesses are stubbed.

`ci` had no tests before v3.41.0, which is how `--max-fp` could read a key
that `evadex scan` never writes and pass every gate for nine releases.
"""

from __future__ import annotations

import json
import subprocess

import pytest
from click.testing import CliRunner

from evadex.cli.app import main
from evadex.cli.commands import ci as ci_module


def _scan_json(total=100, passes=80, fails=20, errors=0, seed=None, legacy=False):
    scored = passes + fails
    meta = {
        "total": total,
        "pass": passes,
        "fail": fails,
        "error": errors,
        "pass_rate": round(passes / total * 100, 1) if total else 0.0,
    }
    if not legacy:
        meta["detection_rate"] = round(passes / scored * 100, 1) if scored else 0.0
        meta["error_rate"] = round(errors / total * 100, 1) if total else 0.0
        meta["seed"] = seed
    return json.dumps({"meta": meta, "results": []})


def _fp_json(rate):
    return json.dumps(
        {
            "total_tested": 200,
            "total_flagged": int(rate * 2),
            "overall_false_positive_rate": rate,
        }
    )


class _FakeRun:
    """Stand-in for subprocess.run that answers scan and falsepos separately."""

    def __init__(self, scan_out, fp_out="", scan_rc=0, fp_rc=0):
        self.scan_out, self.fp_out = scan_out, fp_out
        self.scan_rc, self.fp_rc = scan_rc, fp_rc
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if "falsepos" in cmd:
            return subprocess.CompletedProcess(
                cmd, self.fp_rc, self.fp_out.encode(), b""
            )
        return subprocess.CompletedProcess(
            cmd, self.scan_rc, self.scan_out.encode(), b""
        )

    @property
    def scan_cmd(self):
        return next(c for c in self.calls if "scan" in c)

    @property
    def fp_cmd(self):
        return next((c for c in self.calls if "falsepos" in c), None)


@pytest.fixture
def fake_run(monkeypatch):
    holder = {}

    def install(**kw):
        fake = _FakeRun(**kw)
        monkeypatch.setattr(ci_module.subprocess, "run", fake)
        holder["fake"] = fake
        return fake

    return install


def _invoke(args):
    runner = CliRunner()
    with runner.isolated_filesystem():
        return runner.invoke(main, ["ci", *args])


# ── Detection threshold ─────────────────────────────────────────────────────


def test_passes_when_detection_meets_threshold(fake_run):
    fake_run(scan_out=_scan_json(passes=80, fails=20))
    res = _invoke(["--min-detection", "70"])
    assert res.exit_code == 0, res.output
    assert "All thresholds met" in res.output


def test_fails_when_detection_below_threshold(fake_run):
    fake_run(scan_out=_scan_json(passes=60, fails=40))
    res = _invoke(["--min-detection", "70"])
    assert res.exit_code == 1
    assert "thresholds violated" in res.output


def test_detection_rate_excludes_errored_submissions(fake_run):
    # 70 detected, 10 bypassed, 20 errored: pass_rate 70.0, detection_rate 87.5.
    fake_run(scan_out=_scan_json(passes=70, fails=10, errors=20))
    res = _invoke(["--min-detection", "80", "--max-error-rate", "25"])
    assert res.exit_code == 0, res.output
    assert "87.5%" in res.output


def test_legacy_scan_output_falls_back_to_pass_rate(fake_run):
    fake_run(scan_out=_scan_json(passes=70, fails=10, errors=20, legacy=True))
    res = _invoke(["--min-detection", "80", "--max-error-rate", "25"])
    assert res.exit_code == 1
    assert "70.0%" in res.output


# ── Error gate ──────────────────────────────────────────────────────────────


def test_too_many_errors_is_inconclusive_exit_2(fake_run):
    fake_run(scan_out=_scan_json(passes=50, fails=0, errors=50))
    res = _invoke(["--min-detection", "10"])
    assert res.exit_code == 2
    assert "Inconclusive" in res.output


def test_error_gate_default_is_five_percent(fake_run):
    fake_run(scan_out=_scan_json(passes=94, fails=0, errors=6))
    assert _invoke(["--min-detection", "10"]).exit_code == 2
    fake_run(scan_out=_scan_json(passes=95, fails=0, errors=5))
    assert _invoke(["--min-detection", "10"]).exit_code == 0


# ── False-positive gate ─────────────────────────────────────────────────────


def test_max_fp_runs_falsepos_and_fails_above_threshold(fake_run):
    fake = fake_run(scan_out=_scan_json(), fp_out=_fp_json(8.0))
    res = _invoke(["--min-detection", "10", "--max-fp", "5"])
    assert res.exit_code == 1
    assert fake.fp_cmd is not None
    assert "8.0%" in res.output


def test_max_fp_passes_below_threshold(fake_run):
    fake_run(scan_out=_scan_json(), fp_out=_fp_json(2.0))
    res = _invoke(["--min-detection", "10", "--max-fp", "5"])
    assert res.exit_code == 0, res.output


def test_falsepos_invocation_flags(fake_run):
    fake = fake_run(scan_out=_scan_json(), fp_out=_fp_json(0.0))
    _invoke(
        [
            "--min-detection",
            "10",
            "--max-fp",
            "5",
            "--fp-count",
            "37",
            "--seed",
            "99",
            "--url",
            "http://x:1",
        ]
    )
    cmd = fake.fp_cmd
    assert cmd[-0:] and "--format" in cmd and cmd[cmd.index("--format") + 1] == "json"
    assert cmd[cmd.index("--count") + 1] == "37"
    assert "--wrap-context" in cmd
    assert cmd[cmd.index("--seed") + 1] == "99"
    assert cmd[cmd.index("--url") + 1] == "http://x:1"


def test_fp_category_forwarded_once_per_value(fake_run):
    fake = fake_run(scan_out=_scan_json(), fp_out=_fp_json(0.0))
    _invoke(
        [
            "--min-detection",
            "10",
            "--max-fp",
            "5",
            "--fp-category",
            "ssn",
            "--fp-category",
            "iban",
        ]
    )
    cmd = fake.fp_cmd
    cats = [cmd[i + 1] for i, tok in enumerate(cmd) if tok == "--category"]
    assert cats == ["ssn", "iban"]


def test_no_fp_category_means_falsepos_default_set(fake_run):
    fake = fake_run(scan_out=_scan_json(), fp_out=_fp_json(0.0))
    _invoke(["--min-detection", "10", "--max-fp", "5"])
    assert "--category" not in fake.fp_cmd


def test_falsepos_failure_is_inconclusive_not_a_pass(fake_run):
    fake_run(scan_out=_scan_json(), fp_out="", fp_rc=1)
    res = _invoke(["--min-detection", "10", "--max-fp", "5"])
    assert res.exit_code == 2
    assert "cannot report a pass" in res.output


def test_no_max_fp_means_no_falsepos_run(fake_run):
    fake = fake_run(scan_out=_scan_json())
    _invoke(["--min-detection", "10"])
    assert fake.fp_cmd is None


# ── Seed plumbing ───────────────────────────────────────────────────────────


def test_seed_forwarded_to_scan(fake_run):
    fake = fake_run(scan_out=_scan_json(seed=4242))
    res = _invoke(["--min-detection", "10", "--seed", "4242"])
    cmd = fake.scan_cmd
    assert cmd[cmd.index("--seed") + 1] == "4242"
    assert "4242" in res.output


def test_without_seed_flag_scan_is_not_given_one(fake_run):
    fake = fake_run(scan_out=_scan_json())
    _invoke(["--min-detection", "10"])
    assert "--seed" not in fake.scan_cmd
