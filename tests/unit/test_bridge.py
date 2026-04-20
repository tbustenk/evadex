"""Tests for the evadex HTTP bridge — /v1/evadex/run, metrics, generate.

The bridge shells out to ``evadex`` for runs and generation; these tests
use fake audit fixtures + a monkeypatched subprocess runner so they stay
fast and hermetic. A real end-to-end test lives in
``tests/integration`` once the CLI surface stabilises.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("fastapi")  # [bridge] extra
from fastapi.testclient import TestClient

from evadex.bridge import categories
from evadex.bridge import metrics as metrics_mod
from evadex.bridge import runs as runs_mod
from evadex.bridge.server import create_app


# ── Fixtures ─────────────────────────────────────────────────────

@pytest.fixture
def audit_tree(tmp_path: Path) -> Path:
    """Populate a temp dir with an audit log + a matching scan archive.

    Returns the temp root path. The fixture writes:
        ./results/audit.jsonl       (2 scans + 1 falsepos)
        ./results/scans/scan_*.json (summary_by_category for latest scan)
        ./results/falsepos/falsepos_*.json
    """
    root = tmp_path
    (root / "results" / "scans").mkdir(parents=True)
    (root / "results" / "falsepos").mkdir(parents=True)

    scan_archive = root / "results" / "scans" / "scan_latest.json"
    scan_archive.write_text(json.dumps({
        "meta": {
            "timestamp": "2026-04-20T06:00:00+00:00",
            "scanner": "siphon-cli",
            "total": 500, "pass": 435, "fail": 65, "error": 0,
            "pass_rate": 87.0,
            "categories_total": 557,
            "summary_by_category": {
                "credit_card": {"pass": 120, "fail": 5,  "error": 0},
                "iban":        {"pass": 80,  "fail": 2,  "error": 0},
                "ssn":         {"pass": 70,  "fail": 10, "error": 0},
                "email":       {"pass": 50,  "fail": 8,  "error": 0},
                "aws_key":     {"pass": 60,  "fail": 4,  "error": 0},
                "bitcoin":     {"pass": 55,  "fail": 36, "error": 0},
            },
            "technique_success_rates": {
                "homoglyph_substitution": 0.82,
                "zero_width_space":        0.91,
                "base64_of_rot13":         0.78,
            },
        },
    }), encoding="utf-8")

    fp_archive = root / "results" / "falsepos" / "falsepos_latest.json"
    fp_archive.write_text(json.dumps({
        "meta": {
            "timestamp": "2026-04-20T07:00:00+00:00",
            "total_tested": 800, "total_flagged": 99, "fp_rate": 12.4,
            "fp_by_category": {"email": 7, "phone": 4, "credit_card": 3},
        },
    }), encoding="utf-8")

    audit_log = root / "results" / "audit.jsonl"
    entries = [
        {"timestamp": "2026-04-19T06:00:00+00:00", "type": "scan",
         "tool": "siphon-cli", "scanner_label": "banking-pci-ca",
         "categories": ["credit_card"], "strategies": ["text"],
         "total": 500, "pass": 430, "fail": 70, "pass_rate": 86.0,
         "archive_file": "results/scans/scan_latest.json"},
        {"timestamp": "2026-04-20T06:00:00+00:00", "type": "scan",
         "tool": "siphon-cli", "scanner_label": "banking-pci-ca",
         "categories": ["credit_card", "iban", "ssn", "aws_key", "bitcoin"],
         "strategies": ["text"],
         "total": 500, "pass": 435, "fail": 65, "pass_rate": 87.0,
         "archive_file": "results/scans/scan_latest.json",
         "technique_success_rates": {
             "homoglyph_substitution": 0.82,
             "zero_width_space":        0.91,
             "base64_of_rot13":         0.78,
         }},
        {"timestamp": "2026-04-20T07:00:00+00:00", "type": "falsepos",
         "tool": "siphon-cli", "scanner_label": "banking-pci-ca",
         "categories": ["email", "phone", "credit_card"],
         "total_tested": 800, "total_flagged": 99, "fp_rate": 12.4,
         "archive_file": "results/falsepos/falsepos_latest.json"},
    ]
    with open(audit_log, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    return root


@pytest.fixture
def client(audit_tree: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(audit_tree))
    monkeypatch.delenv("EVADEX_BRIDGE_KEY", raising=False)
    runs_mod.reset()
    app = create_app()
    return TestClient(app)


# ── Category mapping ─────────────────────────────────────────────

class TestCategoryMapping:
    def test_pci_expands_to_financial_categories(self):
        expanded = categories.expand("PCI")
        assert "credit_card" in expanded
        assert "iban" in expanded
        assert "swift_bic" in expanded

    def test_cred_expands_to_credentials(self):
        expanded = categories.expand("CRED")
        assert "aws_key" in expanded
        assert "github_token" in expanded

    def test_unknown_bucket_returns_empty(self):
        assert categories.expand("NOT_A_BUCKET") == []

    def test_bucket_for_category_is_inverse(self):
        assert categories.bucket_for_category("credit_card") == "PCI"
        assert categories.bucket_for_category("aws_key") == "CRED"
        assert categories.bucket_for_category("bitcoin") == "CRYPTO"

    def test_unknown_category_falls_back_to_other(self):
        assert categories.bucket_for_category("totally_made_up") == "OTHER"

    def test_expand_many_dedupes(self):
        out = categories.expand_many(["PCI", "PII"])
        assert len(out) == len(set(out))


# ── /v1/evadex/metrics ──────────────────────────────────────────

class TestMetricsEndpoint:
    def test_shape_has_all_required_keys(self, client: TestClient):
        r = client.get("/v1/evadex/metrics")
        assert r.status_code == 200
        data = r.json()
        for k in (
            "detection_rate", "detection_trend", "fp_rate", "fp_trend",
            "coverage", "patterns_tested", "patterns_total",
            "last_run", "last_run_id", "by_category", "top_evasions",
            "history",
        ):
            assert k in data, f"missing key {k!r}"

    def test_detection_rate_from_latest_scan(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        assert data["detection_rate"] == pytest.approx(87.0)

    def test_fp_rate_from_latest_falsepos(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        assert data["fp_rate"] == pytest.approx(12.4)

    def test_coverage_computed_from_summary(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        # 6 categories in summary_by_category / 557 total
        assert data["patterns_tested"] == 6
        assert data["patterns_total"] == 557
        assert data["coverage"] == pytest.approx(round(6 / 557 * 100, 1))

    def test_by_category_rolls_up_to_c2_buckets(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        pci = data["by_category"]["PCI"]
        # credit_card (120/5) + iban (80/2)
        assert pci["tp"] == 200
        assert pci["fn"] == 7
        # FP was 3 (credit_card) from falsepos_by_category
        assert pci["fp"] == 3
        assert pci["recall"] > 90.0

    def test_top_evasions_ranked(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        names = [e["technique"] for e in data["top_evasions"]]
        assert "zero_width_space" in names
        # Highest first
        rates = [e["success_rate"] for e in data["top_evasions"]]
        assert rates == sorted(rates, reverse=True)

    def test_history_has_ten_slots_or_fewer(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        assert len(data["history"]) <= 10
        # Newest first
        assert data["history"][0]["when"] == "2026-04-20T06:00:00+00:00"

    def test_empty_audit_log_returns_zeros(self, tmp_path: Path,
                                            monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        app = create_app()
        r = TestClient(app).get("/v1/evadex/metrics")
        data = r.json()
        assert data["detection_rate"] == 0.0
        assert data["fp_rate"] == 0.0
        assert data["history"] == []


# ── /v1/evadex/run ──────────────────────────────────────────────

class TestRunEndpoint:
    def test_returns_run_id_and_queued_status(self, client: TestClient,
                                               monkeypatch: pytest.MonkeyPatch):
        # Stub out the async subprocess — we only care about the response shape.
        async def _fake_execute(run_id, argv, cwd):  # noqa: ARG001
            runs_mod._RUNS[run_id]["status"] = runs_mod.STATUS_COMPLETED
            runs_mod._RUNS[run_id]["exit_code"] = 0
        monkeypatch.setattr(runs_mod, "_execute", _fake_execute)

        r = client.post("/v1/evadex/run", json={
            "profile": "banking-pci-ca",
            "tier": "banking",
            "evasion_mode": "weighted",
            "tool": "siphon-cli",
            "scanner_label": "siphon-prod",
        })
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == runs_mod.STATUS_QUEUED
        assert body["run_id"].startswith("R-")
        assert "started_at" in body

    def test_c2_buckets_are_expanded_before_launch(self, client: TestClient,
                                                    monkeypatch: pytest.MonkeyPatch):
        captured: dict = {}

        def _fake_launch(body, cwd=None):
            captured["body"] = body
            return {
                "run_id": "R-TEST", "status": runs_mod.STATUS_QUEUED,
                "started_at": "2026-04-20T00:00:00Z", "finished_at": None,
                "argv": [], "request": body, "exit_code": None,
                "stdout_tail": "", "stderr_tail": "",
            }
        monkeypatch.setattr(runs_mod, "launch", _fake_launch)

        r = client.post("/v1/evadex/run", json={"categories": ["PCI", "CRED"]})
        assert r.status_code == 202
        cats = captured["body"]["categories"]
        assert "credit_card" in cats  # from PCI
        assert "aws_key" in cats      # from CRED

    def test_run_status_404_for_unknown_id(self, client: TestClient):
        r = client.get("/v1/evadex/run/R-DOES-NOT-EXIST")
        assert r.status_code == 404


# ── /v1/evadex/generate ─────────────────────────────────────────

class TestGenerateEndpoint:
    def test_returns_file_download(self, client: TestClient,
                                    monkeypatch: pytest.MonkeyPatch):
        # Fake subprocess.run that writes bytes to the output path.
        from evadex.bridge import server as server_mod

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        def _fake_run(argv, **kw):
            # Find --output PATH in the argv and write bytes to it.
            for i, a in enumerate(argv):
                if a == "--output":
                    Path(argv[i + 1]).write_bytes(b"col1,col2\n1,2\n")
                    break
            return _Proc()

        monkeypatch.setattr(server_mod.subprocess, "run", _fake_run)

        r = client.post("/v1/evadex/generate", json={
            "format": "csv", "tier": "banking", "category": "PCI",
            "count": 50, "evasion_rate": 0.3, "language": "en",
            "template": "statement",
        })
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/octet-stream")
        assert b"col1,col2" in r.content

    def test_evasion_rate_accepts_0_to_100(self, client: TestClient,
                                            monkeypatch: pytest.MonkeyPatch):
        from evadex.bridge import server as server_mod
        captured: dict = {}

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        def _fake_run(argv, **kw):
            captured["argv"] = argv
            for i, a in enumerate(argv):
                if a == "--output":
                    Path(argv[i + 1]).write_bytes(b"x")
                    break
            return _Proc()

        monkeypatch.setattr(server_mod.subprocess, "run", _fake_run)

        r = client.post("/v1/evadex/generate", json={
            "format": "csv", "count": 1, "evasion_rate": 30,  # percent-style
        })
        assert r.status_code == 200
        # --evasion-rate should be normalised into 0–1
        argv = captured["argv"]
        i = argv.index("--evasion-rate")
        assert float(argv[i + 1]) == pytest.approx(0.3, abs=1e-3)

    def test_generate_failure_returns_500(self, client: TestClient,
                                           monkeypatch: pytest.MonkeyPatch):
        from evadex.bridge import server as server_mod

        class _Proc:
            returncode = 2
            stdout = ""
            stderr = "boom"

        monkeypatch.setattr(server_mod.subprocess, "run", lambda *a, **k: _Proc())
        r = client.post("/v1/evadex/generate", json={"format": "csv", "count": 1})
        assert r.status_code == 500


# ── CORS + auth ──────────────────────────────────────────────────

class TestCorsAndAuth:
    def test_cors_allows_any_origin_by_default(self, client: TestClient):
        r = client.options(
            "/v1/evadex/metrics",
            headers={
                "origin": "http://localhost:1234",
                "access-control-request-method": "GET",
            },
        )
        # Starlette answers OPTIONS with the CORS headers set.
        assert r.status_code in (200, 204)
        assert r.headers.get("access-control-allow-origin") in ("*",
                                                                 "http://localhost:1234")

    def test_api_key_required_when_configured(self, audit_tree: Path,
                                                monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(audit_tree))
        monkeypatch.setenv("EVADEX_BRIDGE_KEY", "secret-123")
        app = create_app()
        c = TestClient(app)
        # No header → 401
        r = c.get("/v1/evadex/metrics")
        assert r.status_code == 401
        # Wrong header → 401
        r = c.get("/v1/evadex/metrics", headers={"x-api-key": "nope"})
        assert r.status_code == 401
        # Correct header → 200
        r = c.get("/v1/evadex/metrics", headers={"x-api-key": "secret-123"})
        assert r.status_code == 200

    def test_healthz_always_open(self, audit_tree: Path,
                                  monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("EVADEX_BRIDGE_KEY", "secret-123")
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(audit_tree))
        app = create_app()
        r = TestClient(app).get("/healthz")
        assert r.status_code == 200
        assert r.json()["ok"] is True
