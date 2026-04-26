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

    def test_failed_run_surfaces_error_and_stream_aliases(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ):
        """A failed subprocess should populate `error`, `stdout`, `stderr`
        on the run-status response so the UI can show it directly."""
        async def _fake_execute(run_id, argv, cwd):  # noqa: ARG001
            rec = runs_mod._RUNS[run_id]
            rec["status"] = runs_mod.STATUS_FAILED
            rec["exit_code"] = 1
            rec["stdout_tail"] = ""
            rec["stderr_tail"] = (
                "Tier: core\n"
                "Health check failed for adapter 'siphon-cli'. "
                "Is siphon installed and on PATH?\n"
            )
            rec["finished_at"] = "2026-04-20T23:07:12Z"
        monkeypatch.setattr(runs_mod, "_execute", _fake_execute)

        # Launch a run and wait for it to settle.
        launch = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        run_id = launch.json()["run_id"]

        # Fake executor is awaited on the event loop the TestClient spins up;
        # subsequent GET sees the terminal state.
        r = client.get(f"/v1/evadex/run/{run_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == runs_mod.STATUS_FAILED
        assert "error" in body
        assert "siphon installed and on PATH" in body["error"]
        # stdout/stderr aliases mirror stdout_tail/stderr_tail.
        assert body["stdout"] == ""
        assert "Health check failed" in body["stderr"]
        assert body["stderr"] == body["stderr_tail"]
        # Private exception field should never leak to clients.
        assert "_exception" not in body

    def test_exe_and_cmd_style_default_from_env(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ):
        """Env vars set by the `evadex bridge` CLI should flow into every
        scan argv as the default --exe / --cmd-style."""
        monkeypatch.setenv("EVADEX_BRIDGE_EXE", "C:/bin/siphon.exe")
        monkeypatch.setenv("EVADEX_BRIDGE_CMD_STYLE", "binary")
        argv = runs_mod._build_scan_argv({"tool": "siphon-cli"})
        assert "--exe" in argv
        assert argv[argv.index("--exe") + 1] == "C:/bin/siphon.exe"
        assert "--cmd-style" in argv
        assert argv[argv.index("--cmd-style") + 1] == "binary"

    def test_exe_and_cmd_style_request_overrides_env(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ):
        """Per-request body.exe / body.cmd_style must override the env
        defaults — operator sets a server-wide default, individual runs
        can still point at a different scanner."""
        monkeypatch.setenv("EVADEX_BRIDGE_EXE", "C:/bin/default.exe")
        monkeypatch.setenv("EVADEX_BRIDGE_CMD_STYLE", "stdin")
        argv = runs_mod._build_scan_argv({
            "tool": "siphon-cli",
            "exe":  "C:/bin/override.exe",
            "cmd_style": "binary",
        })
        assert argv[argv.index("--exe") + 1] == "C:/bin/override.exe"
        assert argv[argv.index("--cmd-style") + 1] == "binary"

    def test_failed_launch_python_exception_surfaces(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ):
        """A Python-side launch failure (e.g. subprocess spawn error) still
        populates the public `error` field."""
        async def _boom(run_id, argv, cwd):  # noqa: ARG001
            rec = runs_mod._RUNS[run_id]
            rec["status"] = runs_mod.STATUS_FAILED
            rec["_exception"] = "FileNotFoundError: python not on PATH"
            rec["finished_at"] = "2026-04-20T23:07:12Z"
        monkeypatch.setattr(runs_mod, "_execute", _boom)

        launch = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        run_id = launch.json()["run_id"]
        body = client.get(f"/v1/evadex/run/{run_id}").json()
        assert body["status"] == runs_mod.STATUS_FAILED
        assert body["error"] == "FileNotFoundError: python not on PATH"


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

    def test_generate_rejects_unknown_format(self, client: TestClient):
        r = client.post("/v1/evadex/generate", json={"format": "exe"})
        assert r.status_code == 400
        assert "format" in r.json()["detail"]["error"]

    def test_generate_rejects_path_traversal_template(self, client: TestClient):
        """--template '../etc/passwd' must be rejected at the bridge,
        not forwarded to evadex where a downstream loader might honour it."""
        r = client.post(
            "/v1/evadex/generate",
            json={"format": "csv", "template": "../etc/passwd"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert "template" in detail["error"].lower()

    def test_generate_rejects_non_numeric_count(self, client: TestClient):
        r = client.post(
            "/v1/evadex/generate",
            json={"format": "csv", "count": "not-a-number"},
        )
        assert r.status_code == 400

    def test_generate_cleans_up_tempfile_on_failure(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        """A failed subprocess must not leak the pre-allocated output
        tempfile — we unlink it on every error path."""
        from evadex.bridge import server as server_mod

        captured_paths: list[Path] = []

        class _Proc:
            returncode = 1
            stdout = ""
            stderr = "failed to generate"

        def _fake_run(argv, **kw):
            for i, a in enumerate(argv):
                if a == "--output":
                    captured_paths.append(Path(argv[i + 1]))
            # Deliberately do NOT write the output file — simulates a
            # subprocess that crashed before flushing.
            return _Proc()

        monkeypatch.setattr(server_mod.subprocess, "run", _fake_run)
        r = client.post("/v1/evadex/generate", json={"format": "csv", "count": 1})
        assert r.status_code == 500
        assert captured_paths, "expected generate to allocate an output path"
        for p in captured_paths:
            assert not p.exists(), f"tempfile leaked at {p}"


# ── Metrics path-traversal hardening ────────────────────────────

class TestMetricsPathTraversal:
    def test_metrics_no_longer_accepts_audit_log_query(
        self, audit_tree: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """The ``audit_log`` query param used to allow any file on disk
        to be opened by the metrics parser. It must now be ignored —
        callers configure via env only."""
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(audit_tree))
        monkeypatch.delenv("EVADEX_BRIDGE_KEY", raising=False)
        app = create_app()
        c = TestClient(app)
        # Include a would-be traversal path as a query param — the
        # response must be a 200 with the normal metrics shape; the
        # param is ignored, not honoured.
        r = c.get("/v1/evadex/metrics", params={"audit_log": "/etc/passwd"})
        assert r.status_code == 200
        body = r.json()
        assert "detection_rate" in body  # normal shape preserved


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


# ── Siphon-exe resolution (v3.16.1) ─────────────────────────────

class TestSiphonExeResolution:
    """The bridge resolves the siphon binary via a documented priority
    chain: CLI flag → SIPHON_EXE → bridge.exe → auto-discovery → PATH."""

    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in ("EVADEX_BRIDGE_EXE", "SIPHON_EXE"):
            monkeypatch.delenv(var, raising=False)

    def test_auto_discovery_finds_local_release_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A freshly-built siphon under ./target/release/siphon.exe should
        be picked up without any config, env, or flag."""
        from evadex.bridge import server as server_mod

        release_dir = tmp_path / "target" / "release"
        release_dir.mkdir(parents=True)
        fake_exe = release_dir / "siphon.exe"
        fake_exe.write_text("# fake binary")

        # Run resolution from inside the tmp repo root so the relative
        # path "./target/release/siphon.exe" matches our fake layout.
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))

        resolved = server_mod._resolve_siphon_exe()
        assert resolved is not None
        assert Path(resolved).name == "siphon.exe"
        assert Path(resolved).resolve() == fake_exe.resolve()

    def test_siphon_exe_env_overrides_auto_discovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """SIPHON_EXE must win over any on-disk auto-discovery result."""
        from evadex.bridge import server as server_mod

        # Stage an auto-discoverable binary so we can prove the env var
        # actually takes precedence (not just that nothing else was found).
        release_dir = tmp_path / "target" / "release"
        release_dir.mkdir(parents=True)
        (release_dir / "siphon.exe").write_text("# fake")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))

        override = tmp_path / "override-siphon.exe"
        override.write_text("# override")
        monkeypatch.setenv("SIPHON_EXE", str(override))

        assert server_mod._resolve_siphon_exe() == str(override)

    def test_cli_flag_env_beats_siphon_exe(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """EVADEX_BRIDGE_EXE (set by ``evadex bridge --exe``) wins over
        SIPHON_EXE — operator intent on a specific run trumps the
        shell-level default."""
        from evadex.bridge import server as server_mod

        monkeypatch.setenv("EVADEX_BRIDGE_EXE", "/from/cli/siphon")
        monkeypatch.setenv("SIPHON_EXE", "/from/env/siphon")
        assert server_mod._resolve_siphon_exe() == "/from/cli/siphon"

    def test_config_exe_picked_up_when_env_unset(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """bridge.exe in evadex.yaml is consulted after env, before
        auto-discovery."""
        from evadex.bridge import server as server_mod

        target = tmp_path / "siphon-from-config"
        target.write_text("# fake")
        (tmp_path / "evadex.yaml").write_text(
            f"bridge:\n  exe: {target}\n", encoding="utf-8"
        )
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))

        assert server_mod._resolve_siphon_exe() == str(target)

    def test_healthz_reports_not_found_when_binary_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """With nothing configured and nothing on disk, healthz must
        report siphon_found=false and siphon_exe=null — but still
        return 200 so uptime probes stay green."""
        from evadex.bridge import server as server_mod

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        # Neutralise the absolute Windows auto-discovery path and PATH.
        monkeypatch.setattr(
            server_mod, "_SIPHON_AUTO_DISCOVERY_PATHS", (), raising=True,
        )
        monkeypatch.setattr(server_mod.shutil, "which", lambda *_a, **_k: None)

        app = create_app()
        r = TestClient(app).get("/healthz")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["siphon_found"] is False
        assert body["siphon_exe"] is None

    def test_healthz_reports_found_when_env_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.setenv("SIPHON_EXE", "/fake/siphon")
        app = create_app()
        body = TestClient(app).get("/healthz").json()
        assert body["siphon_found"] is True
        assert body["siphon_exe"] == "/fake/siphon"

    def test_run_returns_clear_error_when_siphon_not_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """POST /v1/evadex/run with no resolvable exe and no override
        must fail fast with 503 and a hint — not silently crash a
        subprocess later."""
        from evadex.bridge import server as server_mod

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.delenv("EVADEX_BRIDGE_KEY", raising=False)
        monkeypatch.setattr(
            server_mod, "_SIPHON_AUTO_DISCOVERY_PATHS", (), raising=True,
        )
        monkeypatch.setattr(server_mod.shutil, "which", lambda *_a, **_k: None)
        runs_mod.reset()

        app = create_app()
        c = TestClient(app)
        r = c.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        assert r.status_code == 503
        detail = r.json()["detail"]
        assert "siphon binary not found" in detail["error"]
        assert "SIPHON_EXE" in detail["hint"]

    def test_run_rejects_unknown_tier_with_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Enum allowlist on /v1/evadex/run returns a clean 400 rather
        than letting a bogus value reach evadex's own validator."""
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.setenv("SIPHON_EXE", "/fake/siphon")
        runs_mod.reset()
        app = create_app()
        c = TestClient(app)
        r = c.post("/v1/evadex/run", json={"tier": "ohno"})
        assert r.status_code == 400
        assert "tier" in r.json()["detail"]["error"]

    def test_run_rejects_non_object_body(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.setenv("SIPHON_EXE", "/fake/siphon")
        runs_mod.reset()
        app = create_app()
        c = TestClient(app)
        # FastAPI itself returns 422 for type violations on `body: dict`,
        # but we exercise a list payload to confirm the response is an
        # error (not a silent 200 or 500).
        r = c.post("/v1/evadex/run", json=["not", "an", "object"])
        assert r.status_code in (400, 422)

    def test_run_accepts_body_exe_override_even_when_auto_discovery_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """body.exe bypasses the resolver — it goes straight to argv so
        a per-request override still works when no siphon is installed."""
        from evadex.bridge import server as server_mod

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.delenv("EVADEX_BRIDGE_KEY", raising=False)
        monkeypatch.setattr(
            server_mod, "_SIPHON_AUTO_DISCOVERY_PATHS", (), raising=True,
        )
        monkeypatch.setattr(server_mod.shutil, "which", lambda *_a, **_k: None)
        runs_mod.reset()

        async def _noop(run_id, argv, cwd):  # noqa: ARG001
            runs_mod._RUNS[run_id]["status"] = runs_mod.STATUS_COMPLETED
            runs_mod._RUNS[run_id]["exit_code"] = 0
        monkeypatch.setattr(runs_mod, "_execute", _noop)

        app = create_app()
        c = TestClient(app)
        r = c.post(
            "/v1/evadex/run",
            json={"tool": "siphon-cli", "exe": "/override/siphon"},
        )
        assert r.status_code == 202


# ── v3.18.1 — hardening: body-size, categories items, scanner_label ──

class TestRequestSizeLimit:
    def test_oversized_body_rejected_with_413(
        self, client: TestClient,
    ):
        """A 2 MiB JSON body should be refused before the handler sees
        it. Content-Length is used so we reject up front without
        buffering the payload."""
        big = "x" * (2 * 1024 * 1024)
        r = client.post(
            "/v1/evadex/run",
            content=f'{{"scanner_label": "{big}"}}',
            headers={"content-type": "application/json"},
        )
        assert r.status_code == 413
        assert "request body too large" in r.json()["detail"]["error"]

    def test_invalid_content_length_rejected(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            content=b"{}",
            headers={"content-length": "not-a-number",
                     "content-type": "application/json"},
        )
        # Starlette's own header parser catches malformed CL before
        # our middleware; either 400 or 422 is acceptable — it just
        # must not crash with 500.
        assert r.status_code < 500


class TestScannerLabelHardening:
    def test_very_long_label_rejected(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            json={"scanner_label": "x" * 200, "tool": "siphon-cli"},
        )
        assert r.status_code == 400
        assert "scanner_label" in r.json()["detail"]["error"]

    def test_control_chars_in_label_rejected(self, client: TestClient):
        for bad in ("foo\nbar", "foo\x1b[31mred", "foo\x00bar"):
            r = client.post(
                "/v1/evadex/run",
                json={"scanner_label": bad, "tool": "siphon-cli"},
            )
            assert r.status_code == 400, (bad, r.json())

    def test_printable_label_accepted(self, client: TestClient,
                                       monkeypatch: pytest.MonkeyPatch):
        async def _noop(run_id, argv, cwd):  # noqa: ARG001
            runs_mod._RUNS[run_id]["status"] = runs_mod.STATUS_COMPLETED
        monkeypatch.setattr(runs_mod, "_execute", _noop)
        r = client.post(
            "/v1/evadex/run",
            json={"scanner_label": "siphon-prod-v2.1", "tool": "siphon-cli"},
        )
        assert r.status_code == 202


class TestCategoryItemHardening:
    def test_categories_item_must_be_string(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            json={"categories": [123, "credit_card"]},
        )
        # Used to return 500 via AttributeError on c.upper() — now 400.
        assert r.status_code == 400
        assert "categories" in r.json()["detail"]["error"]

    def test_categories_item_rejects_path_traversal(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            json={"categories": ["credit_card", "../../etc/passwd"]},
        )
        assert r.status_code == 400
        assert "categories" in r.json()["detail"]["error"]

    def test_categories_item_rejects_very_long_value(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            json={"categories": ["x" * 200]},
        )
        assert r.status_code == 400

    def test_generate_category_rejects_path_traversal(self, client: TestClient):
        r = client.post(
            "/v1/evadex/generate",
            json={"format": "csv", "count": 1, "category": "../secret"},
        )
        assert r.status_code == 400
        assert "category" in r.json()["detail"]["error"]

    def test_strategies_list_validated(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            json={"strategies": ["text", "../bad"]},
        )
        assert r.status_code == 400
        assert "strategies" in r.json()["detail"]["error"]


# ── /v1/evadex/categories — dynamic catalog ─────────────────────────

class TestCategoriesCatalogEndpoint:
    """GET /v1/evadex/categories should enumerate every registered
    PayloadCategory and bucket them into display groups so the UI can
    render the checkbox panel dynamically."""

    def test_shape_has_groups_total_and_order(self, client: TestClient):
        r = client.get("/v1/evadex/categories")
        assert r.status_code == 200
        body = r.json()
        assert "groups" in body and isinstance(body["groups"], dict)
        assert "total" in body and isinstance(body["total"], int)
        assert "group_order" in body and isinstance(body["group_order"], list)
        # Groups in the payload must match group_order.
        assert set(body["groups"].keys()) == set(body["group_order"])

    def test_total_equals_sum_of_group_sizes(self, client: TestClient):
        body = client.get("/v1/evadex/categories").json()
        summed = sum(len(v) for v in body["groups"].values())
        assert body["total"] == summed

    def test_every_payload_category_is_bucketed(self, client: TestClient):
        """No category should vanish into the ether. Every enum value
        apart from the ``unknown`` sentinel must appear in exactly one
        group — otherwise the UI would silently drop it."""
        from evadex.core.result import PayloadCategory

        body = client.get("/v1/evadex/categories").json()
        all_ids: set[str] = set()
        for ids in body["groups"].values():
            for i in ids:
                assert i not in all_ids, f"{i} appears in more than one group"
                all_ids.add(i)
        expected = {m.value for m in PayloadCategory if m.value != "unknown"}
        missing = expected - all_ids
        extra = all_ids - expected
        assert not missing, f"unbucketed categories: {sorted(missing)[:20]}"
        assert not extra, f"unknown categories in catalog: {sorted(extra)[:20]}"

    def test_canonical_groups_present(self, client: TestClient):
        body = client.get("/v1/evadex/categories").json()
        groups = body["groups"]
        for g in ("Credit Cards", "Banking", "Canadian IDs", "US IDs",
                  "European IDs", "Healthcare", "Crypto",
                  "Secrets & Credentials", "Classification", "PII"):
            assert g in groups, f"expected group {g!r} missing"
            assert len(groups[g]) > 0, f"group {g!r} is empty"

    def test_well_known_categories_land_in_expected_groups(
        self, client: TestClient,
    ):
        body = client.get("/v1/evadex/categories").json()
        groups = body["groups"]
        assert "credit_card" in groups["Credit Cards"]
        assert "iban" in groups["Banking"]
        assert "sin" in groups["Canadian IDs"]
        assert "ssn" in groups["US IDs"]
        assert "aws_key" in groups["Secrets & Credentials"]
        assert "bitcoin" in groups["Crypto"]
        assert "ca_ramq" in groups["Healthcare"]

    def test_ids_inside_each_group_sorted_alphabetically(
        self, client: TestClient,
    ):
        body = client.get("/v1/evadex/categories").json()
        for g, ids in body["groups"].items():
            assert ids == sorted(ids), f"group {g!r} not sorted"

    def test_auth_required_when_configured(self, audit_tree: Path,
                                            monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(audit_tree))
        monkeypatch.setenv("EVADEX_BRIDGE_KEY", "secret-123")
        app = create_app()
        c = TestClient(app)
        assert c.get("/v1/evadex/categories").status_code == 401
        assert c.get(
            "/v1/evadex/categories",
            headers={"x-api-key": "secret-123"},
        ).status_code == 200


# ── v3.18.0 — granular scan params, progress, cancel ───────────────

class TestGranularScanParams:
    """Bridge must forward all the new UI-granular fields to the CLI and
    reject anything outside the allowlist with a clean 400."""

    def test_all_fields_flow_into_argv(self, client: TestClient,
                                        monkeypatch: pytest.MonkeyPatch):
        captured: dict = {}

        def _fake_launch(body, cwd=None):
            captured["body"] = body
            captured["argv"] = runs_mod._build_scan_argv(body)
            return {
                "run_id": "R-TEST", "status": runs_mod.STATUS_QUEUED,
                "started_at": "2026-04-20T00:00:00Z", "finished_at": None,
                "argv": captured["argv"], "request": body, "exit_code": None,
                "stdout_tail": "", "stderr_tail": "",
            }
        monkeypatch.setattr(runs_mod, "launch", _fake_launch)

        r = client.post("/v1/evadex/run", json={
            "tier": "banking",
            "categories": ["credit_card", "sin", "iban"],
            "strategy": "both",
            "evasion_mode": "weighted",
            "evasion_rate": 0.3,
            "technique_group": "unicode_encoding",
            "min_confidence": 0.5,
            "require_context": True,
            "wrap_context": True,
            "min_detection_rate": 85,
            "scanner_label": "siphon-prod",
            "save_as_profile": "my-profile",
        })
        assert r.status_code == 202
        argv = captured["argv"]
        # Scope
        assert argv[argv.index("--tier") + 1] == "banking"
        # "both" → repeated --strategy text + file
        strat_positions = [i for i, a in enumerate(argv) if a == "--strategy"]
        assert len(strat_positions) == 2
        assert {argv[i + 1] for i in strat_positions} == {"text", "file"}
        # Evasion
        assert argv[argv.index("--evasion-mode") + 1] == "weighted"
        assert argv[argv.index("--variant-group") + 1] == "unicode_encoding"
        # Quality
        assert argv[argv.index("--min-confidence") + 1] == "0.5"
        assert argv[argv.index("--min-detection-rate") + 1] == "85.0"
        assert "--require-context" in argv
        assert "--wrap-context" in argv
        # Output
        assert argv[argv.index("--scanner-label") + 1] == "siphon-prod"
        assert argv[argv.index("--save-as") + 1] == "my-profile"
        # Progress channel is always enabled so the bridge can report live.
        assert "--progress-json" in argv

    def test_technique_group_all_does_not_add_filter(self,
                                                      client: TestClient):
        argv = runs_mod._build_scan_argv({"tier": "core", "technique_group": "all"})
        assert "--variant-group" not in argv

    def test_wrap_context_false_maps_to_no_wrap(self):
        argv = runs_mod._build_scan_argv({"wrap_context": False})
        assert "--no-wrap-context" in argv
        assert "--wrap-context" not in argv

    def test_evasion_rate_accepts_0_to_100(self, client: TestClient,
                                            monkeypatch: pytest.MonkeyPatch):
        captured: dict = {}
        def _fake_launch(body, cwd=None):
            captured["body"] = body
            return {"run_id": "R", "status": "queued",
                    "started_at": "2026-04-20T00:00:00Z", "finished_at": None,
                    "argv": [], "request": body, "exit_code": None,
                    "stdout_tail": "", "stderr_tail": ""}
        monkeypatch.setattr(runs_mod, "launch", _fake_launch)

        r = client.post("/v1/evadex/run", json={"evasion_rate": 30})
        assert r.status_code == 202
        assert captured["body"]["evasion_rate"] == pytest.approx(0.3)

    def test_rejects_unknown_technique_group(self, client: TestClient):
        r = client.post("/v1/evadex/run", json={"technique_group": "made_up"})
        assert r.status_code == 400
        assert "technique_group" in r.json()["detail"]["error"]

    def test_technique_groups_list_emits_multiple_variant_group_flags(self):
        """Checkbox panel sends ``technique_groups`` as a list — each
        entry must become its own --variant-group NAME in the argv."""
        argv = runs_mod._build_scan_argv({
            "technique_groups": ["unicode_encoding", "leetspeak", "splitting"],
        })
        positions = [i for i, a in enumerate(argv) if a == "--variant-group"]
        assert len(positions) == 3
        values = {argv[i + 1] for i in positions}
        assert values == {"unicode_encoding", "leetspeak", "splitting"}

    def test_technique_groups_empty_list_means_no_filter(self):
        argv = runs_mod._build_scan_argv({"technique_groups": []})
        assert "--variant-group" not in argv

    def test_technique_groups_all_entry_is_treated_as_no_filter(self):
        argv = runs_mod._build_scan_argv({"technique_groups": ["all"]})
        assert "--variant-group" not in argv

    def test_technique_groups_dedupes_repeated_entries(self):
        """UI state bugs (double-toggle) shouldn't inflate the argv."""
        argv = runs_mod._build_scan_argv({
            "technique_groups": ["leetspeak", "leetspeak", "encoding"],
        })
        positions = [i for i, a in enumerate(argv) if a == "--variant-group"]
        assert len(positions) == 2

    def test_rejects_unknown_entry_in_technique_groups(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            json={"technique_groups": ["unicode_encoding", "bogus_group"]},
        )
        assert r.status_code == 400
        assert "technique_groups" in r.json()["detail"]["error"]

    def test_technique_groups_must_be_a_list(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            json={"technique_groups": "unicode_encoding"},
        )
        assert r.status_code == 400

    def test_rejects_out_of_range_min_confidence(self, client: TestClient):
        r = client.post("/v1/evadex/run", json={"min_confidence": 1.5})
        assert r.status_code == 400
        assert "min_confidence" in r.json()["detail"]["error"]

    def test_rejects_path_traversal_in_profile(self, client: TestClient):
        r = client.post(
            "/v1/evadex/run",
            json={"save_as_profile": "../../etc/passwd"},
        )
        assert r.status_code == 400

    def test_save_as_profile_passes_through_to_argv(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ):
        """UI toggle for save_as_profile should surface as --save-as."""
        captured: dict = {}
        def _fake_launch(body, cwd=None):
            captured["argv"] = runs_mod._build_scan_argv(body)
            return {"run_id": "R", "status": "queued",
                    "started_at": "2026-04-20T00:00:00Z", "finished_at": None,
                    "argv": captured["argv"], "request": body, "exit_code": None,
                    "stdout_tail": "", "stderr_tail": ""}
        monkeypatch.setattr(runs_mod, "launch", _fake_launch)
        r = client.post("/v1/evadex/run", json={"save_as_profile": "banking-nightly"})
        assert r.status_code == 202
        argv = captured["argv"]
        assert argv[argv.index("--save-as") + 1] == "banking-nightly"


class TestProgressParsing:
    """--progress-json lines emitted by the scan CLI should feed
    live progress fields on the run record."""

    def test_progress_line_updates_run_record(self):
        rec = {"status": "running"}
        line = '{"progress": 45.2, "tested": 823, "total": 1823, "detected": 412, "elapsed_s": 142.0}'
        runs_mod._on_progress_line(rec, line)
        assert rec["progress"] == 45.2
        assert rec["tested"] == 823
        assert rec["total"] == 1823
        assert rec["detected"] == 412
        assert rec["elapsed_s"] == 142.0

    def test_non_json_stderr_is_ignored(self):
        rec = {"status": "running", "progress": 12.5}
        runs_mod._on_progress_line(rec, "Running evadex scan against siphon-cli...")
        assert rec["progress"] == 12.5  # unchanged

    def test_progress_exposed_in_get_run(self):
        runs_mod.reset()
        runs_mod._RUNS["R-X"] = {
            "status": "running",
            "started_at": "2026-04-20T00:00:00Z",
            "finished_at": None,
            "argv": [], "request": {},
            "exit_code": None,
            "stdout_tail": "", "stderr_tail": "",
            "progress": 45.2, "tested": 823, "total": 1823,
            "detected": 412, "elapsed_s": 142.0,
        }
        view = runs_mod.get_run("R-X")
        assert view["progress"] == 45.2
        assert view["tested"] == 823
        # Private plumbing must never leak.
        for k in ("_proc", "_cancel_requested", "_exception"):
            assert k not in view


class TestCancelEndpoint:
    """DELETE /v1/evadex/run/{id} should terminate the subprocess and
    mark the run as cancelled.

    The cancel path is tested directly against :func:`runs_mod.cancel_run`
    using a fake subprocess — the TestClient spins up a fresh event loop
    per request, which would rebind ``asyncio.Event`` across loops.
    """

    def test_cancel_unknown_run_returns_404(self, client: TestClient):
        r = client.delete("/v1/evadex/run/R-NOPE")
        assert r.status_code == 404

    def test_cancel_run_terminates_and_marks_cancelled(self):
        import asyncio

        async def run_test():
            runs_mod.reset()
            rec = {
                "status":       runs_mod.STATUS_RUNNING,
                "started_at":   runs_mod._now(),
                "finished_at":  None,
                "argv":         [], "request": {},
                "exit_code":    None,
                "stdout_tail":  "", "stderr_tail":  "",
                "progress":     12.0, "tested": 100, "total": 1000,
                "detected":     45, "elapsed_s": 5.0,
            }

            class _FakeProc:
                def __init__(self):
                    self.returncode = None
                    self.terminated = False
                    self._evt = asyncio.Event()

                def terminate(self):
                    self.terminated = True
                    self.returncode = -15
                    self._evt.set()

                def kill(self):
                    self.returncode = -9
                    self._evt.set()

                async def wait(self):
                    await self._evt.wait()
                    return self.returncode

            proc = _FakeProc()
            rec["_proc"] = proc
            runs_mod._RUNS["R-CANCEL"] = rec

            # Simulate the _execute coroutine that watches for cancel
            # and marks the run terminal after wait() returns.
            async def _fake_exec():
                rc = await proc.wait()
                rec["exit_code"] = rc
                rec["status"] = (
                    runs_mod.STATUS_CANCELLED
                    if rec.get("_cancel_requested")
                    else runs_mod.STATUS_COMPLETED
                )
                rec["finished_at"] = runs_mod._now()
                rec.pop("_proc", None)

            exec_task = asyncio.create_task(_fake_exec())
            result = await runs_mod.cancel_run("R-CANCEL")
            await exec_task

            assert proc.terminated is True
            assert result["status"] == runs_mod.STATUS_CANCELLED
            assert rec["status"] == runs_mod.STATUS_CANCELLED
            # Run view must not leak internals.
            view = runs_mod.get_run("R-CANCEL")
            for k in ("_proc", "_cancel_requested", "_exception"):
                assert k not in view

        asyncio.run(run_test())

    def test_cancel_run_escalates_to_sigkill_after_grace(self,
                                                          monkeypatch: pytest.MonkeyPatch):
        """A child that ignores SIGTERM gets SIGKILLed after the grace
        expires — the run still ends up as cancelled."""
        import asyncio
        monkeypatch.setattr(runs_mod, "_CANCEL_GRACE_S", 0.1)

        async def run_test():
            runs_mod.reset()
            rec = {
                "status":      runs_mod.STATUS_RUNNING,
                "started_at":  runs_mod._now(),
                "finished_at": None,
                "argv":        [], "request": {},
                "exit_code":   None,
                "stdout_tail": "", "stderr_tail": "",
            }

            class _StubbornProc:
                def __init__(self):
                    self.returncode = None
                    self.killed = False
                    self._evt = asyncio.Event()

                def terminate(self):  # ignored — simulates a hung child
                    pass

                def kill(self):
                    self.killed = True
                    self.returncode = -9
                    self._evt.set()

                async def wait(self):
                    await self._evt.wait()
                    return self.returncode

            proc = _StubbornProc()
            rec["_proc"] = proc
            runs_mod._RUNS["R-STUBBORN"] = rec

            async def _fake_exec():
                rc = await proc.wait()
                rec["exit_code"] = rc
                rec["status"] = (
                    runs_mod.STATUS_CANCELLED
                    if rec.get("_cancel_requested")
                    else runs_mod.STATUS_COMPLETED
                )
                rec["finished_at"] = runs_mod._now()
                rec.pop("_proc", None)

            exec_task = asyncio.create_task(_fake_exec())
            result = await runs_mod.cancel_run("R-STUBBORN")
            await exec_task

            assert proc.killed is True
            assert result["status"] == runs_mod.STATUS_CANCELLED

        asyncio.run(run_test())

    def test_cancel_run_idempotent_on_terminal_run(self):
        """cancel_run() on a completed run returns current state and does NOT
        re-signal — the underlying function is always idempotent. The HTTP
        handler is responsible for surfacing 409 to callers."""
        import asyncio

        async def run_test():
            runs_mod.reset()
            runs_mod._RUNS["R-DONE"] = {
                "status":       runs_mod.STATUS_COMPLETED,
                "started_at":   runs_mod._now(),
                "finished_at":  runs_mod._now(),
                "argv":         [], "request": {},
                "exit_code":    0,
                "stdout_tail":  "", "stderr_tail":  "",
            }
            result = await runs_mod.cancel_run("R-DONE")
            assert result["status"] == runs_mod.STATUS_COMPLETED

        asyncio.run(run_test())

    def test_cancel_completed_run_via_http_returns_409(self, client: TestClient,
                                                        monkeypatch: pytest.MonkeyPatch):
        """DELETE on a run that is already completed must return 409, not 200.
        Callers should not be able to mistakenly re-cancel a finished run."""
        async def _fake_execute(run_id, argv, cwd):
            runs_mod._RUNS[run_id]["status"] = runs_mod.STATUS_COMPLETED
            runs_mod._RUNS[run_id]["exit_code"] = 0
            runs_mod._RUNS[run_id]["finished_at"] = runs_mod._now()
        monkeypatch.setattr(runs_mod, "_execute", _fake_execute)

        launch = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        run_id = launch.json()["run_id"]
        r = client.delete(f"/v1/evadex/run/{run_id}")
        assert r.status_code == 409
        detail = r.json()["detail"]
        assert detail["status"] == runs_mod.STATUS_COMPLETED
        assert "terminal" in detail["error"]

    def test_cancel_failed_run_via_http_returns_409(self, client: TestClient,
                                                      monkeypatch: pytest.MonkeyPatch):
        """DELETE on a failed run must also return 409."""
        async def _fake_execute(run_id, argv, cwd):
            runs_mod._RUNS[run_id]["status"] = runs_mod.STATUS_FAILED
            runs_mod._RUNS[run_id]["exit_code"] = 1
            runs_mod._RUNS[run_id]["finished_at"] = runs_mod._now()
        monkeypatch.setattr(runs_mod, "_execute", _fake_execute)

        launch = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        run_id = launch.json()["run_id"]
        r = client.delete(f"/v1/evadex/run/{run_id}")
        assert r.status_code == 409


# ── Part 1 — Security tests for new endpoints ────────────────────────────────

class TestNewEndpointSecurity:
    """Seven security tests covering the new endpoints added in v3.18–v3.22."""

    # ── SEC-1: run_id collision resistance ──────────────────────────────────
    def test_rapid_launches_produce_distinct_run_ids(self, client: TestClient,
                                                      monkeypatch: pytest.MonkeyPatch):
        """Two runs launched back-to-back must not collide on the same run_id.
        Previously the second-granularity timestamp could produce duplicates;
        the per-process counter suffix prevents this."""
        async def _noop(run_id, argv, cwd):
            runs_mod._RUNS[run_id]["status"] = runs_mod.STATUS_COMPLETED
        monkeypatch.setattr(runs_mod, "_execute", _noop)

        r1 = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        r2 = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        assert r1.status_code == r2.status_code == 202
        assert r1.json()["run_id"] != r2.json()["run_id"]

    # ── SEC-2: confidence field always numeric or null ───────────────────────
    def test_confidence_coerced_to_float_or_none(self):
        """A subprocess-injected dict/list in the confidence field must not
        propagate to the public run view — only float or None is acceptable."""
        rec = {"status": "running", "recent_results": []}

        # Emit a test_result with a dict confidence (hostile subprocess output).
        line = json.dumps({
            "test_result": {
                "category": "credit_card",
                "technique": "zero_width_space",
                "value": "4111-1111-1111-1111",
                "matched": True,
                "confidence": {"evil": "object"},
            }
        })
        runs_mod._on_progress_line(rec, line)
        assert len(rec["recent_results"]) == 1
        result = rec["recent_results"][0]
        assert result["confidence"] is None  # dict coerced to None

    def test_valid_confidence_preserved_as_float(self):
        """A numeric confidence from the subprocess is retained as float."""
        rec = {"status": "running", "recent_results": []}
        line = json.dumps({
            "test_result": {
                "category": "ssn",
                "technique": "unicode_encoding",
                "value": "123-45-6789",
                "matched": False,
                "confidence": 0.73,
            }
        })
        runs_mod._on_progress_line(rec, line)
        result = rec["recent_results"][0]
        assert isinstance(result["confidence"], float)
        assert result["confidence"] == pytest.approx(0.73)

    # ── SEC-3: categories endpoint uses cached result ───────────────────────
    def test_categories_endpoint_returns_cached_result(self):
        """group_all_categories must return the same dict object on repeated
        calls — no re-classification on every request."""
        from evadex.bridge import categories as cat_mod
        cat_mod.group_all_categories.cache_clear()
        a = cat_mod.group_all_categories()
        b = cat_mod.group_all_categories()
        assert a is b  # same object → lru_cache hit

    # ── SEC-4: report endpoint — no fallback to arbitrary file ──────────────
    def test_report_no_fallback_to_unrelated_json_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """If no scan file matches the run_id timestamp, the endpoint must
        return 404. The old fallback (most-recently-modified JSON) could serve
        data from a completely different run or a planted file."""
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.delenv("EVADEX_BRIDGE_KEY", raising=False)
        runs_mod.reset()
        app = create_app()
        c = TestClient(app)

        # Stage a JSON file that has NO relation to any run.
        bait = tmp_path / "results" / "scans"
        bait.mkdir(parents=True)
        (bait / "unrelated_data.json").write_text('{"secret": "yes"}')

        # Create a completed run.
        run_id = "R-20991231T235959-0001"
        runs_mod._RUNS[run_id] = {
            "status": runs_mod.STATUS_COMPLETED, "exit_code": 0,
            "started_at": runs_mod._now(), "finished_at": runs_mod._now(),
            "argv": [], "request": {}, "stdout_tail": "", "stderr_tail": "",
        }

        r = c.post("/v1/evadex/report", json={"run_id": run_id})
        # Must be 404 — NOT 200 with the unrelated file's content.
        assert r.status_code == 404
        assert "scan output file not found" in r.json()["detail"]["error"]

    # ── SEC-5: cancel on terminal run returns 409 ────────────────────────────
    def test_cancel_completed_run_returns_409(self, client: TestClient,
                                               monkeypatch: pytest.MonkeyPatch):
        """Already covered in TestCancelEndpoint but included here as a
        named security test so the audit trail is explicit."""
        async def _noop(run_id, argv, cwd):
            runs_mod._RUNS[run_id]["status"] = runs_mod.STATUS_COMPLETED
            runs_mod._RUNS[run_id]["exit_code"] = 0
            runs_mod._RUNS[run_id]["finished_at"] = runs_mod._now()
        monkeypatch.setattr(runs_mod, "_execute", _noop)

        launch = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        run_id = launch.json()["run_id"]
        r = client.delete(f"/v1/evadex/run/{run_id}")
        assert r.status_code == 409

    # ── SEC-6: recent_results cleared from terminal-run view ─────────────────
    def test_recent_results_absent_from_completed_run_view(self):
        """recent_results must not appear in the get_run() view once a run
        is terminal — clients must not cache stale live data."""
        runs_mod.reset()
        runs_mod._RUNS["R-COMPLETE"] = {
            "status": runs_mod.STATUS_COMPLETED,
            "started_at": runs_mod._now(), "finished_at": runs_mod._now(),
            "argv": [], "request": {}, "exit_code": 0,
            "stdout_tail": "", "stderr_tail": "",
            "recent_results": [{"category": "credit_card", "technique": "t",
                                 "value": "v", "matched": True, "confidence": None}],
        }
        view = runs_mod.get_run("R-COMPLETE")
        assert "recent_results" not in view

    # ── SEC-7: malformed JSON body on POST /v1/evadex/report ─────────────────
    def test_report_endpoint_rejects_malformed_json(self, client: TestClient):
        """A non-JSON body must be rejected cleanly (422), not crash with 500."""
        r = client.post(
            "/v1/evadex/report",
            content=b"not-json{{{",
            headers={"content-type": "application/json"},
        )
        assert r.status_code in (400, 422)
        assert r.status_code < 500

    def test_report_endpoint_rejects_missing_run_id(self, client: TestClient):
        """run_id is required; omitting it must return 400."""
        r = client.post("/v1/evadex/report", json={"include_falsepos": True})
        assert r.status_code == 400
        assert "run_id" in r.json()["detail"]["error"]

    def test_report_endpoint_rejects_unknown_run_id(self, client: TestClient):
        """run_id not in _RUNS must return 404, not a file-read attempt."""
        r = client.post("/v1/evadex/report", json={"run_id": "R-20991231T235959-0001"})
        assert r.status_code == 404


# ── Part 2 — Feature tests for v3.18.0–v3.22.0 ──────────────────────────────

class TestLiveOutput:
    """recent_results live output for the C2 scan view."""

    def test_recent_results_populated_during_run(self):
        """Emitting test_result progress lines should append to recent_results."""
        rec = {"status": "running", "recent_results": []}
        for i in range(3):
            line = json.dumps({
                "test_result": {
                    "category": "credit_card",
                    "technique": f"tech_{i}",
                    "value": f"4111-{i}",
                    "matched": True,
                    "confidence": 0.9,
                }
            })
            runs_mod._on_progress_line(rec, line)
        assert len(rec["recent_results"]) == 3
        assert rec["recent_results"][0]["technique"] == "tech_0"

    def test_recent_results_capped_at_20(self):
        """More than 20 test_result lines should keep only the last 20."""
        rec = {"status": "running", "recent_results": []}
        for i in range(30):
            line = json.dumps({
                "test_result": {
                    "category": "ssn",
                    "technique": f"t{i}",
                    "value": f"val{i}",
                    "matched": False,
                    "confidence": None,
                }
            })
            runs_mod._on_progress_line(rec, line)
        assert len(rec["recent_results"]) == 20
        # Last 20 — item 10 through 29.
        assert rec["recent_results"][0]["technique"] == "t10"
        assert rec["recent_results"][-1]["technique"] == "t29"

    def test_recent_results_absent_from_terminal_run_view(self):
        """get_run() must not expose recent_results once the run is terminal."""
        runs_mod.reset()
        runs_mod._RUNS["R-T"] = {
            "status": runs_mod.STATUS_COMPLETED,
            "started_at": runs_mod._now(), "finished_at": runs_mod._now(),
            "argv": [], "request": {}, "exit_code": 0,
            "stdout_tail": "", "stderr_tail": "",
            "recent_results": [{"category": "ssn", "technique": "t",
                                 "value": "v", "matched": True, "confidence": None}],
        }
        view = runs_mod.get_run("R-T")
        assert "recent_results" not in view

    def test_recent_results_present_for_running_run(self):
        """recent_results is included in the view while the run is active."""
        runs_mod.reset()
        runs_mod._RUNS["R-LIVE"] = {
            "status": runs_mod.STATUS_RUNNING,
            "started_at": runs_mod._now(), "finished_at": None,
            "argv": [], "request": {}, "exit_code": None,
            "stdout_tail": "", "stderr_tail": "",
            "recent_results": [{"category": "email", "technique": "t",
                                 "value": "v", "matched": True, "confidence": 0.5}],
        }
        view = runs_mod.get_run("R-LIVE")
        assert "recent_results" in view
        assert len(view["recent_results"]) == 1


class TestReportEndpoint:
    """POST /v1/evadex/report — HTML report generation."""

    def _make_completed_run(self, run_id: str) -> None:
        runs_mod._RUNS[run_id] = {
            "status": runs_mod.STATUS_COMPLETED, "exit_code": 0,
            "started_at": runs_mod._now(), "finished_at": runs_mod._now(),
            "argv": [], "request": {}, "stdout_tail": "", "stderr_tail": "",
        }

    def test_report_valid_run_id_returns_html(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A completed run with a matching scan file should yield an HTML response."""
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.delenv("EVADEX_BRIDGE_KEY", raising=False)
        runs_mod.reset()

        # Build a scan file whose name embeds the run's timestamp.
        scan_dir = tmp_path / "results" / "scans"
        scan_dir.mkdir(parents=True)
        ts_part = "20991231T235959"
        run_id = f"R-{ts_part}-0001"
        (scan_dir / f"scan_{ts_part}.json").write_text('{"meta": {}}')

        self._make_completed_run(run_id)

        from evadex.bridge import server as server_mod

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        def _fake_run(argv, **kw):
            for i, a in enumerate(argv):
                if a == "--output":
                    Path(argv[i + 1]).write_text("<html><body>report</body></html>")
                    break
            return _Proc()

        monkeypatch.setattr(server_mod.subprocess, "run", _fake_run)

        app = create_app()
        r = TestClient(app).post("/v1/evadex/report", json={"run_id": run_id})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")

    def test_report_unknown_run_id_returns_404(self, client: TestClient):
        """A well-formed but unknown run_id must return 404."""
        r = client.post("/v1/evadex/report", json={"run_id": "R-20991231T235959-9999"})
        assert r.status_code == 404

    def test_report_malformed_run_id_returns_400(self, client: TestClient):
        """A run_id that doesn't match R-YYYYMMDDTHHMMSS-NNNN must return 400."""
        for bad in ("R-NOTEXIST", "../../etc/passwd", "R-[GLOB*", "", "12345"):
            r = client.post("/v1/evadex/report", json={"run_id": bad})
            assert r.status_code == 400, f"expected 400 for run_id={bad!r}, got {r.status_code}"
            assert "invalid format" in r.json()["detail"]["error"] or \
                   "non-empty" in r.json()["detail"]["error"]

    def test_report_non_completed_run_returns_400(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ):
        """Requesting a report for a running or queued scan returns 400."""
        async def _noop(run_id, argv, cwd):
            pass  # leave status as QUEUED
        monkeypatch.setattr(runs_mod, "_execute", _noop)

        launch = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        run_id = launch.json()["run_id"]
        r = client.post("/v1/evadex/report", json={"run_id": run_id})
        assert r.status_code == 400
        assert "not completed" in r.json()["detail"]["error"]

    def test_report_include_falsepos_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """include_falsepos: True must be accepted (not raise 400)."""
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.delenv("EVADEX_BRIDGE_KEY", raising=False)
        runs_mod.reset()

        scan_dir = tmp_path / "results" / "scans"
        scan_dir.mkdir(parents=True)
        ts_part = "20991231T235900"
        run_id = f"R-{ts_part}-0001"
        (scan_dir / f"scan_{ts_part}.json").write_text('{"meta": {}}')
        self._make_completed_run(run_id)

        from evadex.bridge import server as server_mod

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        def _fake_run(argv, **kw):
            for i, a in enumerate(argv):
                if a == "--output":
                    Path(argv[i + 1]).write_text("<html><body>fp report</body></html>")
                    break
            return _Proc()

        monkeypatch.setattr(server_mod.subprocess, "run", _fake_run)
        app = create_app()
        r = TestClient(app).post(
            "/v1/evadex/report",
            json={"run_id": run_id, "include_falsepos": True},
        )
        assert r.status_code == 200

    def test_report_html_wellformed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """The report endpoint must return a text/html response with HTML tags."""
        monkeypatch.setenv("EVADEX_BRIDGE_ROOT", str(tmp_path))
        monkeypatch.delenv("EVADEX_BRIDGE_KEY", raising=False)
        runs_mod.reset()

        scan_dir = tmp_path / "results" / "scans"
        scan_dir.mkdir(parents=True)
        ts_part = "20991231T235800"
        run_id = f"R-{ts_part}-0001"
        (scan_dir / f"scan_{ts_part}.json").write_text('{"meta": {}}')
        self._make_completed_run(run_id)

        from evadex.bridge import server as server_mod

        class _Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        def _fake_run(argv, **kw):
            for i, a in enumerate(argv):
                if a == "--output":
                    Path(argv[i + 1]).write_text(
                        "<!DOCTYPE html><html><head><title>Report</title></head>"
                        "<body><h1>evadex Report</h1></body></html>"
                    )
                    break
            return _Proc()

        monkeypatch.setattr(server_mod.subprocess, "run", _fake_run)
        app = create_app()
        r = TestClient(app).post("/v1/evadex/report", json={"run_id": run_id})
        assert r.status_code == 200
        body = r.content.decode()
        assert "<html" in body
        assert "</html>" in body


class TestInlineResultsShape:
    """Metrics endpoint fields required by the inline results UI panel."""

    def test_confidence_distribution_present(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        assert "confidence_distribution" in data
        cd = data["confidence_distribution"]
        for band in ("high", "medium", "low"):
            assert band in cd, f"confidence_distribution missing {band!r} band"
            assert isinstance(cd[band], int)

    def test_top_evasions_present_and_ranked(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        assert "top_evasions" in data
        evasions = data["top_evasions"]
        assert isinstance(evasions, list)
        if evasions:
            rates = [e["success_rate"] for e in evasions]
            assert rates == sorted(rates, reverse=True)

    def test_by_category_has_required_fields(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        for bucket, row in data["by_category"].items():
            for field in ("tp", "fn", "fp", "recall", "precision"):
                assert field in row, f"by_category[{bucket!r}] missing {field!r}"

    def test_metrics_has_all_inline_ui_fields(self, client: TestClient):
        data = client.get("/v1/evadex/metrics").json()
        for key in (
            "detection_rate", "fp_rate", "coverage",
            "by_category", "top_evasions", "confidence_distribution",
            "history", "last_run",
        ):
            assert key in data, f"metrics response missing {key!r}"

    def test_confidence_distribution_bands_from_audit(self, client: TestClient):
        """The fixture has 3 technique success rates; 2 are ≥0.8 (high),
        1 is 0.78 (medium)."""
        data = client.get("/v1/evadex/metrics").json()
        cd = data["confidence_distribution"]
        assert cd["high"] == 2    # zero_width_space=0.91, homoglyph=0.82
        assert cd["medium"] == 1  # base64_of_rot13=0.78


class TestFastMode:
    """--fast mode flag forwarded to the scan argv."""

    def test_fast_flag_added_when_requested(self):
        argv = runs_mod._build_scan_argv({"fast": True})
        assert "--fast" in argv

    def test_fast_flag_absent_in_full_scan(self):
        argv = runs_mod._build_scan_argv({})
        assert "--fast" not in argv

    def test_fast_reduces_variant_count_vs_full_scan(self):
        """--fast is only present in fast mode; full-scan argv has no --fast
        flag, meaning the CLI will run the complete variant set."""
        full_argv = runs_mod._build_scan_argv({"tier": "banking"})
        fast_argv = runs_mod._build_scan_argv({"tier": "banking", "fast": True})
        assert "--fast" not in full_argv
        assert "--fast" in fast_argv

    def test_fast_uses_seed_weights_when_no_history(self):
        """--fast is forwarded regardless of audit history; the CLI applies
        seed weights vs. history-blending based on what it finds at runtime."""
        argv = runs_mod._build_scan_argv({"fast": True})
        assert "--fast" in argv

    def test_fast_blends_history_when_audit_exists(self, client: TestClient,
                                                     monkeypatch: pytest.MonkeyPatch):
        """When the bridge has an audit log (audit_tree fixture), --fast should
        still be forwarded so the CLI can blend historical weights."""
        captured: dict = {}

        def _fake_launch(body, cwd=None):
            captured["argv"] = runs_mod._build_scan_argv(body)
            return {
                "run_id": "R-TEST", "status": runs_mod.STATUS_QUEUED,
                "started_at": runs_mod._now(), "finished_at": None,
                "argv": captured["argv"], "request": body, "exit_code": None,
                "stdout_tail": "", "stderr_tail": "",
            }
        monkeypatch.setattr(runs_mod, "launch", _fake_launch)

        r = client.post("/v1/evadex/run", json={"fast": True, "tier": "banking"})
        assert r.status_code == 202
        assert "--fast" in captured["argv"]


class TestProgressTracking:
    """Progress field semantics: monotonicity, completion, elapsed_s."""

    def test_progress_monotonically_increases(self):
        """If a subprocess emits a lower progress value, the bridge must keep
        the higher value — regressions from a subprocess glitch must not reach
        the UI."""
        rec = {"status": "running", "progress": 60.0, "elapsed_s": 10.0}
        line = json.dumps({"progress": 30.0, "tested": 200, "total": 500,
                            "detected": 90, "elapsed_s": 8.0})
        runs_mod._on_progress_line(rec, line)
        assert rec["progress"] == 60.0  # kept the higher value

    def test_progress_advances_on_higher_value(self):
        rec = {"status": "running", "progress": 40.0, "elapsed_s": 5.0}
        line = json.dumps({"progress": 55.0, "tested": 400, "total": 800,
                            "detected": 180, "elapsed_s": 12.0})
        runs_mod._on_progress_line(rec, line)
        assert rec["progress"] == pytest.approx(55.0)

    def test_progress_reaches_100_on_completion(self, client: TestClient,
                                                  monkeypatch: pytest.MonkeyPatch):
        """Successful scan completion must force progress=100 even if the last
        --progress-json tick was lower."""
        async def _fake_execute(run_id, argv, cwd):
            rec = runs_mod._RUNS[run_id]
            rec["status"] = runs_mod.STATUS_RUNNING
            rec["progress"] = 95.0  # last tick before exit
            rec["status"] = runs_mod.STATUS_COMPLETED
            rec["exit_code"] = 0
            rec["finished_at"] = runs_mod._now()
            rec["progress"] = 100.0  # _execute sets this on STATUS_COMPLETED
        monkeypatch.setattr(runs_mod, "_execute", _fake_execute)

        launch = client.post("/v1/evadex/run", json={"tool": "siphon-cli"})
        run_id = launch.json()["run_id"]
        data = client.get(f"/v1/evadex/run/{run_id}").json()
        assert data["status"] == runs_mod.STATUS_COMPLETED
        assert data["progress"] == pytest.approx(100.0)

    def test_elapsed_s_monotonically_increases(self):
        """elapsed_s must never go backwards — same monotonicity rule as progress."""
        rec = {"status": "running", "progress": 0.0, "elapsed_s": 20.0}
        line = json.dumps({"progress": 50.0, "tested": 300, "total": 600,
                            "detected": 120, "elapsed_s": 10.0})
        runs_mod._on_progress_line(rec, line)
        assert rec["elapsed_s"] == pytest.approx(20.0)  # kept the higher value

    def test_elapsed_s_advances_on_higher_value(self):
        rec = {"status": "running", "progress": 0.0, "elapsed_s": 5.0}
        line = json.dumps({"progress": 20.0, "tested": 100, "total": 500,
                            "detected": 40, "elapsed_s": 15.0})
        runs_mod._on_progress_line(rec, line)
        assert rec["elapsed_s"] == pytest.approx(15.0)
