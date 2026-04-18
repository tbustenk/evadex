"""Unit tests for the Siphon-C2 reporter."""
from __future__ import annotations

import os

import httpx
import pytest
import respx

from evadex.reporters import c2_reporter
from evadex.reporters.c2_reporter import (
    C2Client,
    C2PushError,
    PATH_COMPARE,
    PATH_FALSEPOS,
    PATH_HISTORY,
    PATH_SCAN,
    push_comparison,
    push_falsepos_report,
    push_history_batch,
    push_scan_results,
    resolve_c2_config,
)


C2 = "http://c2.test"
KEY = "test-key"


# ── resolve_c2_config ───────────────────────────────────────────────────────

def test_resolve_cli_wins_over_config_and_env(monkeypatch):
    monkeypatch.setenv("EVADEX_C2_URL", "http://env")
    monkeypatch.setenv("EVADEX_C2_KEY", "env-key")
    url, key = resolve_c2_config(
        c2_url="http://cli", c2_key="cli-key",
        cfg_url="http://cfg", cfg_key="cfg-key",
    )
    assert url == "http://cli"
    assert key == "cli-key"


def test_resolve_config_fallback_after_cli(monkeypatch):
    monkeypatch.delenv("EVADEX_C2_URL", raising=False)
    monkeypatch.delenv("EVADEX_C2_KEY", raising=False)
    url, key = resolve_c2_config(
        c2_url=None, c2_key=None,
        cfg_url="http://cfg", cfg_key="cfg-key",
    )
    assert url == "http://cfg"
    assert key == "cfg-key"


def test_resolve_env_fallback(monkeypatch):
    monkeypatch.setenv("EVADEX_C2_URL", "http://env")
    monkeypatch.setenv("EVADEX_C2_KEY", "env-key")
    url, key = resolve_c2_config(c2_url=None, c2_key=None)
    assert url == "http://env"
    assert key == "env-key"


def test_resolve_nothing_means_disabled(monkeypatch):
    monkeypatch.delenv("EVADEX_C2_URL", raising=False)
    monkeypatch.delenv("EVADEX_C2_KEY", raising=False)
    url, key = resolve_c2_config(None, None)
    assert url is None
    assert key is None


# ── Successful push ─────────────────────────────────────────────────────────

@respx.mock
def test_scan_push_sends_expected_body(capsys):
    route = respx.post(f"{C2}{PATH_SCAN}").mock(return_value=httpx.Response(200, json={"ok": True}))
    ok = push_scan_results(
        C2, KEY,
        scanner_label="python-test",
        tool="siphon",
        categories=["credit_card"],
        strategies=["text"],
        total=10, passes=8, fails=2, errors=0,
        pass_rate=80.0,
        by_category={"credit_card": {"pass": 8, "fail": 2, "error": 0}},
        by_technique={"structural": {"pass": 8, "fail": 2, "error": 0}},
        fail_findings=[{"payload": {"value": "x"}, "variant": {"technique": "split"}}],
    )
    assert ok is True
    # No warning printed on success
    assert "warning" not in capsys.readouterr().err.lower()
    # Headers and body
    req = route.calls.last.request
    assert req.headers["x-api-key"] == KEY
    assert req.headers["user-agent"].startswith("evadex/")
    import json as _json
    body = _json.loads(req.content)
    assert body["type"] == "scan"
    assert body["scanner_label"] == "python-test"
    assert body["counts"] == {"total": 10, "pass": 8, "fail": 2, "error": 0}
    assert body["pass_rate"] == 80.0
    assert "timestamp" in body and "evadex_version" in body


@respx.mock
def test_falsepos_push_sends_expected_body():
    route = respx.post(f"{C2}{PATH_FALSEPOS}").mock(return_value=httpx.Response(200))
    report = {
        "tool": "siphon",
        "count_per_category": 100,
        "total_tested": 100,
        "total_flagged": 5,
        "overall_false_positive_rate": 5.0,
        "by_category": {},
    }
    ok = push_falsepos_report(C2, KEY, report=report)
    assert ok is True
    import json as _json
    body = _json.loads(route.calls.last.request.content)
    assert body["type"] == "falsepos"
    assert body["report"] == report


@respx.mock
def test_compare_push_sends_comparison():
    route = respx.post(f"{C2}{PATH_COMPARE}").mock(return_value=httpx.Response(200))
    comparison = {
        "label_a": "python", "label_b": "rust",
        "overall": {"a_rate": 80, "b_rate": 90, "delta": 10},
        "by_category": [], "by_technique": [], "diffs": [],
    }
    ok = push_comparison(C2, KEY, comparison=comparison)
    assert ok is True
    import json as _json
    body = _json.loads(route.calls.last.request.content)
    assert body["type"] == "compare"
    assert body["comparison"] == comparison


@respx.mock
def test_history_batch_push():
    route = respx.post(f"{C2}{PATH_HISTORY}").mock(return_value=httpx.Response(200))
    entries = [
        {"type": "scan", "pass_rate": 80, "timestamp": "2026-04-17T00:00:00Z"},
        {"type": "falsepos", "fp_rate": 5, "timestamp": "2026-04-17T01:00:00Z"},
    ]
    ok = push_history_batch(C2, KEY, entries=entries)
    assert ok is True
    import json as _json
    body = _json.loads(route.calls.last.request.content)
    assert body["type"] == "history"
    assert body["count"] == 2
    assert body["entries"] == entries


# ── Graceful degradation ────────────────────────────────────────────────────

@respx.mock
def test_unreachable_c2_returns_false_and_warns(capsys):
    respx.post(f"{C2}{PATH_SCAN}").mock(side_effect=httpx.ConnectError("refused"))
    ok = push_scan_results(
        C2, KEY,
        scanner_label="x", tool="t", categories=[], strategies=[],
        total=0, passes=0, fails=0, errors=0, pass_rate=0.0,
    )
    assert ok is False
    err = capsys.readouterr().err
    assert "C2 push failed" in err


@respx.mock
def test_auth_failure_surfaced_as_warning(capsys):
    respx.post(f"{C2}{PATH_SCAN}").mock(
        return_value=httpx.Response(401, json={"detail": "bad key"})
    )
    ok = push_scan_results(
        C2, "wrong-key",
        scanner_label="x", tool="t", categories=[], strategies=[],
        total=0, passes=0, fails=0, errors=0, pass_rate=0.0,
    )
    assert ok is False
    err = capsys.readouterr().err
    assert "auth failed" in err.lower() or "401" in err


@respx.mock
def test_server_error_surfaced_as_warning(capsys):
    respx.post(f"{C2}{PATH_SCAN}").mock(return_value=httpx.Response(503))
    ok = push_scan_results(
        C2, KEY,
        scanner_label="x", tool="t", categories=[], strategies=[],
        total=0, passes=0, fails=0, errors=0, pass_rate=0.0,
    )
    assert ok is False


def test_no_url_disables_push(capsys):
    """When c2_url is None, the helpers return False without warning or network calls."""
    assert push_scan_results(
        None, None,
        scanner_label="x", tool="t", categories=[], strategies=[],
        total=0, passes=0, fails=0, errors=0, pass_rate=0.0,
    ) is False
    assert push_falsepos_report(None, None, report={}) is False
    assert push_comparison(None, None, comparison={}) is False
    assert push_history_batch(None, None, entries=[]) is False
    err = capsys.readouterr().err
    assert "warning" not in err.lower()


# ── Client-level ─────────────────────────────────────────────────────────────

@respx.mock
def test_client_without_api_key_omits_header():
    route = respx.post(f"{C2}{PATH_SCAN}").mock(return_value=httpx.Response(200))
    client = C2Client(C2, api_key=None)
    client.post(PATH_SCAN, {"hello": "world"})
    req = route.calls.last.request
    assert "x-api-key" not in req.headers


@respx.mock
def test_client_raises_on_4xx():
    respx.post(f"{C2}{PATH_SCAN}").mock(
        return_value=httpx.Response(400, json={"detail": "bad body"})
    )
    client = C2Client(C2, api_key=KEY)
    with pytest.raises(C2PushError) as exc:
        client.post(PATH_SCAN, {})
    assert "400" in str(exc.value)
    assert "bad body" in str(exc.value)
