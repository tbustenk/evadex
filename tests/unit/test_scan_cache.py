"""Unit tests for the evadex scan result cache."""

import time
import pytest
from pathlib import Path

from evadex.cache.scan_cache import ScanCache, _make_key, CacheStats


# ── Key generation ─────────────────────────────────────────────────────────────

def test_cache_key_is_deterministic():
    k1 = _make_key("4111111111111111", "homoglyph", "siphon-prod", "3.1.0")
    k2 = _make_key("4111111111111111", "homoglyph", "siphon-prod", "3.1.0")
    assert k1 == k2


def test_cache_key_differs_by_variant():
    k1 = _make_key("VALUE-A", "homoglyph", "scanner", "1.0")
    k2 = _make_key("VALUE-B", "homoglyph", "scanner", "1.0")
    assert k1 != k2


def test_cache_key_differs_by_scanner_version():
    k1 = _make_key("VALUE", "tech", "scanner", "1.0")
    k2 = _make_key("VALUE", "tech", "scanner", "2.0")
    assert k1 != k2


# ── Hit and miss ───────────────────────────────────────────────────────────────

def test_cache_miss_returns_none(tmp_path):
    c = ScanCache(db_path=tmp_path / "cache.db", ttl_hours=24)
    result = c.get("4111", "base64", "siphon", "1.0")
    assert result is None


def test_cache_hit_after_put(tmp_path):
    c = ScanCache(db_path=tmp_path / "cache.db", ttl_hours=24)
    c.put("4111", "base64", "siphon", "1.0", {"detected": True, "severity": "PASS"})
    result = c.get("4111", "base64", "siphon", "1.0")
    assert result == {"detected": True, "severity": "PASS"}


def test_cache_ttl_expiry_causes_miss(tmp_path):
    c = ScanCache(db_path=tmp_path / "cache.db", ttl_hours=0.0)  # 0 hours = always expired
    c.put("4111", "base64", "siphon", "1.0", {"detected": False})
    result = c.get("4111", "base64", "siphon", "1.0")
    assert result is None


def test_no_cache_flag_always_misses(tmp_path):
    c = ScanCache(db_path=tmp_path / "cache.db", ttl_hours=24, enabled=False)
    c.put("4111", "base64", "siphon", "1.0", {"detected": True})
    result = c.get("4111", "base64", "siphon", "1.0")
    assert result is None


# ── Stats ──────────────────────────────────────────────────────────────────────

def test_cache_stats_hit_rate(tmp_path):
    c = ScanCache(db_path=tmp_path / "cache.db", ttl_hours=24)
    c.put("4111", "base64", "siphon", "1.0", {"detected": True})
    c.get("4111", "base64", "siphon", "1.0")  # hit
    c.get("9999", "base64", "siphon", "1.0")  # miss
    s = c.stats()
    assert s.hit_count == 1
    assert s.miss_count == 1
    assert abs(s.hit_rate - 0.5) < 0.01


def test_cache_stats_total_entries(tmp_path):
    c = ScanCache(db_path=tmp_path / "cache.db", ttl_hours=24)
    for i in range(5):
        c.put(f"value-{i}", "tech", "scanner", "1.0", {"detected": i % 2 == 0})
    s = c.stats()
    assert s.total_entries == 5


def test_cache_clear(tmp_path):
    c = ScanCache(db_path=tmp_path / "cache.db", ttl_hours=24)
    for i in range(10):
        c.put(f"value-{i}", "tech", "scanner", "1.0", {"detected": True})
    deleted = c.clear()
    assert deleted == 10
    s = c.stats()
    assert s.total_entries == 0
