"""SQLite-backed scan result cache for evadex.

Cache key: SHA-1 of (variant_value, technique, scanner_label, siphon_version)
Cache store: ~/.evadex/cache/scan_cache.db
Cache TTL: configurable (default 24 hours)

Usage::

    cache = ScanCache(ttl_hours=24)
    result = cache.get(variant_value, technique, scanner_label, siphon_version)
    if result is None:
        result = run_scan(...)
        cache.put(variant_value, technique, scanner_label, siphon_version, result)
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_DEFAULT_TTL_HOURS = 24
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_cache (
    cache_key  TEXT PRIMARY KEY,
    result     TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_created_at ON scan_cache (created_at);
"""


def default_cache_path() -> Path:
    return Path.home() / ".evadex" / "cache" / "scan_cache.db"


def _make_key(
    variant_value: str,
    technique: str,
    scanner_label: str,
    siphon_version: str,
) -> str:
    raw = f"{variant_value}\x00{technique}\x00{scanner_label}\x00{siphon_version}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


@dataclass
class CacheStats:
    total_entries: int
    hit_count: int
    miss_count: int

    @property
    def hit_rate(self) -> float:
        total = self.hit_count + self.miss_count
        return self.hit_count / total if total > 0 else 0.0


class ScanCache:
    """Thread-safe SQLite scan result cache."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        ttl_hours: float = _DEFAULT_TTL_HOURS,
        enabled: bool = True,
    ) -> None:
        self._db_path = db_path or default_cache_path()
        self._ttl_seconds = ttl_hours * 3600
        self._enabled = enabled
        self._hits = 0
        self._misses = 0
        if self._enabled:
            self._init_db()

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), check_same_thread=False)

    def get(
        self,
        variant_value: str,
        technique: str,
        scanner_label: str,
        siphon_version: str,
    ) -> Optional[dict]:
        """Return cached result dict if present and not expired, else None."""
        if not self._enabled:
            self._misses += 1
            return None
        key = _make_key(variant_value, technique, scanner_label, siphon_version)
        cutoff = time.time() - self._ttl_seconds
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT result FROM scan_cache WHERE cache_key=? AND created_at>=?",
                    (key, cutoff),
                ).fetchone()
        except sqlite3.Error:
            self._misses += 1
            return None
        if row:
            self._hits += 1
            try:
                return json.loads(row[0])
            except json.JSONDecodeError:
                self._misses += 1
                return None
        self._misses += 1
        return None

    def put(
        self,
        variant_value: str,
        technique: str,
        scanner_label: str,
        siphon_version: str,
        result: dict,
    ) -> None:
        """Insert or replace a cache entry."""
        if not self._enabled:
            return
        key = _make_key(variant_value, technique, scanner_label, siphon_version)
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO scan_cache (cache_key, result, created_at) "
                    "VALUES (?, ?, ?)",
                    (key, json.dumps(result, ensure_ascii=False), time.time()),
                )
        except sqlite3.Error:
            pass

    def stats(self) -> CacheStats:
        """Return hit/miss statistics and total entry count."""
        total = 0
        if self._enabled:
            try:
                with self._conn() as conn:
                    row = conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()
                    total = row[0] if row else 0
            except sqlite3.Error:
                pass
        return CacheStats(
            total_entries=total,
            hit_count=self._hits,
            miss_count=self._misses,
        )

    def clear(self) -> int:
        """Delete all cached entries. Returns number of rows deleted."""
        if not self._enabled:
            return 0
        try:
            with self._conn() as conn:
                cur = conn.execute("DELETE FROM scan_cache")
                return cur.rowcount
        except sqlite3.Error:
            return 0

    def evict_expired(self) -> int:
        """Delete entries older than the TTL. Returns number of rows deleted."""
        if not self._enabled:
            return 0
        cutoff = time.time() - self._ttl_seconds
        try:
            with self._conn() as conn:
                cur = conn.execute(
                    "DELETE FROM scan_cache WHERE created_at < ?", (cutoff,)
                )
                return cur.rowcount
        except sqlite3.Error:
            return 0
