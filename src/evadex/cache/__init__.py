"""Scan result cache — skip variants already tested against the same scanner version."""

from evadex.cache.scan_cache import ScanCache, CacheStats, default_cache_path

__all__ = ["ScanCache", "CacheStats", "default_cache_path"]
