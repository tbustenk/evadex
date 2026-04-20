"""evadex HTTP bridge — drives evadex from siphon-c2 and other frontends.

Exposes three endpoints:
    POST /v1/evadex/run       — trigger a scan (background, returns run_id)
    GET  /v1/evadex/metrics   — detection / FP / coverage aggregated from audit.jsonl
    POST /v1/evadex/generate  — produce a synthetic test file and return it

Install with ``pip install evadex[bridge]``; start with ``evadex bridge``.
"""

__all__ = ["server", "metrics", "categories", "runs"]
