"""LSH near-duplicate generation and Jaccard helpers for testing
Siphon's document-similarity engine.

Siphon's LSH implementation (crates/siphon-core/src/lsh.rs) builds
3-word shingles, MinHashes them with 128 hash functions across 16
bands, and reports Jaccard similarity. We mirror the shingling and
Jaccard arithmetic exactly here so evadex can predict what Siphon
*should* report, then compare against what the scanner actually
returns.
"""
from evadex.lsh.document_generator import (
    BASE_DOCUMENTS,
    distorted_variant,
    jaccard_similarity,
    shingle,
)

__all__ = [
    "BASE_DOCUMENTS",
    "distorted_variant",
    "jaccard_similarity",
    "shingle",
]
