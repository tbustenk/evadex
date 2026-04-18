"""Unit tests for the entropy-focused generate templates."""
import random

import pytest

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry
from evadex.generate.templates import apply_template, _FORMATTERS


def _entry(cat: PayloadCategory, value: str) -> GeneratedEntry:
    return GeneratedEntry(
        category=cat,
        plain_value=value,
        variant_value=value,
        technique=None,
        generator_name=None,
        transform_name=None,
        has_keywords=False,
        embedded_text=value,
    )


def _entries() -> list[GeneratedEntry]:
    return [
        _entry(PayloadCategory.RANDOM_API_KEY, "xK9mP2nL4qR7vT1wY6uI0oE3sA5dF8hJ"),
        _entry(
            PayloadCategory.RANDOM_SECRET,
            "a3f8c2e1d4b7a9f0e2c5d8b1a4f7c0e3d6b9a2f5c8e1d4b7a0f3c6e9d2b5a8c1",
        ),
    ]


def test_all_three_entropy_templates_registered():
    for name in ("env_file", "secrets_file", "code_with_secrets"):
        assert name in _FORMATTERS, f"template {name!r} not registered"


def test_env_file_emits_assignment_lines():
    lines = apply_template("env_file", _entries(), seed=1)
    text = "\n".join(lines)
    # Assignment format means VALUE is preceded by ``KEY=``.
    assert "RANDOM_API_KEY=" in text
    assert "RANDOM_SECRET=" in text
    # Values themselves must appear
    assert "xK9mP2nL4qR7vT1wY6uI0oE3sA5dF8hJ" in text


def test_secrets_file_uses_keyword_near_values():
    lines = apply_template("secrets_file", _entries(), seed=1)
    text = "\n".join(lines)
    # YAML-style: the Siphon keyword appears on the same or preceding line.
    assert "xK9mP2nL4qR7vT1wY6uI0oE3sA5dF8hJ" in text
    # At least one of the Siphon context keywords must appear near values
    keywords = ("api_key", "secret_key", "access_token", "private_key",
                "password", "bearer_token", "signing_key", "encryption_key")
    assert any(kw in text for kw in keywords)


def test_code_with_secrets_uses_bare_values():
    """Values appear as function-call literals, not KEY=VALUE assignments."""
    lines = apply_template("code_with_secrets", _entries(), seed=1)
    text = "\n".join(lines)
    assert "_verify(" in text
    # The exact value must be present as a string literal
    assert '"xK9mP2nL4qR7vT1wY6uI0oE3sA5dF8hJ"' in text
    # No KEY=VALUE assignment for payload values — that would move it into
    # Siphon's assignment context, defeating the "bare value" intent.
    assert "RANDOM_API_KEY=" not in text
    assert "RANDOM_SECRET=" not in text


def test_templates_handle_empty_entries():
    """All three templates must work with an empty entry list."""
    for name in ("env_file", "secrets_file", "code_with_secrets"):
        lines = apply_template(name, [], seed=1)
        assert isinstance(lines, list) and lines, f"{name} produced no output"
