"""`seed:` in evadex.yaml."""

import click
import pytest

from evadex.config import KNOWN_KEYS, load_config


def _load(tmp_path, body: str):
    p = tmp_path / "evadex.yaml"
    p.write_text(body, encoding="utf-8")
    return load_config(p)


def test_seed_is_a_known_key():
    assert "seed" in KNOWN_KEYS


def test_seed_loads_as_int(tmp_path):
    assert _load(tmp_path, "seed: 4242\n").seed == 4242


def test_seed_absent_is_none(tmp_path):
    assert _load(tmp_path, "tier: northam\n").seed is None


@pytest.mark.parametrize("bad", ["seed: abc\n", "seed: 1.5\n", "seed: true\n"])
def test_seed_rejects_non_integers(tmp_path, bad):
    with pytest.raises(click.UsageError):
        _load(tmp_path, bad)
