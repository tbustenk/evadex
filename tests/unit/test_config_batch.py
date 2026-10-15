"""`batch:` in evadex.yaml."""

import click
import pytest

from evadex.config import KNOWN_KEYS, load_config


def _load(tmp_path, body: str):
    p = tmp_path / "evadex.yaml"
    p.write_text(body, encoding="utf-8")
    return load_config(p)


def test_batch_is_a_known_key():
    assert "batch" in KNOWN_KEYS


def test_batch_loads_as_bool(tmp_path):
    assert _load(tmp_path, "batch: true\n").batch is True
    assert _load(tmp_path, "batch: false\n").batch is False


def test_batch_absent_is_none(tmp_path):
    assert _load(tmp_path, "tier: northam\n").batch is None


# YAML 1.1 reads a bare `yes`/`no` as a boolean, so those are valid.
@pytest.mark.parametrize("bad", ["batch: 'yes'\n", "batch: 1\n", "batch: 'true'\n"])
def test_batch_rejects_non_bool(tmp_path, bad):
    with pytest.raises(click.UsageError):
        _load(tmp_path, bad)
