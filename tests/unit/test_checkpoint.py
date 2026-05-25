"""Unit tests for the checkpoint module."""
import json
import pytest
from pathlib import Path
from unittest.mock import patch
from evadex.checkpoint import (
    _fingerprint,
    checkpoint_path,
    delete_checkpoint,
    find_latest_checkpoint,
    new_run_id,
    save_checkpoint,
)


@pytest.fixture
def tmp_checkpoint_dir(tmp_path, monkeypatch):
    """Redirect checkpoint writes to a temp directory."""
    import evadex.checkpoint as cp_mod
    monkeypatch.setattr(cp_mod, "_CHECKPOINT_DIR", tmp_path / "checkpoints")
    return tmp_path / "checkpoints"


class TestFingerprint:
    def test_same_params_same_fingerprint(self):
        a = _fingerprint("northam", "siphon-cli", ["credit_card", "ssn"])
        b = _fingerprint("northam", "siphon-cli", ["ssn", "credit_card"])
        assert a == b

    def test_different_tier_different_fingerprint(self):
        a = _fingerprint("northam", "siphon-cli", [])
        b = _fingerprint("full", "siphon-cli", [])
        assert a != b

    def test_different_tool_different_fingerprint(self):
        a = _fingerprint("northam", "siphon-cli", [])
        b = _fingerprint("northam", "dlpscan-cli", [])
        assert a != b

    def test_fingerprint_is_12_chars(self):
        fp = _fingerprint("northam", "siphon-cli", [])
        assert len(fp) == 12


class TestNewRunId:
    def test_run_id_format(self):
        run_id = new_run_id("northam", "siphon-cli")
        assert run_id.startswith("run-")
        assert "northam" in run_id
        assert "siphon-cli" in run_id


class TestSaveAndLoad:
    def test_save_creates_file(self, tmp_checkpoint_dir):
        run_id = "run-test-123"
        path = save_checkpoint(
            run_id, "northam", "siphon-cli", [],
            [("val", "credit_card", "structural", "uppercase", "text")],
            [{"payload": {}, "variant": {}, "detected": True}],
        )
        assert path.exists()

    def test_save_roundtrip(self, tmp_checkpoint_dir):
        run_id = "run-test-456"
        keys = [("v1", "cat", "gen", "tech", "text")]
        partial = [{"payload": {"value": "v1"}, "variant": {}, "detected": True}]
        save_checkpoint(run_id, "northam", "siphon-cli", [], keys, partial)

        loaded = json.loads((tmp_checkpoint_dir / f"{run_id}.json").read_text())
        assert loaded["run_id"] == run_id
        assert loaded["tier"] == "northam"
        assert loaded["completed_count"] == 1
        assert loaded["completed_keys"] == [list(keys[0])]

    def test_find_latest_returns_most_recent(self, tmp_checkpoint_dir):
        save_checkpoint(
            "run-A", "northam", "siphon-cli", [], [], []
        )
        import time; time.sleep(0.01)
        save_checkpoint(
            "run-B", "northam", "siphon-cli", [], [("k",)], [{"x": 1}]
        )
        cp = find_latest_checkpoint("northam", "siphon-cli", [])
        assert cp is not None
        assert cp["run_id"] == "run-B"

    def test_find_returns_none_when_no_match(self, tmp_checkpoint_dir):
        # Different tier — should not match
        save_checkpoint("run-C", "full", "siphon-cli", [], [], [])
        cp = find_latest_checkpoint("northam", "siphon-cli", [])
        assert cp is None

    def test_find_returns_none_when_dir_empty(self, tmp_checkpoint_dir):
        cp = find_latest_checkpoint("northam", "siphon-cli", [])
        assert cp is None


class TestDeleteCheckpoint:
    def test_delete_removes_file(self, tmp_checkpoint_dir):
        run_id = "run-del-test"
        save_checkpoint(run_id, "northam", "siphon-cli", [], [], [])
        path = checkpoint_path(run_id)
        assert path.exists()
        delete_checkpoint(run_id)
        assert not path.exists()

    def test_delete_nonexistent_is_noop(self, tmp_checkpoint_dir):
        delete_checkpoint("run-does-not-exist")  # should not raise
