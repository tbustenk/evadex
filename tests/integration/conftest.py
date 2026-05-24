"""Integration-test fixtures.

The CLI auto-discovers `evadex.yaml` from the current working directory
(via `evadex.config.find_config`). When pytest is launched from the repo
root, that config sets `tool: siphon-cli`, `min_detection_rate: 85`, and
`output: results.json` — none of which the integration tests anticipate.
Mocked `DlpscanCliAdapter.health_check` patches are silently bypassed,
gate failures collapse `exit_code` to 1, and JSON output that the tests
expect on stdout is diverted to a file.

Run every integration test from a clean temporary cwd so `find_config()`
returns `None` unless a test explicitly opts in by writing an `evadex.yaml`
inside its own `runner.isolated_filesystem()` (which further chdirs).
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_cwd_from_repo_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
