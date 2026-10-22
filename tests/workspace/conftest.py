"""Fixtures for the workspace-image tests (helpers live in ``ws_helpers.py``)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from ws_helpers import RunHook, make_run_hook


@pytest.fixture
def run_hook(tmp_path: Path) -> RunHook:
    """Run a hook script with a JSON payload on stdin and an isolated HOME."""
    return make_run_hook(tmp_path)
