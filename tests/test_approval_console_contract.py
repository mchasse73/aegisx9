"""The approval console contract fixture is self-consistent (examples match schemas)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FIXTURE = Path(__file__).parent / "contracts" / "approval-console"


def test_contract_fixture_is_consistent() -> None:
    result = subprocess.run(
        [sys.executable, "-I", "check.py"], cwd=FIXTURE, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "fixture OK" in result.stdout
