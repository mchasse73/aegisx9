"""Shared fixtures for the workspace-image tests.

The image's tools are standalone scripts (they run inside the image without the
``aegisx9`` package), so tests load them by path, as ``tests/test_redteam_tools.py``
does for the red-team helpers.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
IMAGE_DIR = ROOT / "workspace" / "image"
HOOKS_DIR = IMAGE_DIR / "hooks"
BIN_DIR = IMAGE_DIR / "bin"

EXAMPLE_VALUES = {
    "AEGISX9_GATEWAY_URL": "https://gateway.example.test",
    "AEGISX9_OTLP_ENDPOINT": "https://otlp.example.test:4318",
    "AEGISX9_VAULT_ADDR": "https://vault.example.test:8200",
}


def load_script(rel: str) -> ModuleType:
    path = IMAGE_DIR / rel
    name = "ws_" + path.stem.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RunHook = Callable[
    [str, Mapping[str, object], Mapping[str, str] | None], subprocess.CompletedProcess[str]
]


def make_run_hook(tmp_path: Path) -> RunHook:
    """Build a runner that feeds a hook script JSON on stdin with an isolated HOME."""

    def _run(
        name: str, payload: Mapping[str, object], extra_env: Mapping[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        home = tmp_path / "home"
        home.mkdir(exist_ok=True)
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(home),
            "TMPDIR": str(tmp_path),
            "LANG": "C.UTF-8",
        }
        env.update(extra_env or {})
        bash = shutil.which("bash")
        assert bash is not None
        return subprocess.run(  # noqa: S603 - test harness running the script under test
            [bash, str(HOOKS_DIR / name)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )

    return _run
