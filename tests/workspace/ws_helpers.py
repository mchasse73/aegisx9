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


def install_image_copy(dest: Path) -> Path:
    """Lay out hooks and the handoff CLI as in the image, under ``dest``.

    The installed scripts read only fixed ``/opt/aegisx9/...`` paths (no environment
    override), so tests run copies whose paths are rewritten to ``dest``. Tests that
    exercise fail-closed paths delete or empty files in this copy.
    """
    (dest / "hooks").mkdir(parents=True, exist_ok=True)
    (dest / "bin").mkdir(parents=True, exist_ok=True)
    sources = {p: dest / "hooks" / p.name for p in HOOKS_DIR.iterdir() if p.is_file()}
    sources[BIN_DIR / "handoff.py"] = dest / "bin" / "handoff"
    for src, target in sources.items():
        text = src.read_text(encoding="utf-8").replace("/opt/aegisx9/", f"{dest}/")
        target.write_text(text, encoding="utf-8")
        target.chmod(0o755 if src.suffix in {".sh", ".py"} else 0o644)
    return dest


def load_script(rel: str) -> ModuleType:
    path = IMAGE_DIR / rel
    name = "ws_" + path.stem.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RunHook = Callable[
    [str, Mapping[str, object] | str, Mapping[str, str] | None], subprocess.CompletedProcess[str]
]


def make_run_hook(tmp_path: Path) -> RunHook:
    """Build a runner that feeds a hook script JSON on stdin with an isolated HOME.

    It runs the patched image copy at ``tmp_path / "opt"`` (see install_image_copy).
    A ``str`` payload is sent verbatim (to test malformed input).
    """
    opt = install_image_copy(tmp_path / "opt")

    def _run(
        name: str, payload: Mapping[str, object] | str, extra_env: Mapping[str, str] | None = None
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
            [bash, str(opt / "hooks" / name)],
            input=payload if isinstance(payload, str) else json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )

    return _run
