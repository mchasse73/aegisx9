from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    path = ROOT / "scripts" / "image" / "bake_prisma.py"
    spec = importlib.util.spec_from_file_location("bake_prisma", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bake_prisma"] = mod
    spec.loader.exec_module(mod)
    return mod


PATHS = {
    "debian-openssl-1.1.x": "/opt/prisma/binaries/query-engine-debian-openssl-1.1.x",
    "debian-openssl-3.0.x": "/opt/prisma/binaries/query-engine-debian-openssl-3.0.x",
    "linux-musl": "/opt/prisma/binaries/query-engine-linux-musl",
}


def test_select_engine_exact_and_same_major() -> None:
    bake = _load()
    assert bake.select_engine("debian-openssl-3.0.x", PATHS) == PATHS["debian-openssl-3.0.x"]
    # prisma-client-py reports the OpenSSL minor; the CLI ships one engine per major.
    assert bake.select_engine("debian-openssl-3.5.x", PATHS) == PATHS["debian-openssl-3.0.x"]
    assert bake.select_engine("linux-musl", PATHS) == PATHS["linux-musl"]


def test_select_engine_never_crosses_distro_or_major() -> None:
    bake = _load()
    assert bake.select_engine("rhel-openssl-3.0.x", PATHS) is None
    assert bake.select_engine("debian-openssl-4.0.x", PATHS) is None
    assert bake.select_engine("darwin-arm64", PATHS) is None
