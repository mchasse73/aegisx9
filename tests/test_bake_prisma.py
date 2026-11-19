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
    "linux-arm64-openssl-3.0.x": "/opt/prisma/binaries/query-engine-linux-arm64-openssl-3.0.x",
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


def test_select_engine_arm64_uses_the_arm64_engine() -> None:
    bake = _load()
    # prisma-client-py reports the x86-64 name on arm64 too; the arm64 engine must be chosen.
    arm64 = PATHS["linux-arm64-openssl-3.0.x"]
    for machine in ("aarch64", "arm64"):
        assert bake.select_engine("debian-openssl-3.5.x", PATHS, machine) == arm64
    assert (
        bake.select_engine("debian-openssl-3.5.x", PATHS, "x86_64") == PATHS["debian-openssl-3.0.x"]
    )


def test_select_engine_arm64_never_falls_back_to_x86_64() -> None:
    bake = _load()
    assert bake.select_engine("linux-musl-openssl-3.0.x", PATHS, "aarch64") is None
    assert bake.select_engine("linux-musl", PATHS, "aarch64") is None
    assert bake.select_engine("debian-openssl-1.1.x", PATHS, "aarch64") is None


def test_select_engine_arm64_maps_every_glibc_distro_to_the_generic_engine() -> None:
    bake = _load()
    # The linux-arm64 engine is generic glibc: distro doesn't matter on arm64, unlike x86-64.
    arm64 = PATHS["linux-arm64-openssl-3.0.x"]
    assert bake.select_engine("rhel-openssl-3.0.x", PATHS, "aarch64") == arm64
    assert bake.select_engine("rhel-openssl-3.0.x", PATHS, "x86_64") is None


def test_select_engine_arm64_musl_is_unsupported() -> None:
    bake = _load()
    assert bake.select_engine("linux-musl-arm64-openssl-3.0.x", PATHS, "aarch64") is None
    assert bake.engine_target("linux-musl-arm64-openssl-3.0.x", "aarch64") is None
