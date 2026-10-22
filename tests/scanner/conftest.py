"""Shared fixtures for the scanner tests. No network, no subprocesses: every I/O seam is
injected."""

from __future__ import annotations

import shutil
from datetime import date
from pathlib import Path

import pytest

from aegisx9_scanner.approved import Registry, load_registry
from aegisx9_scanner.targets import NeverTargetList, TargetConfig, load_never_target, load_targets

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "scanner"

TODAY = date(2026, 10, 21)


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    """A config directory populated from the shipped example files."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    shutil.copy(EXAMPLES / "approved_public.example.yml", cfg / "approved_public.yml")
    shutil.copy(EXAMPLES / "targets.example.yml", cfg / "targets.yml")
    shutil.copy(EXAMPLES / "never_target.example.yml", cfg / "never_target.yml")
    return cfg


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    s = tmp_path / "state"
    s.mkdir()
    return s


@pytest.fixture
def registry(config_dir: Path) -> Registry:
    return load_registry(config_dir / "approved_public.yml")


@pytest.fixture
def targets_cfg(config_dir: Path) -> TargetConfig:
    return load_targets(config_dir / "targets.yml")


@pytest.fixture
def never(config_dir: Path) -> NeverTargetList:
    return load_never_target(config_dir / "never_target.yml")


def fake_resolver(table: dict[str, list[str]]):  # type: ignore[no-untyped-def]
    def _resolve(name: str) -> list[str]:
        return list(table.get(name, []))

    return _resolve
