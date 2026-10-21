from __future__ import annotations

import json
import secrets
import shutil
from collections.abc import Mapping
from pathlib import Path

import pytest

from aegisx9_scanner import redteam_external as rt
from aegisx9_scanner.checks import CommandResult
from aegisx9_scanner.diff import Kind

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def suite_dir(tmp_path: Path) -> Path:
    dst = tmp_path / "redteam"
    shutil.copytree(ROOT / "redteam", dst, ignore=shutil.ignore_patterns("results"))
    return dst


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    f = tmp_path / "key"
    f.write_text(secrets.token_urlsafe(24))
    f.chmod(0o600)
    return f


def test_config_from_env(tmp_path: Path) -> None:
    cfg = rt.RedteamConfig.from_env(
        {
            "AEGISX9_SCANNER_REDTEAM_TARGET_URL": "https://gateway.example.com ",
            "AEGISX9_SCANNER_REDTEAM_MODEL": "m",
            "AEGISX9_SCANNER_REDTEAM_KEY_FILE": str(tmp_path / "k"),
            "AEGISX9_SCANNER_REDTEAM_SUITE_DIR": str(tmp_path),
        }
    )
    assert cfg.target_url == "https://gateway.example.com" and cfg.suite_dir == tmp_path
    assert rt.RedteamConfig.from_env({}).suite_dir == rt.DEFAULT_SUITE_DIR


def test_read_key_file(key_file: Path, tmp_path: Path) -> None:
    assert rt.read_key_file(str(key_file)) == key_file.read_text().strip()
    key_file.chmod(0o640)
    with pytest.raises(PermissionError):
        rt.read_key_file(str(key_file))
    with pytest.raises(PermissionError):
        rt.read_key_file(str(tmp_path / "nope"))
    empty = tmp_path / "empty"
    empty.write_text("")
    empty.chmod(0o600)
    with pytest.raises(PermissionError):
        rt.read_key_file(str(empty))


def test_parsers() -> None:
    assert rt.parse_promptfoo(
        json.dumps({"results": {"stats": {"successes": 9, "failures": 1, "errors": 1}}})
    ) == (9, 2)
    assert rt.parse_promptfoo(
        json.dumps({"results": {"results": [{"success": True}, {"success": False}]}})
    ) == (1, 1)
    assert rt.parse_promptfoo("[]") == (0, 0)
    rows = "\n".join(
        [
            json.dumps({"entry_type": "eval", "probe": "dan.Dan_11_0", "passed": 9, "total": 10}),
            json.dumps(
                {"entry_type": "eval", "probe": "encoding.InjectHex", "passed": 5, "total": 10}
            ),
            json.dumps({"entry_type": "start_run setup"}),
            "garbage",
            "",
        ]
    )
    rates = rt.garak_pass_rates(rows)
    assert rates == {"dan": 0.9, "encoding": 0.5}
    thresholds = json.loads((ROOT / "redteam/garak/thresholds.json").read_text())
    assert rt.garak_failures(rates, thresholds) == [("dan", 0.9, 0.95), ("encoding", 0.5, 0.9)]
    assert rt.garak_failures({"x": 1.0}, {"probes": "bad"}) == []
    gen = rt.generator_options("https://gateway.example.com/", "m")
    assert gen["openai"]["OpenAICompatible"]["uri"] == "https://gateway.example.com/v1"  # type: ignore[index]


def test_run_redteam_full(suite_dir: Path, key_file: Path, tmp_path: Path) -> None:
    key = key_file.read_text().strip()
    envs: list[Mapping[str, str]] = []
    argvs: list[list[str]] = []

    def runner(argv: list[str], timeout: int, env: Mapping[str, str]) -> CommandResult:
        argvs.append(argv)
        envs.append(env)
        if "promptfoo@" in argv[2]:
            Path(argv[argv.index("--output") + 1]).write_text(
                json.dumps({"results": {"stats": {"successes": 10, "failures": 2, "errors": 0}}})
            )
        else:
            prefix = Path(argv[argv.index("--report_prefix") + 1])
            report = prefix.with_name(prefix.name + ".report.jsonl")
            report.write_text(
                json.dumps({"entry_type": "eval", "probe": "dan.X", "passed": 1, "total": 10})
                + "\n"
            )
        return CommandResult(0, "")

    cfg = rt.RedteamConfig(
        target_url="https://gateway.example.com/",
        model="m",
        key_file=str(key_file),
        suite_dir=suite_dir,
    )
    out = rt.run_redteam(
        cfg, tmp_path / "work", runner=runner, npx="/usr/bin/npx", python="/usr/bin/python3"
    )
    assert out.promptfoo_ran and out.garak_ran
    assert [a.kind for a in out.alerts] == [Kind.REDTEAM_REGRESSION, Kind.REDTEAM_REGRESSION]
    assert "promptfoo: 2 attack(s)" in out.alerts[0].detail and "garak dan" in out.alerts[1].detail
    assert all(key not in " ".join(a) for a in argvs)  # the key never reaches argv
    assert envs[0]["AEGIS_REDTEAM_KEY"] == key and envs[1]["OPENAICOMPATIBLE_API_KEY"] == key
    assert envs[0]["AEGIS_STAGING_URL"] == "https://gateway.example.com"
    assert "--no-share" in argvs[0] and argvs[1][1:3] == ["-m", "garak"]


def test_run_redteam_tool_and_output_failures(
    suite_dir: Path, key_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rt, "find_tool", lambda n: None)  # this machine may have npx
    cfg = rt.RedteamConfig(
        target_url="https://g.example.com", model="m", key_file=str(key_file), suite_dir=suite_dir
    )
    out = rt.run_redteam(
        cfg,
        tmp_path / "w",
        runner=lambda a, t, e: CommandResult(3, ""),
        npx=None,
        python="/usr/bin/python3",
    )
    kinds = [(a.kind, a.detail) for a in out.alerts]
    assert all(k == Kind.CHECK_INCOMPLETE for k, _ in kinds)
    assert any("npx not installed" in d for _, d in kinds) and any(
        "garak produced no report" in d for _, d in kinds
    )
    out = rt.run_redteam(
        cfg,
        tmp_path / "w",
        runner=lambda a, t, e: CommandResult(3, ""),
        npx="/usr/bin/npx",
        python="/usr/bin/python3",
    )
    assert any("promptfoo produced no output" in a.detail for a in out.alerts)

    def empty_report(argv: list[str], timeout: int, env: Mapping[str, str]) -> CommandResult:
        if "--report_prefix" in argv:
            prefix = Path(argv[argv.index("--report_prefix") + 1])
            prefix.with_name(prefix.name + ".report.jsonl").write_text("")
        return CommandResult(0, "")

    out = rt.run_redteam(
        cfg, tmp_path / "w", runner=empty_report, npx=None, python="/usr/bin/python3"
    )
    assert any("no eval rows" in a.detail for a in out.alerts) and not out.garak_ran


def test_run_redteam_preconditions(suite_dir: Path, key_file: Path, tmp_path: Path) -> None:
    never_called = lambda a, t, e: (_ for _ in ()).throw(AssertionError("must not run"))  # noqa: E731
    cfg = rt.RedteamConfig(
        target_url="https://g.example.com",
        model="m",
        key_file=str(key_file),
        suite_dir=tmp_path / "none",
    )
    out = rt.run_redteam(cfg, tmp_path / "w", runner=never_called)
    assert "incomplete" in out.alerts[0].detail
    cfg.suite_dir = suite_dir
    cfg.model = ""
    assert (
        "no red-team model"
        in rt.run_redteam(cfg, tmp_path / "w", runner=never_called).alerts[0].detail
    )
    cfg.model = "m"
    cfg.key_file = ""
    assert (
        "no red-team key"
        in rt.run_redteam(cfg, tmp_path / "w", runner=never_called).alerts[0].detail
    )
    cfg.key_file = str(tmp_path / "missing")
    assert (
        "key unavailable"
        in rt.run_redteam(cfg, tmp_path / "w", runner=never_called).alerts[0].detail
    )


def test_default_runner_passes_env() -> None:
    res = rt._default_runner(
        ["/bin/sh", "-c", 'printf %s "$MARK"'], 5, {"MARK": "ok", "PATH": "/bin"}
    )
    assert res.stdout == "ok"
