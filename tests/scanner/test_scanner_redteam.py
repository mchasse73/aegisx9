from __future__ import annotations

import json
import secrets
import shutil
import sys
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


@pytest.fixture
def cfg(suite_dir: Path, key_file: Path) -> rt.RedteamConfig:
    return rt.RedteamConfig(
        target_url="https://gateway.example.com/",
        model="m",
        key_file=str(key_file),
        suite_dir=suite_dir,
    )


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


def test_parsers(tmp_path: Path) -> None:
    stats = {"results": {"stats": {"successes": 9, "failures": 1, "errors": 1}}}
    assert rt.parse_promptfoo(json.dumps(stats)) == (9, 2)
    rows = {"results": {"results": [{"success": True}, {"success": False}]}}
    assert rt.parse_promptfoo(json.dumps(rows)) == (1, 1)
    for bad in ("[]", '{"results": 3}', '{"results": {}}'):
        with pytest.raises(ValueError, match="promptfoo"):
            rt.parse_promptfoo(bad)

    out = tmp_path / "promptfoo.json"
    assert rt.promptfoo_result(out) == (0, 0, "produced no output")
    out.write_text("{not json")
    assert rt.promptfoo_result(out) == (0, 0, "output invalid (JSONDecodeError)")
    out.write_text("[]")
    assert rt.promptfoo_result(out) == (0, 0, "output invalid (ValueError)")
    out.write_text(json.dumps({"results": {"stats": {"successes": 0, "failures": 0}}}))
    assert rt.promptfoo_result(out) == (0, 0, "ran no tests")
    out.write_text(json.dumps(stats))
    assert rt.promptfoo_result(out) == (9, 2, "")

    report = "\n".join(
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
    rates = rt.garak_pass_rates(report)
    assert rates == {"dan": 0.9, "encoding": 0.5}
    thresholds = json.loads((ROOT / "redteam/garak/thresholds.json").read_text())
    assert rt.garak_failures(rates, thresholds) == [("dan", 0.9, 0.95), ("encoding", 0.5, 0.9)]
    assert rt.garak_failures({"x": 1.0}, {"probes": "bad"}) == []
    gen = rt.generator_options("https://gateway.example.com/", "m")
    assert gen["openai"]["OpenAICompatible"]["uri"] == "https://gateway.example.com/v1"  # type: ignore[index]


def test_run_redteam_full(cfg: rt.RedteamConfig, key_file: Path, tmp_path: Path) -> None:
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

    work = tmp_path / "work"
    out = rt.run_redteam(cfg, work, runner=runner, npx="/usr/bin/npx", python="/usr/bin/python3")
    assert out.promptfoo_ran and out.garak_ran
    assert [a.kind for a in out.alerts] == [Kind.REDTEAM_REGRESSION, Kind.REDTEAM_REGRESSION]
    assert "promptfoo: 2 attack(s)" in out.alerts[0].detail and "garak dan" in out.alerts[1].detail
    assert all(key not in " ".join(a) for a in argvs)  # the key never reaches argv
    assert envs[0]["AEGIS_REDTEAM_KEY"] == key and envs[1]["OPENAICOMPATIBLE_API_KEY"] == key
    assert envs[0]["AEGIS_STAGING_URL"] == "https://gateway.example.com"
    assert "--no-share" in argvs[0] and argvs[1][1:3] == ["-m", "garak"]
    # Every run gets its own fresh, private directory under the work dir.
    assert out.run_dir is not None and out.run_dir.parent == work
    assert (out.run_dir.stat().st_mode & 0o777) == 0o700
    assert Path(argvs[0][argvs[0].index("--output") + 1]).parent == out.run_dir
    again = rt.run_redteam(cfg, work, runner=runner, npx="/usr/bin/npx", python="/usr/bin/python3")
    assert again.run_dir != out.run_dir


def test_garak_runs_with_the_current_interpreter(
    cfg: rt.RedteamConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rt, "find_tool", lambda n: None)
    argvs: list[list[str]] = []

    def runner(argv: list[str], timeout: int, env: Mapping[str, str]) -> CommandResult:
        argvs.append(argv)
        return CommandResult(1, "")

    rt.run_redteam(cfg, tmp_path / "w", runner=runner)
    assert argvs[0][0] == sys.executable  # not whatever python3 is first on PATH


def test_stale_results_are_never_reused(cfg: rt.RedteamConfig, tmp_path: Path) -> None:
    """A passing result left by an earlier run must not turn a failed run into a pass."""
    work = tmp_path / "work"
    passing = json.dumps({"results": {"stats": {"successes": 10, "failures": 0, "errors": 0}}})
    stale_run = work / "run-stale"
    (stale_run / "garak").mkdir(parents=True)
    (stale_run / "promptfoo.json").write_text(passing)
    (stale_run / "garak" / "aegisx9.report.jsonl").write_text(
        json.dumps({"entry_type": "eval", "probe": "dan.X", "passed": 10, "total": 10}) + "\n"
    )
    (work / "promptfoo.json").write_text(passing)
    out = rt.run_redteam(
        cfg,
        work,
        runner=lambda a, t, e: CommandResult(1, ""),  # both tools fail, write nothing
        npx="/usr/bin/npx",
        python="/usr/bin/python3",
    )
    assert not out.promptfoo_ran and not out.garak_ran
    details = [a.detail for a in out.alerts]
    assert all(a.kind == Kind.CHECK_INCOMPLETE for a in out.alerts)
    assert any("promptfoo produced no output (exit 1)" in d for d in details)
    assert any("garak produced no report (exit 1)" in d for d in details)


def test_run_redteam_tool_and_output_failures(
    cfg: rt.RedteamConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rt, "find_tool", lambda n: None)  # this machine may have npx
    out = rt.run_redteam(
        cfg,
        tmp_path / "w",
        runner=lambda a, t, e: CommandResult(3, ""),
        npx=None,
        python="/usr/bin/python3",
    )
    kinds = [(a.kind, a.detail) for a in out.alerts]
    assert all(k == Kind.CHECK_INCOMPLETE for k, _ in kinds)
    assert any("npx not installed" in d for _, d in kinds)
    assert any("garak produced no report" in d for _, d in kinds)

    def empty_and_invalid(argv: list[str], timeout: int, env: Mapping[str, str]) -> CommandResult:
        if "--output" in argv:
            Path(argv[argv.index("--output") + 1]).write_text("[]")
        if "--report_prefix" in argv:
            prefix = Path(argv[argv.index("--report_prefix") + 1])
            prefix.with_name(prefix.name + ".report.jsonl").write_text("")
        return CommandResult(0, "")

    out = rt.run_redteam(cfg, tmp_path / "w", runner=empty_and_invalid, npx="/usr/bin/npx")
    details = [a.detail for a in out.alerts]
    assert any("promptfoo output invalid" in d for d in details) and not out.promptfoo_ran
    assert any("no eval rows" in d for d in details) and not out.garak_ran

    def no_tests(argv: list[str], timeout: int, env: Mapping[str, str]) -> CommandResult:
        if "--output" in argv:
            Path(argv[argv.index("--output") + 1]).write_text(
                json.dumps({"results": {"stats": {"successes": 0, "failures": 0}}})
            )
        return CommandResult(0, "")

    out = rt.run_redteam(cfg, tmp_path / "w", runner=no_tests, npx="/usr/bin/npx")
    assert any("promptfoo ran no tests" in a.detail for a in out.alerts)


def test_run_redteam_preconditions(cfg: rt.RedteamConfig, tmp_path: Path) -> None:
    never_called = lambda a, t, e: (_ for _ in ()).throw(AssertionError("must not run"))  # noqa: E731
    suite_dir = cfg.suite_dir
    cfg.suite_dir = tmp_path / "none"
    out = rt.run_redteam(cfg, tmp_path / "w", runner=never_called)
    assert "incomplete" in out.alerts[0].detail
    cfg.suite_dir = suite_dir
    cfg.model = ""
    assert (
        "no red-team model"
        in rt.run_redteam(cfg, tmp_path / "w", runner=never_called).alerts[0].detail
    )
    cfg.model = "m"
    key_file = cfg.key_file
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
    cfg.key_file = key_file
    assert not list((tmp_path / "w").glob("run-*")) if (tmp_path / "w").exists() else True


def test_default_runner_passes_env() -> None:
    res = rt._default_runner(
        ["/bin/sh", "-c", 'printf %s "$MARK"'], 5, {"MARK": "ok", "PATH": "/bin"}
    )
    assert res.stdout == "ok"
