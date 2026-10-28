"""Run this repository's promptfoo and garak suites against a *public* gateway endpoint
from the external vantage, and feed the outcome into the same report and alert path.

The target URL is checked against the never-target list first. The red-team API key is
read from the 0600 file named by ``AEGISX9_SCANNER_REDTEAM_KEY_FILE`` and handed to the
tools through their environment variables, never on a command line.

Every invocation gets a fresh, private work directory: a tool that fails to write its
result can never be mistaken for a pass because last week's file is still there.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from aegisx9_scanner.checks import CommandResult, find_tool, run_command
from aegisx9_scanner.diff import Alert, Kind, Severity
from aegisx9_scanner.fsutil import ensure_group_dir
from aegisx9_scanner.log import error_name, event

PROMPTFOO_VERSION = "0.124.1"
GARAK_VERSION = "0.17.1"
SUITE_TIMEOUT_S = 2 * 60 * 60
DEFAULT_SUITE_DIR = Path("/opt/aegisx9-scanner/redteam")
ENV_PREFIX = "AEGISX9_SCANNER_REDTEAM_"

EnvRunner = Callable[[list[str], int, Mapping[str, str]], CommandResult]
"""``runner(argv, timeout_seconds, env)``: the key travels in ``env``, never in argv."""


def _default_runner(argv: list[str], timeout: int, env: Mapping[str, str]) -> CommandResult:
    return run_command(argv, timeout, env=env)


@dataclass
class RedteamConfig:
    target_url: str = ""
    model: str = ""
    key_file: str = ""
    suite_dir: Path = DEFAULT_SUITE_DIR

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> RedteamConfig:
        env = os.environ if env is None else env
        return cls(
            target_url=env.get(ENV_PREFIX + "TARGET_URL", "").strip(),
            model=env.get(ENV_PREFIX + "MODEL", "").strip(),
            key_file=env.get(ENV_PREFIX + "KEY_FILE", "").strip(),
            suite_dir=Path(env.get(ENV_PREFIX + "SUITE_DIR", "").strip() or DEFAULT_SUITE_DIR),
        )


@dataclass
class RedteamOutcome:
    alerts: list[Alert] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    promptfoo_ran: bool = False
    garak_ran: bool = False
    run_dir: Path | None = None


def read_key_file(path: str) -> str:
    """The API key from a 0600 file. Only the exception type ever leaves this function."""
    p = Path(path)
    try:
        if stat.S_IMODE(p.stat().st_mode) & 0o077:
            raise PermissionError("key file readable by others")
        value = p.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PermissionError(error_name(exc)) from exc
    if not value:
        raise PermissionError("key file empty")
    return value


def promptfoo_argv(npx: str, config: Path, output: Path) -> list[str]:
    return [
        npx,
        "--yes",
        f"promptfoo@{PROMPTFOO_VERSION}",
        "eval",
        "--config",
        str(config),
        "--no-cache",
        "--no-share",
        "--output",
        str(output),
    ]


def garak_argv(python: str, config: Path, generator_file: Path, report_prefix: Path) -> list[str]:
    return [
        python,
        "-m",
        "garak",
        "--config",
        str(config),
        "--generator_option_file",
        str(generator_file),
        "--report_prefix",
        str(report_prefix),
    ]


def generator_options(target_url: str, model: str) -> dict[str, object]:
    return {
        "openai": {
            "OpenAICompatible": {
                "uri": f"{target_url.rstrip('/')}/v1",
                "model": model,
                "max_tokens": 256,
                "suppressed_params": ["n", "frequency_penalty", "presence_penalty"],
            }
        }
    }


def parse_promptfoo(text: str) -> tuple[int, int]:
    """``(successes, failures)`` from a promptfoo output file (errors count as failures).

    Raises ``ValueError`` when the document is not a promptfoo result.
    """
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError("promptfoo output is not an object")
    results = doc.get("results", doc)
    if not isinstance(results, dict):
        raise ValueError("promptfoo output has no results")
    stats = results.get("stats")
    if isinstance(stats, dict):
        return (
            int(stats.get("successes", 0)),
            int(stats.get("failures", 0)) + int(stats.get("errors", 0)),
        )
    rows = results.get("results")
    if not isinstance(rows, list):
        raise ValueError("promptfoo output has neither stats nor rows")
    ok = sum(1 for r in rows if isinstance(r, dict) and r.get("success"))
    return ok, len(rows) - ok


def promptfoo_result(output: Path) -> tuple[int, int, str]:
    """``(successes, failures, problem)``; ``problem`` is non-empty when the file is
    missing, invalid or records no executed test, which is CHECK_INCOMPLETE, not a pass."""
    if not output.exists():
        return 0, 0, "produced no output"
    try:
        ok, failed = parse_promptfoo(output.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        return 0, 0, f"output invalid ({error_name(exc)})"
    if ok + failed == 0:
        return 0, 0, "ran no tests"
    return ok, failed, ""


def garak_pass_rates(report_text: str) -> dict[str, float]:
    """Pass rate per probe family from garak's ``*.report.jsonl`` (``eval`` rows)."""
    passed: dict[str, int] = defaultdict(int)
    total: dict[str, int] = defaultdict(int)
    for line in report_text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or row.get("entry_type") != "eval":
            continue
        family = str(row.get("probe", "")).split(".")[0]
        passed[family] += int(row.get("passed", 0))
        total[family] += int(row.get("total", 0))
    return {f: (passed[f] / total[f] if total[f] else 1.0) for f in total}


def garak_failures(
    rates: dict[str, float], thresholds: dict[str, object]
) -> list[tuple[str, float, float]]:
    default = float(str(thresholds.get("default", 1.0)))
    per_probe = thresholds.get("probes", {})
    per_probe = per_probe if isinstance(per_probe, dict) else {}
    out = []
    for family, rate in sorted(rates.items()):
        floor = float(str(per_probe.get(family, default)))
        if rate < floor:
            out.append((family, rate, floor))
    return out


def _incomplete(detail: str) -> Alert:
    return Alert(Kind.CHECK_INCOMPLETE, Severity.MEDIUM, "redteam", detail)


def run_redteam(
    cfg: RedteamConfig,
    work_dir: Path,
    *,
    runner: EnvRunner = _default_runner,
    npx: str | None = None,
    python: str | None = None,
) -> RedteamOutcome:
    """Run both suites in a fresh directory under ``work_dir``. Every path that would make
    the result meaningless (missing tool, key or suite; empty or invalid output) is an
    alert, never a silent pass."""
    outcome = RedteamOutcome()
    run = runner
    target = cfg.target_url.rstrip("/")
    suite = cfg.suite_dir
    promptfoo_cfg = suite / "promptfoo" / "promptfooconfig.yaml"
    garak_cfg = suite / "garak" / "aegisx9.yaml"
    thresholds_file = suite / "garak" / "thresholds.json"
    if not promptfoo_cfg.exists() or not garak_cfg.exists() or not thresholds_file.exists():
        outcome.alerts.append(_incomplete("red-team suite directory is incomplete"))
        return outcome
    if not cfg.model:
        outcome.alerts.append(_incomplete("no red-team model configured"))
        return outcome
    try:
        key = read_key_file(cfg.key_file) if cfg.key_file else ""
    except PermissionError as exc:
        outcome.alerts.append(_incomplete(f"red-team key unavailable ({error_name(exc)})"))
        return outcome
    if not key:
        outcome.alerts.append(_incomplete("no red-team key file configured"))
        return outcome

    ensure_group_dir(work_dir)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=work_dir))  # fresh and 0700
    outcome.run_dir = run_dir
    base_env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR")}
    base_env.update(
        {"AEGIS_STAGING_URL": target, "AEGIS_REDTEAM_MODEL": cfg.model, "NO_COLOR": "1"}
    )

    npx = npx or find_tool("npx")
    if npx is None:
        outcome.alerts.append(_incomplete("npx not installed: promptfoo skipped"))
    else:
        output = run_dir / "promptfoo.json"
        output.unlink(missing_ok=True)
        res = run(
            promptfoo_argv(npx, promptfoo_cfg, output),
            SUITE_TIMEOUT_S,
            {**base_env, "AEGIS_REDTEAM_KEY": key},
        )
        ok, failed, problem = promptfoo_result(output)
        if problem:
            outcome.alerts.append(_incomplete(f"promptfoo {problem} (exit {res.returncode})"))
        else:
            outcome.promptfoo_ran = True
            outcome.notes.append(f"promptfoo: {ok} passed, {failed} failed")
            if failed:
                outcome.alerts.append(
                    Alert(
                        Kind.REDTEAM_REGRESSION,
                        Severity.HIGH,
                        target,
                        f"promptfoo: {failed} attack(s) succeeded",
                    )
                )

    # garak is installed in this interpreter's environment; PATH may point elsewhere.
    python = python or sys.executable
    generator_file = run_dir / "garak-generator.json"
    generator_file.write_text(json.dumps(generator_options(target, cfg.model)), encoding="utf-8")
    prefix = run_dir / "garak" / "aegisx9"
    prefix.parent.mkdir(parents=True, exist_ok=True)
    report = prefix.with_name(prefix.name + ".report.jsonl")
    report.unlink(missing_ok=True)
    res = run(
        garak_argv(python, garak_cfg, generator_file, prefix),
        SUITE_TIMEOUT_S,
        {**base_env, "OPENAICOMPATIBLE_API_KEY": key},
    )
    if report.exists():
        rates = garak_pass_rates(report.read_text(encoding="utf-8"))
        thresholds = json.loads(thresholds_file.read_text(encoding="utf-8"))
        outcome.garak_ran = bool(rates)
        if not rates:
            outcome.alerts.append(
                _incomplete(f"garak report has no eval rows (exit {res.returncode})")
            )
        for family, rate, floor in garak_failures(rates, thresholds):
            outcome.alerts.append(
                Alert(
                    Kind.REDTEAM_REGRESSION,
                    Severity.HIGH,
                    target,
                    f"garak {family}: pass rate {rate:.2f} < {floor:.2f}",
                )
            )
        outcome.notes.append(
            "garak: " + ", ".join(f"{f}={r:.2f}" for f, r in sorted(rates.items()))
        )
    else:
        outcome.alerts.append(_incomplete(f"garak produced no report (exit {res.returncode})"))
    event(
        "red-team run finished",
        promptfoo=outcome.promptfoo_ran,
        garak=outcome.garak_ran,
        alerts=len(outcome.alerts),
    )
    return outcome
