"""Individual checks. Each one is a pure function over an injectable I/O callable so the
tests never open a socket or start a process."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from aegisx9_scanner.log import log_error


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


CommandRunner = Callable[[list[str], int], CommandResult]
"""``runner(argv, timeout_seconds)``. Argv is a fixed list, never a shell string."""


def run_command(
    argv: list[str],
    timeout: int,
    env: Mapping[str, str] | None = None,
    stdin: str | None = None,
) -> CommandResult:
    """Run a tool with a fixed argv and no shell. Secrets never appear in ``argv``; a
    payload that must not be on the command line goes through ``stdin``."""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, absolute executable, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=dict(env) if env is not None else None,
            input=stdin,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log_error("command failed to run", exc, tool=argv[0].rsplit("/", 1)[-1])
        return CommandResult(returncode=127, stdout="", stderr=type(exc).__name__)
    return CommandResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def find_tool(name: str) -> str | None:
    return shutil.which(name)
