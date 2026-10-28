"""Run a command under the sandbox of one of the scanner's systemd units.

Usage (as root, on a host with systemd; CI runs it on the GitHub-hosted runner):

    python3 scripts/ci/scanner_unit_sandbox.py UNIT [--extra KEY=VALUE ...] -- CMD [ARGS...]

The ``[Service]`` hardening of ``UNIT`` (capabilities, Protect*, ProcSubset, address
families, system-call filter, ...) is parsed from the unit file and handed to
``systemd-run --wait --pipe -p ...``, so a test exercises exactly what the unit ships,
not a hand-copied list. Settings that need the real host (the config directory, the
credentials, the state directory, the executable) are left out: see ``SKIPPED``.
``--extra`` adds a property, e.g. ``ProcSubset=pid`` for a negative control. Exits with
the command's status.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

# Not sandbox properties, or ones that point at files only the scanner host has.
SKIPPED = frozenset(
    {
        "Type",
        "ExecStart",
        "EnvironmentFile",
        "Environment",
        "LoadCredential",
        "TimeoutStartSec",
        "StateDirectory",
        "StateDirectoryMode",
        "LogsDirectory",
        "LogsDirectoryMode",
        "CacheDirectory",
        "WorkingDirectory",
        "ReadOnlyPaths",
        "ReadWritePaths",
        "RemainAfterExit",
        "Restart",
        "RestartSec",
    }
)


def parse_unit(path: Path) -> dict[str, list[tuple[str, str]]]:
    """Section -> ordered (key, value) pairs. Repeated keys (SystemCallFilter=) are kept
    in order because systemd merges them."""
    sections: dict[str, list[tuple[str, str]]] = {}
    current = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.setdefault(current, [])
            continue
        key, sep, value = line.partition("=")
        if sep:
            sections.setdefault(current, []).append((key.strip(), value.strip()))
    return sections


def service_settings(path: Path) -> dict[str, str]:
    """The last value of each ``[Service]`` key (for lint tests)."""
    return dict(parse_unit(path).get("Service", []))


def sandbox_properties(path: Path) -> list[str]:
    return [f"{k}={v}" for k, v in parse_unit(path).get("Service", []) if k not in SKIPPED]


def systemd_run_argv(path: Path, command: list[str], extra: list[str]) -> list[str]:
    argv = ["systemd-run", "--wait", "--pipe", "--quiet", "--collect"]
    for prop in [*sandbox_properties(path), *extra]:
        argv += ["-p", prop]
    return [*argv, "--", *command]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--" not in argv:
        print("usage: scanner_unit_sandbox.py UNIT [--extra K=V] [--print] -- CMD", file=sys.stderr)
        return 2
    split = argv.index("--")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("unit", type=Path)
    parser.add_argument("--extra", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--print", action="store_true", help="print the argv, run nothing")
    args = parser.parse_args(argv[:split])
    command = argv[split + 1 :]
    if not command:
        parser.error("a command is required after --")
    run_argv = systemd_run_argv(args.unit, command, args.extra)
    if args.print:
        print(" ".join(run_argv))
        return 0
    return subprocess.run(run_argv, check=False).returncode  # noqa: S603


if __name__ == "__main__":
    sys.exit(main())
