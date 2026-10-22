#!/usr/bin/env python3
"""AegisX9 ``handoff``: write and update the daily handoff note.

Installed as ``/opt/aegisx9/bin/handoff``. Notes live on the developer's home volume in
``$HOME/.aegisx9/handoff/YYYY-MM-DD.md`` and have three sections: *What changed*,
*Open items* and *First thing tomorrow*. A fourth section, *Sessions*, records which
Claude Code sessions ended without a note (written by the SessionEnd hook).

Commands::

    handoff add changed "Shipped the workspace image (refs #48)"
    handoff add open --stdin < items.txt      # one bullet per line
    handoff add tomorrow "Run the container self-test on the new runner"
    handoff show [--date YYYY-MM-DD]
    handoff stub --session <id> --reason <reason>   # used by the SessionEnd hook
    handoff publish                           # copy today's note to team memory

Every bullet is checked against the workspace's secret patterns before it is written:
memory stores are scanned by the same detectors as code. The text is never echoed when
it is refused.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shutil
import sys
from pathlib import Path

SECTIONS = {
    "changed": "What changed",
    "open": "Open items",
    "tomorrow": "First thing tomorrow",
}
SESSIONS = "Sessions"
# The managed pattern file only; no environment variable can point elsewhere.
PATTERNS_FILE = Path("/opt/aegisx9/hooks/credential-patterns.txt")
PLACEHOLDER = "- (not recorded)"
PLACEHOLDER_PREFIX = "- (not recorded"
_HEADING = re.compile(r"^## (.+?)\s*$")


class SecretShapedTextError(ValueError):
    """A bullet looked like a credential and was refused."""


class PatternsUnavailableError(RuntimeError):
    """The managed credential-pattern file is missing or empty (fail closed)."""


class NoteMissingError(FileNotFoundError):
    """No note exists for the requested day."""


def today() -> str:
    return os.environ.get("AEGISX9_TODAY") or dt.date.today().isoformat()


def notes_dir() -> Path:
    override = os.environ.get("AEGISX9_HANDOFF_DIR")
    base = Path(override) if override else Path.home() / ".aegisx9" / "handoff"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base


def note_path(date: str) -> Path:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ValueError("date")
    return notes_dir() / f"{date}.md"


def secret_patterns() -> list[re.Pattern[str]]:
    """Compile the managed patterns; a missing or empty file refuses (fail closed)."""
    try:
        lines = PATTERNS_FILE.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        raise PatternsUnavailableError from e
    patterns = [re.compile(_to_python_re(ln)) for ln in lines if ln.strip()]
    if not patterns:
        raise PatternsUnavailableError
    return patterns


def _to_python_re(pattern: str) -> str:
    return pattern.replace("[[:space:]]", r"\s")


def check_text(text: str) -> None:
    for pattern in secret_patterns():
        if pattern.search(text):
            raise SecretShapedTextError


def parse(text: str) -> dict[str, list[str]]:
    """Split a note into ``{heading: [lines]}``; the title goes under ``""``."""
    sections: dict[str, list[str]] = {"": []}
    current = ""
    for line in text.splitlines():
        m = _HEADING.match(line)
        if m:
            current = m.group(1)
            sections.setdefault(current, [])
            continue
        sections[current].append(line)
    return sections


def render(date: str, sections: dict[str, list[str]]) -> str:
    out = [f"# Handoff {date}", ""]
    order = [*SECTIONS.values(), SESSIONS]
    extra = [h for h in sections if h and h not in order]
    for heading in order + extra:
        body = [ln for ln in sections.get(heading, []) if ln.strip()]
        if heading == SESSIONS and not body:
            continue
        out.append(f"## {heading}")
        out.extend(body or [PLACEHOLDER])
        out.append("")
    return "\n".join(out)


def load(date: str) -> dict[str, list[str]]:
    path = note_path(date)
    if path.exists():
        return parse(path.read_text(encoding="utf-8"))
    return {"": [], **{h: [] for h in SECTIONS.values()}}


def save(date: str, sections: dict[str, list[str]]) -> Path:
    path = note_path(date)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, render(date, sections).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, path)
    return path


def add(section: str, bullets: list[str], date: str) -> Path:
    heading = SECTIONS[section]
    sections = load(date)
    lines = [
        ln
        for ln in sections.get(heading, [])
        if ln.strip() and not ln.startswith(PLACEHOLDER_PREFIX)
    ]
    for bullet in bullets:
        text = bullet.strip()
        if not text:
            continue
        check_text(text)
        lines.append(text if text.startswith("- ") else f"- {text}")
    sections[heading] = lines
    return save(date, sections)


def stub(session: str, reason: str, date: str) -> tuple[Path, bool]:
    """Create today's note if missing; always record the ending session. Returns (path, created)."""
    created = not note_path(date).exists()
    sections = load(date)
    stamp = dt.datetime.now(dt.UTC).strftime("%H:%M UTC")
    session_lines = [ln for ln in sections.get(SESSIONS, []) if ln.strip()]
    note = "without a handoff note" if created else "note already present"
    session_lines.append(f"- {stamp}: session {session} ended ({reason}), {note}")
    sections[SESSIONS] = session_lines
    if created:
        sections[SECTIONS["changed"]] = [
            "- (not recorded: the session ended before a handoff was written;"
            " run `handoff add changed ...` to fill this in)"
        ]
    return save(date, sections), created


def show(date: str) -> str:
    path = note_path(date)
    if not path.exists():
        raise NoteMissingError(date)
    return path.read_text(encoding="utf-8")


def publish(date: str) -> Path:
    """Copy the note to the team-memory volume under the developer's user name."""
    team_dir = os.environ.get("AEGISX9_TEAM_MEMORY_DIR")
    if not team_dir or not Path(team_dir).is_dir():
        raise FileNotFoundError("team-memory")
    source = note_path(date)
    if not source.exists():
        raise NoteMissingError(date)
    check_text(source.read_text(encoding="utf-8"))
    user = re.sub(r"[^A-Za-z0-9_.-]", "", os.environ.get("USER", "dev")) or "dev"
    target_dir = Path(team_dir) / user
    target_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    target = target_dir / source.name
    shutil.copyfile(source, target)
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="handoff", description="Daily handoff notes.")
    parser.add_argument("--date", default=None, help="YYYY-MM-DD (default: today)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="append bullets to a section")
    p_add.add_argument("section", choices=sorted(SECTIONS))
    p_add.add_argument("text", nargs="*", help="bullet text (or use --stdin)")
    p_add.add_argument("--stdin", action="store_true", help="read one bullet per line")

    sub.add_parser("show", help="print the note")

    p_stub = sub.add_parser("stub", help="ensure a note exists (SessionEnd hook)")
    p_stub.add_argument("--session", required=True)
    p_stub.add_argument("--reason", default="unknown")

    sub.add_parser("publish", help="copy the note to team memory")
    return parser


def run(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    date = args.date or today()
    if args.command == "add":
        bullets = list(args.text)
        if args.stdin:
            bullets += sys.stdin.read().splitlines()
        if not bullets:
            raise ValueError("no text")
        add(args.section, bullets, date)
    elif args.command == "show":
        sys.stdout.write(show(date))
    elif args.command == "stub":
        _, created = stub(args.session, args.reason, date)
        if created:
            print("handoff: stub written; fill it in with `handoff add ...`", file=sys.stderr)
    elif args.command == "publish":
        publish(date)
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except SystemExit as e:  # argparse already printed its usage message
        return int(e.code or 0)
    except Exception as e:
        print(f"handoff: {type(e).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
