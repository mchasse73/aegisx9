"""Fail when a tracked file contains an internal identifier (see identifiers.py).

Usage: python3 scripts/ci/check_identifiers.py [paths...]  (default: all git-tracked files)
Prints file and line numbers plus a pattern label, never the matched text, so the check
itself cannot leak what it guards. Exit 1 on any hit.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from identifiers import find, load_patterns

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pdf", ".b64"}


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True)  # noqa: S607
    return [Path(p) for p in out.stdout.decode().split("\0") if p]


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv] or tracked_files()
    patterns = load_patterns()
    total = 0
    for path in paths:
        if path.suffix.lower() in SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, label in find(text, patterns):
            total += 1
            print(f"{path}:{lineno}: internal identifier ({label})")
    if total:
        print(f"identifier check: {total} hit(s); generalise them before going public")
        return 1
    print("identifier check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
