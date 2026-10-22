"""Internal-identifier denylist shared by the CI check and the log redaction filter.

The repository carries only generic patterns (private host addresses but not CIDR blocks,
``.local`` names, secret-store paths with at least two segments, build-job ids) in
``identifier-patterns.json``. The organisation's own
names and ranges are never in the repository: they arrive at runtime through the
``AEGISX9_EXTRA_IDENTIFIER_PATTERNS`` environment variable (newline-separated regexes,
injected from a CI secret that is never printed and is empty on forks).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

_PATTERN_FILE = Path(__file__).with_name("identifier-patterns.json")


def load_patterns() -> list[re.Pattern[str]]:
    raw = json.loads(_PATTERN_FILE.read_text())
    extra_env = os.environ.get("AEGISX9_EXTRA_IDENTIFIER_PATTERNS", "")
    extra = [p for p in extra_env.splitlines() if p.strip()]
    return [re.compile(p, re.IGNORECASE) for p in [*raw, *extra]]


def find(text: str, patterns: list[re.Pattern[str]]) -> list[tuple[int, str]]:
    """Return (line_number, pattern_index_label) pairs; never the matched text."""
    hits: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for idx, pat in enumerate(patterns):
            if pat.search(line):
                hits.append((lineno, f"pattern-{idx}"))
    return hits


def redact(text: str, patterns: list[re.Pattern[str]], extra_values: list[str]) -> str:
    out = text
    for value in sorted({v for v in extra_values if len(v) >= 4}, key=len, reverse=True):
        out = out.replace(value, "[masked]")
    for pat in patterns:
        out = pat.sub("[masked]", out)
    return out
