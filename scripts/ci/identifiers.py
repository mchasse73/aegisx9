"""Internal-identifier denylist shared by the CI check and the log redaction filter.

The patterns live base64-encoded next to this file so the repository does not publish the
identifiers it protects. Extra patterns can be supplied at runtime through the
``AEGISX9_EXTRA_IDENTIFIER_PATTERNS`` environment variable (newline-separated regexes,
typically injected from a CI secret, which is never printed).
"""

from __future__ import annotations

import base64
import json
import os
import re
from pathlib import Path

_PATTERN_FILE = Path(__file__).with_name(".identifier-patterns.b64")


def load_patterns() -> list[re.Pattern[str]]:
    raw = json.loads(base64.b64decode(_PATTERN_FILE.read_text().strip()))
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
