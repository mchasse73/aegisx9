"""The identifier denylist must find and mask without ever printing what it matched."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
MODULE = ROOT / "scripts" / "ci" / "identifiers.py"
spec = importlib.util.spec_from_file_location("identifiers", MODULE)
assert spec and spec.loader
identifiers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identifiers)


def test_patterns_load_and_are_regexes() -> None:
    pats = identifiers.load_patterns()
    assert len(pats) >= 5
    assert all(hasattr(p, "search") for p in pats)


def test_find_reports_labels_not_text() -> None:
    pats = identifiers.load_patterns()
    sample = "host " + "node1.corp" + ".local" + " reachable"
    hits = identifiers.find(sample, pats)
    assert hits and all(label.startswith("pattern-") for _, label in hits)
    assert "corp" not in " ".join(label for _, label in hits)


def test_extra_patterns_from_environment(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("AEGISX9_EXTRA_IDENTIFIER_PATTERNS", r"\bzz-internal-\d+\b")
    pats = identifiers.load_patterns()
    assert identifiers.find("see zz-internal-7 now", pats)


def test_redact_masks_patterns_and_env_values() -> None:
    pats = identifiers.load_patterns()
    secret_value = "internal-" + "value-" + "42"
    text = f"url={secret_value} ip=10." + "1" + ".2.3 done"
    out = identifiers.redact(text, pats, [secret_value])
    assert secret_value not in out
    assert "10." + "1.2.3" not in out
    assert "done" in out


def test_generic_cidr_blocks_and_prose_are_not_hits() -> None:
    pats = identifiers.load_patterns()
    assert not identifiers.find("egressExceptCidrs: 10.0.0.0/8 and 192.168.0.0/16", pats)
    assert not identifiers.find("covers secret/PII echo in prompts", pats)
    assert identifiers.find("vault path " + "secret" + "/team/app-key", pats)


def test_clean_text_untouched() -> None:
    pats = identifiers.load_patterns()
    text = "Apply complete! Resources: 1 added, 0 changed, 0 destroyed."
    assert identifiers.redact(text, pats, []) == text
