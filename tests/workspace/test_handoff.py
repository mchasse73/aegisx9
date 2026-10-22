"""The handoff CLI: note format, secret refusal, stub and team-memory publish."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from ws_helpers import HOOKS_DIR, install_image_copy, load_script

import samples

handoff = load_script("bin/handoff.py")


@pytest.fixture
def notes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(handoff, "PATTERNS_FILE", HOOKS_DIR / "credential-patterns.txt")
    notes_dir = tmp_path / "handoff"
    monkeypatch.setenv("AEGISX9_HANDOFF_DIR", str(notes_dir))
    monkeypatch.setenv("AEGISX9_TODAY", "2026-03-04")
    monkeypatch.setenv("USER", "jane")
    return notes_dir


def test_add_and_show(notes: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert handoff.main(["add", "changed", "Shipped the image (refs #48)"]) == 0
    assert handoff.main(["add", "open", "- CI runner label", "Sandbox userns"]) == 0
    assert handoff.main(["add", "tomorrow", "Run the self-test"]) == 0
    assert handoff.main(["show"]) == 0
    text = capsys.readouterr().out
    assert text == (
        "# Handoff 2026-03-04\n\n"
        "## What changed\n- Shipped the image (refs #48)\n\n"
        "## Open items\n- CI runner label\n- Sandbox userns\n\n"
        "## First thing tomorrow\n- Run the self-test\n"
    )
    path = notes / "2026-03-04.md"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(notes.stat().st_mode) == 0o700


def test_add_from_stdin_and_date_override(notes: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", _Stdin("one\n\ntwo\n"))
    assert handoff.main(["--date", "2026-03-01", "add", "open", "--stdin"]) == 0
    text = (notes / "2026-03-01.md").read_text()
    assert "- one\n- two\n" in text
    assert "## What changed\n- (not recorded)" in text


class _Stdin:
    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text


@pytest.mark.parametrize(
    "secret",
    [
        samples.aws_access_key_id(),
        samples.github_token(),
        samples.jwt(),
        samples.labelled_api_key(),
    ],
    ids=["aws", "github", "jwt", "labelled"],  # sample values never appear in test ids
)
def test_refuses_credential_shaped_bullets(
    notes: Path, capsys: pytest.CaptureFixture[str], secret: str
) -> None:
    assert handoff.main(["add", "changed", f"rotated {secret}"]) == 1
    out, err = capsys.readouterr()
    assert out == "" and err == "handoff: SecretShapedTextError\n"
    assert not (notes / "2026-03-04.md").exists()


def test_stub_then_fill_in(notes: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert handoff.main(["stub", "--session", "abc123", "--reason", "exit"]) == 0
    assert "stub written" in capsys.readouterr().err
    text = (notes / "2026-03-04.md").read_text()
    assert "session abc123 ended (exit), without a handoff note" in text
    assert "## Open items\n- (not recorded)" in text
    assert "run `handoff add changed ...`" in text
    assert handoff.main(["add", "changed", "Real content"]) == 0
    assert handoff.main(["add", "open", "Something"]) == 0
    text = (notes / "2026-03-04.md").read_text()
    assert "## What changed\n- Real content\n" in text
    assert "(not recorded" not in text.split("## First thing tomorrow")[0]
    assert "## Sessions\n- " in text
    assert handoff.main(["stub", "--session", "def", "--reason", "logout"]) == 0
    assert (
        "session def ended (logout), note already present" in (notes / "2026-03-04.md").read_text()
    )


def test_publish_to_team_memory(
    notes: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert handoff.main(["publish"]) == 1
    assert capsys.readouterr().err == "handoff: FileNotFoundError\n"
    team = tmp_path / "team-memory"
    team.mkdir()
    monkeypatch.setenv("AEGISX9_TEAM_MEMORY_DIR", str(team))
    assert handoff.main(["publish"]) == 1  # no note yet
    assert capsys.readouterr().err == "handoff: NoteMissingError\n"
    assert handoff.main(["add", "changed", "x"]) == 0
    assert handoff.main(["publish"]) == 0
    assert (team / "jane" / "2026-03-04.md").read_text() == (notes / "2026-03-04.md").read_text()
    # A note that somehow carries a secret is never published.
    (notes / "2026-03-04.md").write_text(
        "# Handoff 2026-03-04\n\n## What changed\n- " + samples.github_token() + "\n"
    )
    assert handoff.main(["publish"]) == 1
    assert capsys.readouterr().err == "handoff: SecretShapedTextError\n"


def test_errors_and_usage(notes: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert handoff.main(["show"]) == 1
    assert capsys.readouterr().err == "handoff: NoteMissingError\n"
    assert handoff.main(["add", "changed"]) == 1
    assert capsys.readouterr().err == "handoff: ValueError\n"
    assert handoff.main(["--date", "yesterday", "add", "changed", "x"]) == 1
    assert capsys.readouterr().err == "handoff: ValueError\n"
    assert handoff.main(["bogus"]) == 2  # argparse usage error
    assert handoff.main(["--help"]) == 0


def test_patterns_fail_closed(
    notes: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An environment override is never read.
    monkeypatch.setenv("AEGISX9_CREDENTIAL_PATTERNS", str(tmp_path / "missing.txt"))
    assert handoff.secret_patterns()
    monkeypatch.setattr(handoff, "PATTERNS_FILE", tmp_path / "missing.txt")
    with pytest.raises(handoff.PatternsUnavailableError):
        handoff.secret_patterns()
    empty = tmp_path / "empty.txt"
    empty.write_text("\n   \n")
    monkeypatch.setattr(handoff, "PATTERNS_FILE", empty)
    with pytest.raises(handoff.PatternsUnavailableError):
        handoff.secret_patterns()
    assert handoff.main(["add", "changed", "harmless"]) == 1
    assert capsys.readouterr().err == "handoff: PatternsUnavailableError\n"
    assert not (notes / "2026-03-04.md").exists()


def test_parse_roundtrip() -> None:
    text = "# Handoff 2026-03-04\n\n## What changed\n- a\n\n## Custom\n- b\n"
    sections = handoff.parse(text)
    assert sections["Custom"] == ["- b"]
    rendered = handoff.render("2026-03-04", sections)
    assert "## Custom\n- b\n" in rendered and "## Open items\n- (not recorded)" in rendered


def test_runs_as_a_script(notes: Path, tmp_path: Path) -> None:
    opt = install_image_copy(tmp_path / "opt")  # the CLI reads only /opt paths
    result = subprocess.run(  # noqa: S603 - the script under test
        [sys.executable, str(opt / "bin" / "handoff"), "add", "tomorrow", "Start here"],
        capture_output=True,
        text=True,
        env=dict(os.environ),
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "- Start here" in (notes / "2026-03-04.md").read_text()
