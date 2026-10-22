"""Hook behaviour: block versus allow, driven by crafted stdin. Nothing sensitive is echoed."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

import pytest
from ws_helpers import HOOKS_DIR, RunHook

import samples


def _broken_grep(tmp_path: Path) -> dict[str, str]:
    """A PATH prefix whose `grep` crashes, to exercise the fail-closed path."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "grep"
    script.write_text("#!/usr/bin/env bash\nexit 7\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


# --- prompt-credential-check -------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        samples.aws_access_key_id(),
        samples.github_token(),
        samples.private_key_block(),
        samples.jwt(),
        samples.labelled_api_key(),
        "hv" + "s." + secrets.token_urlsafe(32),
    ],
    # Explicit ids: the sample values must never appear in test ids, caches or CI logs.
    ids=["aws", "github", "private-key", "jwt", "labelled", "vault"],
)
def test_prompt_with_secret_is_blocked_without_echo(
    run_hook: RunHook, tmp_path: Path, secret: str
) -> None:
    prompt = f"please deploy this for me: {secret} thanks"
    result = run_hook("prompt-credential-check.sh", {"prompt": prompt})
    assert result.returncode == 2
    assert result.stderr.startswith("prompt-credential-check: ")
    assert result.stderr.count("\n") == 1
    for fragment in (secret, secret[:8], secret[-8:]):
        assert fragment not in result.stderr and fragment not in result.stdout


def test_clean_prompt_is_allowed(run_hook: RunHook) -> None:
    result = run_hook("prompt-credential-check.sh", {"prompt": "refactor the parser and add tests"})
    assert result.returncode == 0, result.stderr
    assert result.stdout == "" and result.stderr == ""


def test_prompt_check_fails_closed(run_hook: RunHook, tmp_path: Path) -> None:
    payload = {"prompt": "hello"}
    crashed = run_hook("prompt-credential-check.sh", payload, _broken_grep(tmp_path))
    assert crashed.returncode == 2 and "fail closed" in crashed.stderr
    # The managed pattern file is the only source: an override is ignored, and an
    # empty or missing file blocks.
    patterns = tmp_path / "opt" / "hooks" / "credential-patterns.txt"
    ignored = run_hook(
        "prompt-credential-check.sh", payload, {"AEGISX9_CREDENTIAL_PATTERNS": "/dev/null"}
    )
    assert ignored.returncode == 0
    patterns.write_text("\n  \n")
    empty = run_hook("prompt-credential-check.sh", payload)
    assert empty.returncode == 2 and "pattern file" in empty.stderr
    patterns.unlink()
    missing = run_hook("prompt-credential-check.sh", payload)
    assert missing.returncode == 2 and "pattern file" in missing.stderr


def test_prompt_check_rejects_malformed_input(run_hook: RunHook) -> None:
    result = run_hook("prompt-credential-check.sh", {"prompt": ["not", "a", "string"]})
    assert result.returncode == 0  # non-string prompts are serialised and scanned
    broken = run_hook("prompt-credential-check.sh", {})
    assert broken.returncode == 0
    not_json = run_hook("prompt-credential-check.sh", "not json")
    assert not_json.returncode == 2 and "fail closed" in not_json.stderr


# --- pretooluse-guard ----------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "cat ~/.claude/.credentials.json",
        "cat $HOME/.aegisx9/vault-token",
        "base64 ~/.ssh/id_ed25519",
        "cat ~/.aws/credentials",
        "env",
        "env | grep -i key",
        "printenv",
        "printenv VAULT_TOKEN",
        "set",
        "export -p",
        "python3 -c 'import os; print(os.environ)'",
        "node -e 'console.log(process.env)'",
        "cat /proc/self/environ",
        "export ANTHROPIC_" + "API_KEY=abc",
        "sudo apt-get install something",
        "cat .env",
        "cat secrets/db.yaml",
        "cat /etc/shadow",
        "cat ~/.docker/config.json",
        "cat .en[v]",
        "cat ./.e?v",
        "cat *env",
        "head .env*",
        "cat .{e,}nv",
    ],
)
def test_guard_blocks_credential_access(run_hook: RunHook, command: str) -> None:
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    result = run_hook("pretooluse-guard.sh", payload)
    assert result.returncode == 2, command
    assert result.stderr.startswith("pretooluse-guard: ")
    assert result.stderr.count("\n") == 1
    if len(command) > 8:  # short words such as "env" legitimately appear in the reason
        assert command not in result.stderr


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status && git diff --stat",
        "pytest -q tests/",
        "env VAR=1 python3 script.py",
        "python3 -c 'print(1+1)'",
        "set -euo pipefail; make test",
        "grep -rn environment docs/",
        "cat README.md",
        "ls src/secrets.py",
        "echo $HOME",
        "ls *.py",
        "ls -a .*",
        "cat .venv/pyvenv.cfg",
        "rm -rf build/*",
    ],
)
def test_guard_allows_ordinary_commands(run_hook: RunHook, command: str) -> None:
    payload = {"tool_name": "Bash", "tool_input": {"command": command}}
    result = run_hook("pretooluse-guard.sh", payload)
    assert result.returncode == 0, (command, result.stderr)


def test_guard_ignores_other_tools_and_fails_closed(run_hook: RunHook, tmp_path: Path) -> None:
    other = run_hook(
        "pretooluse-guard.sh",
        {"tool_name": "Read", "tool_input": {"file_path": "~/.aws/credentials"}},
    )
    assert other.returncode == 0
    garbage = run_hook(
        "pretooluse-guard.sh", {"tool_name": "Bash", "tool_input": {"command": ["ls"]}}
    )
    assert garbage.returncode == 0
    ls = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
    printenv = {"tool_name": "Bash", "tool_input": {"command": "printenv"}}
    ignored = run_hook("pretooluse-guard.sh", printenv, {"AEGISX9_BASH_DENY_PATTERNS": "/dev/null"})
    assert ignored.returncode == 2  # an environment override is not honoured
    patterns = tmp_path / "opt" / "hooks" / "bash-deny-patterns.txt"
    patterns.write_text("")
    assert run_hook("pretooluse-guard.sh", ls).returncode == 2
    patterns.unlink()
    assert run_hook("pretooluse-guard.sh", ls).returncode == 2


# --- session-end-handoff --------------------------------------------------------------


def test_session_end_creates_stub(run_hook: RunHook, tmp_path: Path) -> None:
    notes = tmp_path / "notes"
    env = {"AEGISX9_HANDOFF_DIR": str(notes), "AEGISX9_TODAY": "2026-01-02"}
    session = "sess-" + secrets.token_hex(4)
    result = run_hook("session-end-handoff.sh", {"session_id": session, "reason": "exit"}, env)
    assert result.returncode == 0, result.stderr
    note = (notes / "2026-01-02.md").read_text()
    assert note.startswith("# Handoff 2026-01-02")
    assert session in note and "(exit)" in note and "without a handoff note" in note
    assert "## First thing tomorrow" in note
    assert stat.S_IMODE((notes / "2026-01-02.md").stat().st_mode) == 0o600
    # A second session the same day keeps the note and records itself.
    again = run_hook("session-end-handoff.sh", {"session_id": "s2", "reason": "logout"}, env)
    assert again.returncode == 0
    assert "note already present" in (notes / "2026-01-02.md").read_text()


def test_session_end_tolerates_bad_input_and_fails_without_cli(
    run_hook: RunHook, tmp_path: Path
) -> None:
    notes = tmp_path / "notes2"
    env = {"AEGISX9_HANDOFF_DIR": str(notes), "AEGISX9_TODAY": "2026-01-03"}
    result = run_hook("session-end-handoff.sh", {"session_id": "../x; rm -rf /"}, env)
    assert result.returncode == 0
    assert "session ..xrm-rf ended (unknown)" in (notes / "2026-01-03.md").read_text()
    # An override naming another program is ignored; the managed CLI always runs.
    rogue = tmp_path / "rogue"
    rogue.write_text('#!/bin/sh\ntouch "$0.ran"\n')
    rogue.chmod(0o755)
    again = run_hook(
        "session-end-handoff.sh", {"session_id": "s"}, {**env, "AEGISX9_HANDOFF_BIN": str(rogue)}
    )
    assert again.returncode == 0 and not (tmp_path / "rogue.ran").exists()
    (tmp_path / "opt" / "bin" / "handoff").unlink()
    missing = run_hook("session-end-handoff.sh", {"session_id": "s"}, env)
    assert missing.returncode == 2 and "session-end-handoff:" in missing.stderr


def test_hook_scripts_are_executable_and_set_strict_mode() -> None:
    for script in HOOKS_DIR.glob("*.sh"):
        text = script.read_text()
        assert text.startswith("#!/usr/bin/env bash")
        assert "set -euo pipefail" in text
        assert os.access(script, os.X_OK)
