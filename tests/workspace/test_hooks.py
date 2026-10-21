"""Hook behaviour: block versus allow, driven by crafted stdin. Nothing sensitive is echoed."""

from __future__ import annotations

import os
import secrets
import shutil
import stat
from pathlib import Path

import pytest
from ws_helpers import HOOKS_DIR, RunHook

import samples

HAS_GITLEAKS = shutil.which("gitleaks") is not None
needs_gitleaks = pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not on PATH")


def _fake_gitleaks(tmp_path: Path, exit_code: int) -> dict[str, str]:
    """A PATH prefix whose `gitleaks` exits with a fixed code (0 clean, 2 leak, 7 crash)."""
    bin_dir = tmp_path / "fakebin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "gitleaks"
    script.write_text(f"#!/usr/bin/env bash\nexit {exit_code}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def _no_gitleaks(tmp_path: Path) -> dict[str, str]:
    """A PATH with only the essentials, so `gitleaks` is missing."""
    bin_dir = tmp_path / "minbin"
    bin_dir.mkdir(exist_ok=True)
    for tool in ("bash", "python3", "grep", "mktemp", "rm", "dirname", "cat", "date"):
        src = shutil.which(tool)
        assert src is not None
        (bin_dir / tool).symlink_to(src)
    return {"PATH": str(bin_dir)}


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
    # The regex layer must catch each shape on its own: gitleaks is faked as "clean".
    result = run_hook("prompt-credential-check.sh", {"prompt": prompt}, _fake_gitleaks(tmp_path, 0))
    assert result.returncode == 2
    assert result.stderr.startswith("prompt-credential-check: ")
    assert result.stderr.count("\n") == 1
    for fragment in (secret, secret[:8], secret[-8:]):
        assert fragment not in result.stderr and fragment not in result.stdout


@needs_gitleaks
def test_clean_prompt_is_allowed(run_hook: RunHook) -> None:
    result = run_hook("prompt-credential-check.sh", {"prompt": "refactor the parser and add tests"})
    assert result.returncode == 0, result.stderr
    assert result.stdout == "" and result.stderr == ""


@needs_gitleaks
def test_gitleaks_layer_catches_what_the_regexes_do_not(run_hook: RunHook) -> None:
    # A Slack webhook style URL is not in the fast pattern list but is in gitleaks' rules.
    hook = "https://hooks.slack.com/services/T" + secrets.token_hex(4).upper()
    hook += (
        "/B" + secrets.token_hex(4).upper() + "/" + secrets.token_hex(12)
    )  # [0-9a-f] only: matches the rule shape
    result = run_hook("prompt-credential-check.sh", {"prompt": f"post to {hook}"})
    assert result.returncode == 2
    assert "gitleaks" in result.stderr
    assert hook not in result.stderr


def test_prompt_check_fails_closed(run_hook: RunHook, tmp_path: Path) -> None:
    payload = {"prompt": "hello"}
    crashed = run_hook("prompt-credential-check.sh", payload, _fake_gitleaks(tmp_path, 7))
    assert crashed.returncode == 2 and "fail closed" in crashed.stderr
    missing = run_hook("prompt-credential-check.sh", payload, _no_gitleaks(tmp_path))
    assert missing.returncode == 2 and "unavailable" in missing.stderr
    leak = run_hook("prompt-credential-check.sh", payload, _fake_gitleaks(tmp_path, 2))
    assert leak.returncode == 2 and "gitleaks" in leak.stderr
    no_patterns = run_hook(
        "prompt-credential-check.sh",
        payload,
        {"AEGISX9_CREDENTIAL_PATTERNS": str(tmp_path / "none")},
    )
    assert no_patterns.returncode == 2 and "pattern file" in no_patterns.stderr


def test_prompt_check_rejects_malformed_input(run_hook: RunHook, tmp_path: Path) -> None:
    result = run_hook(
        "prompt-credential-check.sh",
        {"prompt": ["not", "a", "string"]},
        _fake_gitleaks(tmp_path, 0),
    )
    assert result.returncode == 0  # non-string prompts are serialised and scanned
    broken = run_hook("prompt-credential-check.sh", {}, _fake_gitleaks(tmp_path, 0))
    assert broken.returncode == 0


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
    no_patterns = run_hook(
        "pretooluse-guard.sh",
        {"tool_name": "Bash", "tool_input": {"command": "ls"}},
        {"AEGISX9_BASH_DENY_PATTERNS": str(tmp_path / "none")},
    )
    assert no_patterns.returncode == 2
    garbage = run_hook(
        "pretooluse-guard.sh", {"tool_name": "Bash", "tool_input": {"command": ["ls"]}}
    )
    assert garbage.returncode == 0


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
    missing = run_hook(
        "session-end-handoff.sh",
        {"session_id": "s"},
        {**env, "AEGISX9_HANDOFF_BIN": str(tmp_path / "nope")},
    )
    assert missing.returncode == 2 and "session-end-handoff:" in missing.stderr


def test_hook_scripts_are_executable_and_set_strict_mode() -> None:
    for script in HOOKS_DIR.glob("*.sh"):
        text = script.read_text()
        assert text.startswith("#!/usr/bin/env bash")
        assert "set -euo pipefail" in text
        assert os.access(script, os.X_OK)
