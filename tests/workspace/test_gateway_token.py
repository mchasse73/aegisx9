"""The apiKeyHelper against a fake `vault` binary: token on stdout, nothing else."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from ws_helpers import BIN_DIR, load_script

gateway_token = load_script("bin/gateway_token.py")

FAKE_VAULT = r"""#!/usr/bin/env bash
# Fake vault CLI for tests. Secrets reach it only through the environment.
set -eu
printf 'argv:%s\n' "$*" >> "$FAKE_VAULT_LOG"
sha=$(printf '%s' "${VAULT_TOKEN:-}" | sha256sum | cut -c1-12)
printf 'token_sha:%s\n' "$sha" >> "$FAKE_VAULT_LOG"
case "$1" in
  token)
    if [ "${VAULT_TOKEN:-}" = "$FAKE_VALID_TOKEN" ]; then
      printf '{"data":{"ttl":%s}}\n' "$FAKE_TTL"
    else
      echo "Error looking up token" >&2; exit 2
    fi ;;
  login)
    echo "Complete the login via your OIDC provider. Launching browser to:" >&2
    echo "    https://idp.example.test/authorize?state=x" >&2
    printf 'Success! You are now authenticated.\n'
    printf '{"auth":{"client_token":"%s"}}\n' "$FAKE_NEW_TOKEN" ;;
  read)
    [ -n "${VAULT_TOKEN:-}" ] || { echo "permission denied" >&2; exit 2; }
    printf '{"data":{"token":"%s","ttl":%s}}\n' "$FAKE_GW_TOKEN" "${FAKE_GW_TTL:-3600}" ;;
  *) exit 1 ;;
esac
"""


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


@pytest.fixture
def vault_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "vault"
    script.write_text(FAKE_VAULT)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    state = tmp_path / "state"
    env = {
        "FAKE_VAULT_LOG": str(tmp_path / "vault.log"),
        "FAKE_VALID_TOKEN": secrets.token_urlsafe(24),
        "FAKE_NEW_TOKEN": secrets.token_urlsafe(24),
        "FAKE_GW_TOKEN": secrets.token_urlsafe(48),
        "FAKE_TTL": "3600",
        "AEGISX9_STATE_DIR": str(state),
        "HOME": str(tmp_path / "home"),
    }
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    # Static credentials in the caller's environment must never reach vault.
    monkeypatch.setenv("ANTHROPIC_" + "API_KEY", "should-be-dropped")
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    return env


def _log(env: dict[str, str]) -> list[str]:
    return Path(env["FAKE_VAULT_LOG"]).read_text().splitlines()


def test_first_run_logs_in_and_issues_token(
    vault_env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert gateway_token.main() == 0
    out, err = capsys.readouterr()
    assert out == vault_env["FAKE_GW_TOKEN"] + "\n"
    assert err == ""
    log = _log(vault_env)
    argv_lines = [ln for ln in log if ln.startswith("argv:")]
    assert (
        argv_lines[0]
        == "argv:login -method=oidc -no-store -format=json role=aegisx9-developer skip_browser=true"
    )
    assert argv_lines[1] == "argv:read -format=json identity/oidc/token/aegisx9-gateway"
    for ln in argv_lines:  # no token on any command line
        for secret in (vault_env["FAKE_NEW_TOKEN"], vault_env["FAKE_VALID_TOKEN"]):
            assert secret not in ln
    # The read call carried the freshly issued Vault token in the environment.
    assert log[-1] == "token_sha:" + _sha(vault_env["FAKE_NEW_TOKEN"])
    state = Path(vault_env["AEGISX9_STATE_DIR"])
    for name in ("vault-token", "gateway-token.json"):
        assert stat.S_IMODE((state / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert (state / "vault-token").read_text().strip() == vault_env["FAKE_NEW_TOKEN"]
    cached = json.loads((state / "gateway-token.json").read_text())
    assert cached["token"] == vault_env["FAKE_GW_TOKEN"] and cached["expires_at"] > 0


def test_cached_gateway_token_short_circuits(
    vault_env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    state = Path(vault_env["AEGISX9_STATE_DIR"])
    state.mkdir(mode=0o700)
    token = secrets.token_urlsafe(40)
    gateway_token.write_private(
        state / "gateway-token.json", json.dumps({"token": token, "expires_at": 4102444800})
    )
    assert gateway_token.main() == 0
    assert capsys.readouterr().out == token + "\n"
    assert not Path(vault_env["FAKE_VAULT_LOG"]).exists()


def test_expired_gateway_token_reuses_valid_vault_token(
    vault_env: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    state = Path(vault_env["AEGISX9_STATE_DIR"])
    state.mkdir(mode=0o700)
    gateway_token.write_private(
        state / "gateway-token.json", json.dumps({"token": "old", "expires_at": 10})
    )
    gateway_token.write_private(state / "vault-token", vault_env["FAKE_VALID_TOKEN"] + "\n")
    assert gateway_token.main() == 0
    assert capsys.readouterr().out == vault_env["FAKE_GW_TOKEN"] + "\n"
    argv_lines = [ln for ln in _log(vault_env) if ln.startswith("argv:")]
    assert [ln.split()[0] for ln in argv_lines] == ["argv:token", "argv:read"]


def test_vault_token_near_expiry_triggers_login(
    vault_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FAKE_TTL", "120")
    state = Path(vault_env["AEGISX9_STATE_DIR"])
    state.mkdir(mode=0o700)
    gateway_token.write_private(state / "vault-token", vault_env["FAKE_VALID_TOKEN"])
    assert gateway_token.gateway_token(now=1.0) == vault_env["FAKE_GW_TOKEN"]
    argv_lines = [ln.split()[0] for ln in _log(vault_env) if ln.startswith("argv:")]
    assert argv_lines == ["argv:token", "argv:login", "argv:read"]
    assert (state / "vault-token").read_text().strip() == vault_env["FAKE_NEW_TOKEN"]


def test_world_readable_cache_is_ignored(vault_env: dict[str, str]) -> None:
    state = Path(vault_env["AEGISX9_STATE_DIR"])
    state.mkdir(mode=0o700)
    loose = state / "vault-token"
    loose.write_text(vault_env["FAKE_VALID_TOKEN"])
    loose.chmod(0o644)
    assert gateway_token.read_private(loose) is None
    assert gateway_token.gateway_token(now=1.0) == vault_env["FAKE_GW_TOKEN"]
    assert "argv:login" in [ln.split()[0] for ln in _log(vault_env)]
    assert gateway_token.cached_gateway_token(now=0.0) is not None
    (state / "gateway-token.json").write_text("not json")
    assert gateway_token.cached_gateway_token(now=0.0) is None


def test_errors_print_type_name_only(
    vault_env: dict[str, str], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", str(Path(vault_env["HOME"]) / "empty"))
    assert gateway_token.main() == 1
    out, err = capsys.readouterr()
    assert out == "" and err == "gateway-token: VaultUnavailableError\n"


def test_malformed_vault_output(vault_env: dict[str, str], monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(gateway_token.VaultResponseError):
        gateway_token.parse_json_output("no json here")
    with pytest.raises(gateway_token.VaultResponseError):
        gateway_token.parse_json_output("[1, 2]")
    assert gateway_token.parse_json_output('prefix\n{"a": 1}') == {"a": 1}
    monkeypatch.setenv("FAKE_NEW_TOKEN", "")
    with pytest.raises(gateway_token.VaultResponseError):
        gateway_token.oidc_login()
    monkeypatch.setenv("FAKE_GW_TOKEN", "")
    with pytest.raises(gateway_token.VaultResponseError):
        gateway_token.issue_gateway_token(vault_env["FAKE_VALID_TOKEN"], now=0.0)
    assert gateway_token.vault_token_ttl("wrong") == -1


def test_runs_as_a_script(vault_env: dict[str, str]) -> None:
    result = subprocess.run(  # noqa: S603 - the script under test
        [sys.executable, str(BIN_DIR / "gateway_token.py")],
        capture_output=True,
        text=True,
        env=dict(os.environ),
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == vault_env["FAKE_GW_TOKEN"] + "\n"
    assert "Complete the login" in result.stderr  # the browser hand-off reaches the IDE
    assert vault_env["FAKE_NEW_TOKEN"] not in result.stderr
