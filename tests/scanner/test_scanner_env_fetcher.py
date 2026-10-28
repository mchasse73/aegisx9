"""The boot-time secrets fetcher (scanner/systemd/aegisx9-scanner-env), run with a fake
``aws`` on PATH. A required parameter that cannot be read fails the service and never
leaves an empty secret file; an absent optional one stays informational (#96)."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from conftest import ROOT

BASH = shutil.which("bash") or "/bin/bash"
SCRIPT = ROOT / "scanner" / "systemd" / "aegisx9-scanner-env"
PARAMS = {
    "WEBHOOK_URL_PARAMETER": "/example/scanner/webhook_url",
    "WEBHOOK_SECRET_PARAMETER": "/example/scanner/webhook_secret",
    "TUNNEL_SECRET_PARAMETER": "/example/scanner/tunnel_secret",
    "REDTEAM_KEY_PARAMETER": "/example/scanner/redteam_key",
}

# A stand-in for the AWS CLI: values come from files in $FAKE_SSM named after the
# parameter; a name listed in $FAKE_SSM/denied fails as access denied; a number in
# $FAKE_SSM/<key>.flaky is how many more calls fail with a network error first; anything
# else is ParameterNotFound. Mirrors the real CLI's stdout/stderr split.
FAKE_AWS = """#!/bin/bash
name=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--name" ]; then name="$2"; shift; fi
  shift
done
key="${name//\\//_}"
flaky="${FAKE_SSM}/${key}.flaky"
if [ -f "${flaky}" ] && [ "$(cat "${flaky}")" -gt 0 ]; then
  echo $(( $(cat "${flaky}") - 1 )) > "${flaky}"
  echo "Could not connect to the endpoint URL" >&2
  exit 255
fi
if grep -qx -- "${name}" "${FAKE_SSM}/denied" 2>/dev/null; then
  echo "An error occurred (AccessDeniedException) when calling the GetParameter operation" >&2
  exit 254
fi
if [ -f "${FAKE_SSM}/${key}" ]; then
  cat "${FAKE_SSM}/${key}"; echo
  exit 0
fi
echo "An error occurred (ParameterNotFound) when calling the GetParameter operation" >&2
exit 254
"""

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")


def _setup(tmp_path: Path, *, redteam_target: str = "") -> tuple[Path, Path, dict[str, str]]:
    conf_dir = tmp_path / "etc"
    conf_dir.mkdir()
    lines = ["AWS_REGION='us-east-1'", f"REDTEAM_TARGET_URL='{redteam_target}'"]
    lines += [f"{k}='{v}'" for k, v in PARAMS.items()]
    (conf_dir / "env-source.conf").write_text("\n".join(lines) + "\n")
    ssm = tmp_path / "ssm"
    ssm.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    aws = bindir / "aws"
    aws.write_text(FAKE_AWS)
    aws.chmod(0o755)
    env = {
        "PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "AEGISX9_SCANNER_ENV_DIR": str(conf_dir),
        "FAKE_SSM": str(ssm),
        "AEGISX9_SCANNER_ENV_RETRY_DELAYS": "0 0 0 0",
    }
    return conf_dir, ssm, env


def _put(ssm: Path, name: str, value: str) -> None:
    (ssm / name.replace("/", "_")).write_text(value)


def _run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed script, test-only environment
        [BASH, str(SCRIPT)], env=env, capture_output=True, text=True, check=False, timeout=30
    )


def _logs(proc: subprocess.CompletedProcess[str]) -> list[dict[str, str]]:
    return [json.loads(line) for line in proc.stderr.splitlines() if line.startswith("{")]


def test_all_required_present_optional_absent(tmp_path: Path) -> None:
    conf_dir, ssm, env = _setup(tmp_path)
    hook_key = secrets.token_urlsafe(24)
    _put(ssm, PARAMS["WEBHOOK_SECRET_PARAMETER"], hook_key)
    _put(ssm, PARAMS["WEBHOOK_URL_PARAMETER"], "https://eda.example.com/hook")
    proc = _run(env)
    assert proc.returncode == 0, _logs(proc)
    assert (conf_dir / "webhook_secret").read_text() == hook_key
    for f in ("webhook_secret", "webhook_url", "tunnel_secret", "redteam_key", "env"):
        assert stat.S_IMODE((conf_dir / f).stat().st_mode) == 0o600, f
    # Absent optional parameters are informational and leave an empty file.
    assert (conf_dir / "tunnel_secret").read_text() == ""
    absent = [r for r in _logs(proc) if "optional parameter absent" in r["msg"]]
    assert {r["level"] for r in absent} == {"info"} and len(absent) == 2
    assert (
        "AEGISX9_SCANNER_WEBHOOK_URL=https://eda.example.com/hook" in (conf_dir / "env").read_text()
    )
    # No value reaches a log line.
    assert hook_key not in proc.stderr and hook_key not in proc.stdout
    assert not list(conf_dir.glob(".fetch*"))


def test_required_parameter_missing_fails_and_leaves_no_empty_file(tmp_path: Path) -> None:
    conf_dir, ssm, env = _setup(tmp_path)
    _put(ssm, PARAMS["WEBHOOK_URL_PARAMETER"], "https://eda.example.com/hook")
    # A stale file from an earlier boot must not survive as if it were current.
    (conf_dir / "webhook_secret").write_text("")
    proc = _run(env)
    assert proc.returncode == 1
    assert not (conf_dir / "webhook_secret").exists()
    errors = [r for r in _logs(proc) if r["level"] == "error"]
    assert any(
        "required parameter not readable (absent)" in r["msg"]
        and PARAMS["WEBHOOK_SECRET_PARAMETER"] in r["msg"]
        for r in errors
    )
    assert not (conf_dir / "env").exists()


def test_access_denied_and_empty_values_are_errors(tmp_path: Path) -> None:
    conf_dir, ssm, env = _setup(tmp_path)
    _put(ssm, PARAMS["WEBHOOK_SECRET_PARAMETER"], secrets.token_urlsafe(24))
    _put(ssm, PARAMS["WEBHOOK_URL_PARAMETER"], "")
    (ssm / "denied").write_text(PARAMS["TUNNEL_SECRET_PARAMETER"] + "\n")
    proc = _run(env)
    assert proc.returncode == 1
    msgs = {r["msg"]: r["level"] for r in _logs(proc)}
    assert msgs[f"required parameter not readable (empty): {PARAMS['WEBHOOK_URL_PARAMETER']}"] == (
        "error"
    )
    tunnel = PARAMS["TUNNEL_SECRET_PARAMETER"]
    denied = f"optional parameter not readable (access_denied) after retries: {tunnel}"
    assert msgs[denied + " (empty file)"] == "error"
    # Access denied is retried (the instance role can lag at boot): 4 retries logged.
    retries = [r for r in _logs(proc) if r["msg"].startswith("parameter read failed")]
    assert len([r for r in retries if tunnel in r["msg"]]) == 4
    assert not (conf_dir / "webhook_url").exists()


def test_redteam_key_required_when_a_target_is_set(tmp_path: Path) -> None:
    conf_dir, ssm, env = _setup(tmp_path, redteam_target="https://gateway.example.com")
    _put(ssm, PARAMS["WEBHOOK_SECRET_PARAMETER"], secrets.token_urlsafe(24))
    _put(ssm, PARAMS["WEBHOOK_URL_PARAMETER"], "https://eda.example.com/hook")
    proc = _run(env)
    assert proc.returncode == 1
    assert not (conf_dir / "redteam_key").exists()
    key = secrets.token_urlsafe(24)
    _put(ssm, PARAMS["REDTEAM_KEY_PARAMETER"], key)
    proc = _run(env)
    assert proc.returncode == 0 and (conf_dir / "redteam_key").read_text() == key


def test_missing_aws_cli_fails(tmp_path: Path) -> None:
    _conf, _ssm, env = _setup(tmp_path)
    (tmp_path / "bin" / "aws").unlink()
    env["PATH"] = str(tmp_path / "bin")
    proc = subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 1
    assert any("aws cli not found" in r["msg"] for r in _logs(proc))


def _good(ssm: Path) -> str:
    key = secrets.token_urlsafe(24)
    _put(ssm, PARAMS["WEBHOOK_SECRET_PARAMETER"], key)
    _put(ssm, PARAMS["WEBHOOK_URL_PARAMETER"], "https://eda.example.com/hook")
    return key


def _flaky(ssm: Path, name: str, failures: int) -> None:
    (ssm / (name.replace("/", "_") + ".flaky")).write_text(f"{failures}\n")


def test_transient_error_is_retried_then_succeeds(tmp_path: Path) -> None:
    conf_dir, ssm, env = _setup(tmp_path)
    key = _good(ssm)
    _flaky(ssm, PARAMS["WEBHOOK_SECRET_PARAMETER"], 3)
    proc = _run(env)
    assert proc.returncode == 0, _logs(proc)
    assert (conf_dir / "webhook_secret").read_text() == key
    retries = [r for r in _logs(proc) if "retrying" in r["msg"]]
    assert len(retries) == 3 and {r["level"] for r in retries} == {"warning"}
    assert all("(fetch_failed)" in r["msg"] for r in retries)


def test_transient_error_keeps_the_last_good_value(tmp_path: Path) -> None:
    conf_dir, ssm, env = _setup(tmp_path)
    key = _good(ssm)
    assert _run(env).returncode == 0
    # Next boot: SSM unreachable for longer than the retries last.
    _flaky(ssm, PARAMS["WEBHOOK_SECRET_PARAMETER"], 99)
    proc = _run(env)
    assert proc.returncode == 0, _logs(proc)
    assert (conf_dir / "webhook_secret").read_text() == key
    assert stat.S_IMODE((conf_dir / "webhook_secret").stat().st_mode) == 0o600
    kept = [r for r in _logs(proc) if "kept the previous value" in r["msg"]]
    assert len(kept) == 1 and kept[0]["level"] == "error"
    assert PARAMS["WEBHOOK_SECRET_PARAMETER"] in kept[0]["msg"] and key not in proc.stderr


def test_transient_error_without_a_good_file_fails(tmp_path: Path) -> None:
    conf_dir, ssm, env = _setup(tmp_path)
    _good(ssm)
    _flaky(ssm, PARAMS["WEBHOOK_SECRET_PARAMETER"], 99)
    (conf_dir / "webhook_secret").write_text("")  # an empty leftover is not a good file
    proc = _run(env)
    assert proc.returncode == 1
    assert not (conf_dir / "webhook_secret").exists()


def test_absent_required_parameter_removes_the_last_value(tmp_path: Path) -> None:
    """Deleting a parameter is deliberate: the old value must not outlive it."""
    conf_dir, ssm, env = _setup(tmp_path)
    _good(ssm)
    assert _run(env).returncode == 0
    (ssm / PARAMS["WEBHOOK_SECRET_PARAMETER"].replace("/", "_")).unlink()
    proc = _run(env)
    assert proc.returncode == 1 and not (conf_dir / "webhook_secret").exists()
    assert not any("retrying" in r["msg"] for r in _logs(proc))


def test_optional_transient_error_keeps_previous_value(tmp_path: Path) -> None:
    conf_dir, ssm, env = _setup(tmp_path)
    _good(ssm)
    tunnel = secrets.token_urlsafe(24)
    _put(ssm, PARAMS["TUNNEL_SECRET_PARAMETER"], tunnel)
    assert _run(env).returncode == 0
    _flaky(ssm, PARAMS["TUNNEL_SECRET_PARAMETER"], 99)
    assert _run(env).returncode == 0
    assert (conf_dir / "tunnel_secret").read_text() == tunnel
