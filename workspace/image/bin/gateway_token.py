#!/usr/bin/env python3
"""AegisX9 ``apiKeyHelper``: print a short-lived gateway token and nothing else.

Installed as ``/opt/aegisx9/bin/gateway-token`` in the workspace image and named by the
managed ``apiKeyHelper`` setting. Claude Code runs it whenever it needs a credential, so
no static API key exists anywhere on a workspace.

Flow
----
1. A cached gateway token (``$HOME/.aegisx9/gateway-token.json``, 0600) that is still
   valid for more than a minute is printed as is.
2. Otherwise a Vault token is needed. The cached one (``$HOME/.aegisx9/vault-token``,
   0600) is used when ``vault token lookup`` succeeds and its TTL is above five minutes;
   if not, ``vault login -method=oidc`` runs for role ``aegisx9-developer``. Vault prints
   the browser hand-off URL on **stderr** (the IDE opens it); the new token is cached.
3. ``vault read identity/oidc/token/aegisx9-gateway`` issues a signed JWT bound to the
   developer's identity. The gateway validates it against Vault's JWKS. It is cached with
   its expiry and printed on stdout.

Secrets only ever travel through environment variables (``VAULT_TOKEN``), stdin and 0600
files, never on a command line. Errors are reported by exception type name only.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

VAULT_ROLE = "aegisx9-developer"
IDENTITY_OIDC_PATH = "identity/oidc/token/aegisx9-gateway"
MIN_VAULT_TTL_SECONDS = 300
GATEWAY_TOKEN_SKEW_SECONDS = 60
LOGIN_TIMEOUT_SECONDS = 300
CALL_TIMEOUT_SECONDS = 30
DROPPED_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")


class GatewayTokenError(RuntimeError):
    """The helper could not obtain a token."""


class VaultUnavailableError(GatewayTokenError):
    """The ``vault`` binary is not on PATH."""


class VaultResponseError(GatewayTokenError):
    """Vault returned something the helper does not understand."""


def state_dir() -> Path:
    """Where the helper keeps its 0600 cache files."""
    override = os.environ.get("AEGISX9_STATE_DIR")
    base = Path(override) if override else Path.home() / ".aegisx9"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    return base


def read_private(path: Path) -> str | None:
    """Read a cache file only if it is a regular file readable by its owner alone."""
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(mode) or mode & 0o077:
        return None
    return path.read_text(encoding="utf-8").strip()


def write_private(path: Path, content: str) -> None:
    """Create or replace a file with 0600 permissions, never widening them."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _vault_env(token: str | None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in DROPPED_ENV}
    env.pop("VAULT_TOKEN", None)
    if token:
        env["VAULT_TOKEN"] = token
    return env


def run_vault(
    args: list[str], token: str | None = None, *, show_stderr: bool = False, timeout: int
) -> str:
    """Run the vault CLI; return stdout. Vault's stderr is hidden unless asked for."""
    binary = shutil.which("vault")
    if binary is None:
        raise VaultUnavailableError
    proc = subprocess.run(  # noqa: S603 - fixed binary, fixed argument list, no shell
        [binary, *args],
        env=_vault_env(token),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=None if show_stderr else subprocess.DEVNULL,
        timeout=timeout,
        check=True,
    )
    return proc.stdout.decode("utf-8", errors="replace")


def parse_json_output(raw: str) -> dict[str, Any]:
    """Return the JSON object in ``raw``, ignoring any text printed before it."""
    start = raw.find("{")
    if start < 0:
        raise VaultResponseError
    data = json.loads(raw[start:])
    if not isinstance(data, dict):
        raise VaultResponseError
    return data


def vault_token_ttl(token: str) -> int:
    """Remaining TTL of a Vault token in seconds; -1 when it is not usable."""
    try:
        raw = run_vault(["token", "lookup", "-format=json"], token, timeout=CALL_TIMEOUT_SECONDS)
        ttl = parse_json_output(raw)["data"]["ttl"]
    except (subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return -1
    return int(ttl)


def oidc_login() -> str:
    """Interactive OIDC login; the hand-off URL goes to stderr, the token comes back."""
    raw = run_vault(
        [
            "login",
            "-method=oidc",
            "-no-store",
            "-format=json",
            f"role={VAULT_ROLE}",
            "skip_browser=true",
        ],
        show_stderr=True,
        timeout=LOGIN_TIMEOUT_SECONDS,
    )
    token = parse_json_output(raw).get("auth", {}).get("client_token")
    if not isinstance(token, str) or not token:
        raise VaultResponseError
    return token


def vault_token() -> str:
    """A Vault token with more than five minutes left, from cache or a fresh login."""
    path = state_dir() / "vault-token"
    cached = read_private(path)
    if cached and vault_token_ttl(cached) > MIN_VAULT_TTL_SECONDS:
        return cached
    token = oidc_login()
    write_private(path, token + "\n")
    return token


def cached_gateway_token(now: float) -> str | None:
    raw = read_private(state_dir() / "gateway-token.json")
    if not raw:
        return None
    try:
        data = json.loads(raw)
        token = data["token"]
        expires_at = float(data["expires_at"])
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(token, str) or expires_at - now <= GATEWAY_TOKEN_SKEW_SECONDS:
        return None
    return token


def issue_gateway_token(token: str, now: float) -> str:
    """Ask Vault's identity OIDC provider for a gateway JWT and cache it with its expiry."""
    raw = run_vault(
        ["read", "-format=json", IDENTITY_OIDC_PATH], token, timeout=CALL_TIMEOUT_SECONDS
    )
    data = parse_json_output(raw).get("data", {})
    jwt, ttl = data.get("token"), data.get("ttl")
    if not isinstance(jwt, str) or not jwt or not isinstance(ttl, int | float):
        raise VaultResponseError
    record = json.dumps({"token": jwt, "expires_at": now + float(ttl)})
    write_private(state_dir() / "gateway-token.json", record + "\n")
    return jwt


def gateway_token(now: float | None = None) -> str:
    now = time.time() if now is None else now
    cached = cached_gateway_token(now)
    if cached:
        return cached
    return issue_gateway_token(vault_token(), now)


def main() -> int:
    try:
        token = gateway_token()
    except Exception as e:
        print(f"gateway-token: {type(e).__name__}", file=sys.stderr)
        return 1
    sys.stdout.write(token + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
