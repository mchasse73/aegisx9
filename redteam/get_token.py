"""Get a short-lived gateway token for the red-team job from the identity provider.

The job authenticates as a machine identity (ADR 0018), never with a stored gateway key:

* **Federated (preferred):** the job's own GitHub Actions OIDC token (``id-token: write``)
  is sent as a ``client_assertion`` in a ``client_credentials`` request, so nothing is
  stored anywhere. GitHub's issuer is shared by every repository and the caller picks the
  audience, so the identity provider itself must accept the assertion only when its
  ``repository``, ``ref``, ``environment`` and ``job_workflow_ref`` claims name this
  repository, ``main``, the ``redteam`` environment and this workflow. That binding is
  part of the identity provider's configuration, and is proven by a negative test (#147).
* **Client secret (fallback):** used only when ``AEGIS_RT_CLIENT_SECRET`` is set.

The access token must be a bearer token that lives at most 900 s (the auth sidecar
refuses anything longer) and at least ``MIN_LIFETIME_S``, so it outlives the suite step
that uses it (each is capped at 12 minutes in the workflow). It is registered with
``::add-mask::`` before anything else and handed to later steps through ``$GITHUB_ENV``;
it is never printed. Errors are reported by type or by a fixed message, never with a
response body.

Inputs (environment): ``AEGIS_RT_TOKEN_URL``, ``AEGIS_RT_CLIENT_ID``,
``AEGIS_RT_ASSERTION_AUDIENCE`` (federated), ``AEGIS_RT_CLIENT_SECRET`` (fallback),
``AEGIS_RT_SCOPE`` (default ``openid profile``), and GitHub's
``ACTIONS_ID_TOKEN_REQUEST_URL`` / ``ACTIONS_ID_TOKEN_REQUEST_TOKEN``.
"""

from __future__ import annotations

import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

MAX_LIFETIME_S = 900
# Suite steps are capped at 12 minutes; a token must outlive one with a minute to spare.
MIN_LIFETIME_S = 780
OUTPUT_VAR = "AEGIS_REDTEAM_KEY"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
MAX_RESPONSE_BYTES = 1 << 20

Fetch = Callable[[urllib.request.Request], Mapping[str, Any]]


class TokenError(Exception):
    """A step failed; the message is fixed text, never a token or a response body."""


def _fetch_json(request: urllib.request.Request) -> Mapping[str, Any]:
    if urllib.parse.urlsplit(request.full_url).scheme != "https":
        raise TokenError("only https endpoints are allowed")
    try:
        with urllib.request.urlopen(request, timeout=20) as resp:  # noqa: S310 - https only
            body = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise TokenError(f"endpoint answered {e.code}") from None
    if len(body) > MAX_RESPONSE_BYTES:
        raise TokenError("response too large")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise TokenError("response is not a JSON object")
    return data


def github_oidc_token(env: Mapping[str, str], audience: str, fetch: Fetch) -> str:
    url, bearer = env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise TokenError("no GitHub OIDC token available (does the job have id-token: write?)")
    sep = "&" if urllib.parse.urlsplit(url).query else "?"
    req = urllib.request.Request(  # noqa: S310 - https enforced in _fetch_json
        url + sep + urllib.parse.urlencode({"audience": audience}),
        headers={"Authorization": "Bearer " + bearer, "Accept": "application/json"},
    )
    value = fetch(req).get("value")
    if not isinstance(value, str) or not value:
        raise TokenError("GitHub OIDC answer has no token")
    return value


def _lifetime(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, int | float) and math.isfinite(value) and value > 0:
        return int(value)
    return 0


def request_token(env: Mapping[str, str], fetch: Fetch = _fetch_json) -> tuple[str, int]:
    """Returns (access token, lifetime in seconds)."""
    token_url, client_id = env.get("AEGIS_RT_TOKEN_URL", ""), env.get("AEGIS_RT_CLIENT_ID", "")
    if not token_url or not client_id:
        raise TokenError(
            "no red-team credential configured (AEGIS_RT_TOKEN_URL / AEGIS_RT_CLIENT_ID)"
        )
    form = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "scope": env.get("AEGIS_RT_SCOPE") or "openid profile",
    }
    secret = env.get("AEGIS_RT_CLIENT_SECRET", "")
    if secret:
        form["client_secret"] = secret
    else:
        audience = env.get("AEGIS_RT_ASSERTION_AUDIENCE", "")
        if not audience:
            raise TokenError("set AEGIS_RT_ASSERTION_AUDIENCE (federated) or a client secret")
        form["client_assertion_type"] = ASSERTION_TYPE
        form["client_assertion"] = github_oidc_token(env, audience, fetch)
    req = urllib.request.Request(  # noqa: S310 - https enforced in _fetch_json
        token_url,
        data=urllib.parse.urlencode(form).encode("ascii"),
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    data = fetch(req)
    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        raise TokenError("token response has no access token")
    if str(data.get("token_type", "")).lower() != "bearer":
        raise TokenError("token response is not a bearer token")
    lifetime = _lifetime(data.get("expires_in"))
    if not MIN_LIFETIME_S <= lifetime <= MAX_LIFETIME_S:
        raise TokenError(f"token lifetime must be {MIN_LIFETIME_S}-{MAX_LIFETIME_S} s")
    return token, lifetime


def hand_over(token: str, github_env: Path, out: Callable[[str], None] = print) -> None:
    """Masks the token in the job log, then exports it to later steps."""
    if "\n" in token or "\r" in token:
        raise TokenError("token contains a line break")
    out("::add-mask::" + token)
    with github_env.open("a", encoding="utf-8") as fh:
        fh.write(f"{OUTPUT_VAR}={token}\n")


def main(env: Mapping[str, str] | None = None, fetch: Fetch = _fetch_json) -> int:
    env = os.environ if env is None else env
    try:
        target = env.get("GITHUB_ENV")
        if not target:
            raise TokenError("GITHUB_ENV is not set")
        token, lifetime = request_token(env, fetch)
        hand_over(token, Path(target))
    except TokenError as e:
        print(f"get_token: {e}", file=sys.stderr)
        return 1
    except Exception as e:  # report the type only, never the message
        print(f"get_token: failed ({type(e).__name__})", file=sys.stderr)
        return 1
    print(f"get_token: gateway token ready (valid {lifetime} s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
