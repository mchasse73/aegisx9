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

import base64
import json
import math
import os
import re
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
# RFC 6749 section 5.2 error codes are short lowercase words; anything else (a description, a
# body that echoes input) is never printed.
OAUTH_ERROR_RE = re.compile(r"^[a-z_]{1,40}$")

Fetch = Callable[[urllib.request.Request], Mapping[str, Any]]


class TokenError(Exception):
    """A step failed; the message is fixed text, never a token or a response body."""


def oauth_error_code(body: bytes) -> str | None:
    """The ``error`` code of an OAuth error answer, only if it has the standard shape."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    code = data.get("error") if isinstance(data, dict) else None
    return code if isinstance(code, str) and OAUTH_ERROR_RE.match(code) else None


def describe_assertion(assertion: str, env: Mapping[str, str]) -> str:
    """The shape of the assertion's ``sub``, for triage when the identity provider refuses it.

    Prints only key names and whether each value equals the expected one (repository, ref,
    ``AEGIS_RT_EXPECTED_ENVIRONMENT``), never a value. The payload is decoded without
    verifying the signature: it is read for diagnosis only, never trusted.
    """
    try:
        payload = assertion.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        parts = str(claims.get("sub", "")).split(":")
    except (IndexError, ValueError, AttributeError):
        return "assertion is not a readable JWT"
    expected = {
        "repo": env.get("GITHUB_REPOSITORY", ""),
        "environment": env.get("AEGIS_RT_EXPECTED_ENVIRONMENT", "redteam"),
        "ref": env.get("GITHUB_REF", ""),
    }
    shape = []
    for i in range(0, len(parts) - 1, 2):
        key, value = parts[i], parts[i + 1]
        want = expected.get(key)
        mark = "?" if not want else ("=" if value == want else "!=")
        shape.append(f"{key}{mark}")
    if len(parts) % 2:
        shape.append("<odd>")
    return "assertion sub shape " + ":".join(shape) + " (= expected, != differs, ? unchecked)"


def _fetch_json(request: urllib.request.Request) -> Mapping[str, Any]:
    if urllib.parse.urlsplit(request.full_url).scheme != "https":
        raise TokenError("only https endpoints are allowed")
    try:
        with urllib.request.urlopen(request, timeout=20) as resp:  # noqa: S310 - https only
            body = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as e:
        try:
            code = oauth_error_code(e.read(4096))
        except OSError:
            code = None
        suffix = f" ({code})" if code else ""
        raise TokenError(f"endpoint answered {e.code}{suffix}") from None
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
    try:
        value = fetch(req).get("value")
    except TokenError as e:
        raise TokenError(f"GitHub OIDC token: {e}") from None
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
    try:
        data = fetch(req)
    except TokenError as e:
        detail = ""
        if "client_assertion" in form:
            detail = "; " + describe_assertion(form["client_assertion"], env)
        raise TokenError(f"identity provider token request: {e}{detail}") from None
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
