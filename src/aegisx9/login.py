"""Developer login: obtain a short-lived gateway token from the identity provider.

``aegisx9-login`` runs the OIDC authorization-code flow with PKCE (S256) against a public
client and a loopback redirect, then stores the access token for gateway calls. The auth
sidecar (ADR 0010) accepts that token for at most 15 minutes and exchanges it for a
virtual key that expires with it.

Security properties:

* The issuer, its discovered endpoints and the token endpoint must be ``https``; the
  discovery document's ``issuer`` must equal the configured issuer exactly.
* ``state`` is single-use and compared in constant time; the callback listens on the
  loopback interface only, serves one request, and gives up after ``--timeout`` seconds.
* The access token is written to a 0600 file by atomic replace and is never printed or
  logged; the only output about it is its remaining lifetime.
* Errors are reported by exception type name only.

Standard library only: the gateway package has no runtime dependencies of its own.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import math
import os
import secrets
import sys
import tempfile
import threading
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_PORT = 8250
DEFAULT_TIMEOUT_S = 300
# The identity provider emits the groups claim (which picks the gateway team) with profile.
DEFAULT_SCOPE = "openid profile"
HTTP_TIMEOUT_S = 15
MAX_RESPONSE_BYTES = 1 << 20
# Idle limit per callback connection; each runs in its own thread, so a slow or silent
# client never holds up the real redirect, and the overall wait is an absolute deadline.
CALLBACK_READ_TIMEOUT_S = 10

Fetch = Callable[[urllib.request.Request], Mapping[str, Any]]


class LoginError(Exception):
    """A login step failed; the message never contains a token or a URL with one."""


@dataclass(frozen=True)
class Endpoints:
    authorize: str
    token_url: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def pkce_pair() -> tuple[str, str]:
    """Returns (verifier, S256 challenge) as in RFC 7636."""
    verifier = secrets.token_urlsafe(64)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _require_https(url: str, what: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise LoginError(f"{what} must be an https URL")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses every redirect, so the https-only checks cover every hop."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise LoginError("redirects are not followed")


_OPENER = urllib.request.build_opener(_NoRedirect)


def _fetch_json(request: urllib.request.Request) -> Mapping[str, Any]:
    _require_https(request.full_url, "request URL")
    with _OPENER.open(request, timeout=HTTP_TIMEOUT_S) as response:  # nosemgrep
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise LoginError("response too large")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise LoginError("response is not a JSON object")
    return data


def discover(issuer: str, fetch: Fetch = _fetch_json) -> Endpoints:
    _require_https(issuer, "issuer")
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    doc = fetch(urllib.request.Request(url, headers={"Accept": "application/json"}))  # noqa: S310
    if doc.get("issuer") != issuer:
        raise LoginError("discovery issuer does not match the configured issuer")
    methods = doc.get("code_challenge_methods_supported")
    if isinstance(methods, list) and "S256" not in methods:
        raise LoginError("identity provider does not support PKCE S256")
    auth = _require_https(str(doc.get("authorization_endpoint", "")), "authorization endpoint")
    token = _require_https(str(doc.get("token_endpoint", "")), "token endpoint")
    return Endpoints(authorize=auth, token_url=token)


def authorization_url(
    endpoints: Endpoints, client_id: str, redirect_uri: str, scope: str, state: str, challenge: str
) -> str:
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    sep = "&" if urllib.parse.urlsplit(endpoints.authorize).query else "?"
    return endpoints.authorize + sep + query


class CallbackServer(http.server.ThreadingHTTPServer):
    """Loopback listener for the redirect; bound before the browser is opened."""

    daemon_threads = True

    def __init__(self, port: int, state: str) -> None:
        if not 1 <= port <= 65535:
            raise LoginError("port must be 1-65535")
        self.state = state
        self.result: dict[str, str] = {}
        self.done = threading.Event()
        self._lock = threading.Lock()
        super().__init__(("127.0.0.1", port), _CallbackHandler)

    def finish_with(self, key: str, value: str) -> bool:
        """Records the first outcome; later ones (and any after the deadline) are dropped."""
        with self._lock:
            if self.done.is_set():
                return False
            self.result[key] = value
            self.done.set()
            return True


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    timeout = CALLBACK_READ_TIMEOUT_S
    server: CallbackServer

    def log_message(self, format: str, *args: Any) -> None:  # the query holds the code
        return

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        got_state = params.get("state", [""])[0]
        if not hmac.compare_digest(got_state.encode(), self.server.state.encode()):
            # Not our redirect (a favicon, a preconnect, another local process): ignore it
            # and keep waiting, so a stray request cannot abort the login.
            self._reply(404, b"Not found.")
            return
        code = params.get("code", [""])[0]
        if "error" in params:
            self.server.finish_with("error", "identity provider returned an error")
            ok = False
        elif not code:
            self.server.finish_with("error", "no authorization code")
            ok = False
        else:
            ok = self.server.finish_with("code", code)
        self._reply(
            200 if ok else 400,
            b"Login complete. You can close this tab." if ok else b"Login failed.",
        )


def wait_for_code(server: CallbackServer, timeout_s: float) -> str:
    """Serves loopback requests until the redirect with our state arrives; returns the code."""
    loop = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
    loop.daemon = True
    loop.start()
    try:
        arrived = server.done.wait(timeout_s)
        # Close the door: a callback that completes after this point is dropped.
        timed_out = server.finish_with("error", "timed out waiting for the browser")
    finally:
        server.shutdown()
        server.server_close()
    if timed_out or not arrived:
        raise LoginError("timed out waiting for the browser")
    if "code" not in server.result:
        raise LoginError(server.result["error"])
    return server.result["code"]


def exchange_code(
    endpoints: Endpoints,
    client_id: str,
    redirect_uri: str,
    code: str,
    verifier: str,
    fetch: Fetch = _fetch_json,
) -> tuple[str, int]:
    """Returns (access token, lifetime in seconds)."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": verifier,
        }
    ).encode("ascii")
    request = urllib.request.Request(  # noqa: S310 - https enforced in discover()
        endpoints.token_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    data = fetch(request)
    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        raise LoginError("token response has no access token")
    if str(data.get("token_type", "")).lower() != "bearer":
        raise LoginError("token response is not a bearer token")
    return token, _lifetime(data.get("expires_in"))


def _lifetime(value: Any) -> int:
    """``expires_in`` as whole seconds; 0 when absent or not a sane number."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, str) and value.isdigit():
        value = int(value)
    if isinstance(value, int | float) and math.isfinite(value) and value > 0:
        return int(value)
    return 0


def write_token(path: Path, token: str) -> None:
    """Writes the token with mode 0600 by atomic replace."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_uid == os.getuid():
        path.parent.chmod(0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".token-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(token)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def default_token_file(env: Mapping[str, str]) -> Path:
    base = env.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "aegisx9" / "token"


def _parser(env: Mapping[str, str]) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegisx9-login", description="Get a short-lived AegisX9 gateway token."
    )
    p.add_argument("--issuer", default=env.get("AEGISX9_OIDC_ISSUER", ""))
    p.add_argument("--client-id", default=env.get("AEGISX9_OIDC_CLIENT_ID", ""))
    p.add_argument("--scope", default=env.get("AEGISX9_OIDC_SCOPE", DEFAULT_SCOPE))
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    p.add_argument("--token-file", type=Path, default=default_token_file(env))
    p.add_argument("--no-browser", action="store_true", help="print the URL only")
    return p


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    env = os.environ if env is None else env
    args = _parser(env).parse_args(argv)
    if not args.issuer or not args.client_id:
        print("aegisx9-login: --issuer and --client-id are required", file=sys.stderr)
        return 2
    try:
        endpoints = discover(args.issuer)
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(32)
        server = CallbackServer(args.port, state)  # bound before the browser opens
        redirect_uri = f"http://127.0.0.1:{server.server_address[1]}"
        url = authorization_url(
            endpoints, args.client_id, redirect_uri, args.scope, state, challenge
        )
        print("Open this URL to sign in:\n" + url, file=sys.stderr)
        if not args.no_browser:
            webbrowser.open(url)
        code = wait_for_code(server, args.timeout)
        token, lifetime = exchange_code(endpoints, args.client_id, redirect_uri, code, verifier)
        write_token(args.token_file, token)
    except Exception as e:  # report the type only, never the message
        print(f"aegisx9-login: failed ({type(e).__name__})", file=sys.stderr)
        return 1
    print(f"Token saved to {args.token_file} (valid {lifetime} s).", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
