#!/usr/bin/env python3
"""Boot smoke for short-lived JWT authentication (ADR 0010) against a running proxy.

  auth_smoke.py prepare --dir D --jwks-port P   # throwaway signing key + auth.json in D
  auth_smoke.py check --dir D --jwks-port P --base-url URL [--team developers]

``prepare`` generates an RSA key at runtime (nothing credential-shaped is committed) and
writes ``auth.json`` naming a loopback JWKS. ``check`` serves that JWKS, makes sure the team
exists (admin key from ``LITELLM_MASTER_KEY``), then requires: a valid 5-minute token is
accepted; tokens over the lifetime ceiling, expired, for another audience or signed by an
unpublished key get a generic 401; a token can't reach a management route (403); the
admin key still works and a random key does not.
Prints only check names and status codes.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://idp.ci.invalid/"
AUDIENCE = "aegisx9"
GROUP = "ci-developers"
KID = "ci-1"
LEAK_WORDS = ("enterprise", "licen", "premium", "traceback")


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def prepare(directory: Path, jwks_port: int, team: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "signing-key.pem"
    pem = _new_key().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path.touch(mode=0o600)
    key_path.write_bytes(pem)
    config = {
        "issuers": [
            {
                "name": "ci",
                "issuer": ISSUER,
                "jwksUrl": f"http://127.0.0.1:{jwks_port}/jwks",
                "audience": AUDIENCE,
                "groupTeams": [{"group": GROUP, "team": team}],
            }
        ]
    }
    (directory / "auth.json").write_text(json.dumps(config), encoding="utf-8")


def _load_key(directory: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key((directory / "signing-key.pem").read_bytes(), None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("signing key is not RSA")
    return key


def _serve_jwks(key: rsa.RSAPrivateKey, port: int) -> ThreadingHTTPServer:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    body = json.dumps({"keys": [jwk | {"kid": KID, "use": "sig", "alg": "RS256"}]}).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200 if self.path == "/jwks" else 404)
            self.send_header("content-type", "application/json")
            self.end_headers()
            if self.path == "/jwks":
                self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _token(key: rsa.RSAPrivateKey, **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "ci-user",
        "groups": [GROUP],
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": KID})


def _call(base: str, path: str, bearer: str, body: dict[str, Any] | None = None) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(  # noqa: S310 - loopback URL from the CI step
        base + path,
        data=data,
        method="POST" if data else "GET",
        headers={"authorization": f"Bearer {bearer}", "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def check(directory: Path, jwks_port: int, base: str, team: str) -> int:
    master = os.environ.get("LITELLM_MASTER_KEY", "")
    if not master:
        print("LITELLM_MASTER_KEY is required")
        return 2
    key = _load_key(directory)
    server = _serve_jwks(key, jwks_port)
    failures = 0

    def expect(name: str, got: tuple[int, str], want: int) -> None:
        nonlocal failures
        status, text = got
        leak = want in (401, 403) and any(w in text.lower() for w in LEAK_WORDS)
        ok = status == want and not leak
        note = " (body leaks details)" if leak else ""
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {status}{note}")
        failures += 0 if ok else 1

    try:
        status, _ = _call(base, "/team/info?team_id=" + team, master)
        if status != 200:
            expect("create team", _call(base, "/team/new", master, {"team_id": team}), 200)
        now = int(time.time())
        expect("valid 5-minute token", _call(base, "/v1/models", _token(key)), 200)
        expect(
            "token over the 15-minute ceiling",
            _call(base, "/v1/models", _token(key, exp=now + 3600)),
            401,
        )
        expect(
            "expired token",
            _call(base, "/v1/models", _token(key, iat=now - 600, exp=now - 120)),
            401,
        )
        expect("other audience", _call(base, "/v1/models", _token(key, aud="other")), 401)
        expect("unpublished key", _call(base, "/v1/models", _token(_new_key())), 401)
        expect("unmapped group", _call(base, "/v1/models", _token(key, groups=["x"])), 401)
        expect(
            "token on a management route",
            _call(base, "/key/generate", _token(key), {"duration": "30d"}),
            403,
        )
        expect("admin key passes through", _call(base, "/v1/models", master), 200)
        expect("random key", _call(base, "/v1/models", "sk-" + os.urandom(16).hex()), 401)
    finally:
        server.shutdown()
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=["prepare", "check"])
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--jwks-port", type=int, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:4000")
    parser.add_argument("--team", default="developers")
    args = parser.parse_args(argv)
    if args.action == "prepare":
        prepare(args.dir, args.jwks_port, args.team)
        return 0
    return check(args.dir, args.jwks_port, args.base_url.rstrip("/"), args.team)


if __name__ == "__main__":
    sys.exit(main())
