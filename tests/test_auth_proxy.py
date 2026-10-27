"""Tests for the JWT auth sidecar. Signing keys, master and virtual keys are generated per run."""

from __future__ import annotations

import http.client
import json
import logging
import secrets
import signal
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from aegisx9 import auth_proxy as ap
from aegisx9.auth import IssuerConfig, Principal, Verifier
from aegisx9.wif_broker import JsonFormatter

ISS = "https://idp.example.test/app/"
AUD = "aegisx9"
ADMIN_PATHS = {ap.TEAM_MEMBER_ADD_PATH, ap.KEY_GENERATE_PATH}


# -- identity provider --------------------------------------------------------------------


class Keys:
    def __init__(self) -> None:
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def fetch(self, url: str, timeout: float, ca_file: str | None) -> bytes:
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.rsa.public_key()))
        return json.dumps({"keys": [public | {"kid": "r1", "use": "sig"}]}).encode()

    def token(self, sub: str = "alice", lifetime: int = 600, **kw: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": ISS,
            "aud": AUD,
            "sub": sub,
            "groups": ["dev"],
            "iat": now,
            "exp": now + lifetime,
            "jti": secrets.token_hex(8),
        } | kw
        return jwt.encode(claims, self.rsa, algorithm="RS256", headers={"kid": "r1"})


ISSUER_MAPPING: dict[str, Any] = {
    "name": "idp",
    "issuer": ISS,
    "jwksUrl": "https://idp.example.test/jwks",
    "audience": AUD,
    "groupTeams": [{"group": "dev", "team": "developers"}],
}


@pytest.fixture(scope="module")
def keys() -> Keys:
    return Keys()


def make_verifier(keys: Keys) -> Verifier:
    return Verifier([IssuerConfig.from_mapping(ISSUER_MAPPING, {})], fetch=keys.fetch)


# -- fake LiteLLM ---------------------------------------------------------------------------


@dataclass
class FakeLiteLLM:
    port: int = 0
    requests: list[dict[str, Any]] = field(default_factory=list)
    minted: list[str] = field(default_factory=list)
    enrol_status: int = 200
    enrol_body: dict[str, Any] = field(default_factory=lambda: {"team_id": "developers"})
    mint_status: int = 200
    mint_body: dict[str, Any] | None = None
    mint_delay: float = 0.0
    stream_gate: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def calls(self, path: str) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["path"] == path]

    def caller_requests(self) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["path"] not in ADMIN_PATHS]


def _fake_handler(fake: FakeLiteLLM) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _send(self, status: int, payload: Any, extra: dict[str, str] | None = None) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _any(self) -> None:
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length) if length else b""
            record = {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "raw_headers": [(k.lower(), v) for k, v in self.headers.items()],
                "body": body,
            }
            with fake.lock:
                fake.requests.append(record)
            if self.path == ap.TEAM_MEMBER_ADD_PATH:
                self._send(fake.enrol_status, fake.enrol_body)
            elif self.path == ap.KEY_GENERATE_PATH:
                time.sleep(fake.mint_delay)
                if fake.mint_body is not None:
                    self._send(fake.mint_status, fake.mint_body)
                    return
                key = secrets.token_urlsafe(24)
                with fake.lock:
                    fake.minted.append(key)
                self._send(fake.mint_status, {"key": key})
            elif self.path == "/stream":
                # Close-delimited SSE: the second event waits until the test saw the first.
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("connection", "close")
                self.end_headers()
                self.wfile.write(b"data: one\n\n")
                self.wfile.flush()
                fake.stream_gate.wait(5)
                self.wfile.write(b"data: two\n\n")
                self.wfile.flush()
                self.close_connection = True
            elif self.path == "/chunked":
                self.send_response(200)
                self.send_header("transfer-encoding", "chunked")
                self.end_headers()
                for part in (b"ab", b"cd"):
                    self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            elif self.path == "/broken":
                # A chunked body cut off mid-chunk.
                self.send_response(200)
                self.send_header("transfer-encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"10\r\nabc")
                self.wfile.flush()
                self.close_connection = True
            else:
                self._send(
                    200,
                    {"ok": True},
                    {"x-upstream": "yes", "connection": "x-internal", "x-internal": "1"},
                )

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _any

    return Handler


@pytest.fixture
def fake() -> Iterator[FakeLiteLLM]:
    f = FakeLiteLLM()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _fake_handler(f))
    server.daemon_threads = True
    f.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f
    f.stream_gate.set()
    server.shutdown()
    server.server_close()


# -- the sidecar ----------------------------------------------------------------------------


@dataclass
class Clock:
    offset: float = 0.0

    def __call__(self) -> float:
        return time.time() + self.offset


@dataclass
class Proxy:
    port: int
    master_key: str
    clock: Clock
    exchanger: ap.KeyExchanger | None

    def conn(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)

    def request(
        self,
        method: str = "POST",
        path: str = "/v1/chat/completions",
        body: bytes | None = b"{}",
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes, http.client.HTTPResponse]:
        c = self.conn()
        c.request(method, path, body=body, headers=headers or {})
        resp = c.getresponse()
        data = resp.read()
        c.close()
        return resp.status, data, resp


def _start(
    upstream_port: int, verifier: Any, jwt_enabled: bool = True, **kw: Any
) -> tuple[Proxy, Callable[[], None]]:
    master_key = secrets.token_urlsafe(24)
    cfg = ap.ProxyConfig(
        upstream_port=upstream_port,
        listen_host="127.0.0.1",
        listen_port=0,
        master_key=master_key,
        **kw,
    )
    clock = Clock()
    exchanger = ap.KeyExchanger(ap.admin_client(cfg), now=clock) if jwt_enabled else None
    server = ap.build_server(cfg, verifier if jwt_enabled else None, exchanger)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def stop() -> None:
        server.shutdown()
        server.server_close()

    return Proxy(server.server_address[1], master_key, clock, exchanger), stop


@pytest.fixture
def proxy(fake: FakeLiteLLM, keys: Keys) -> Iterator[Proxy]:
    p, stop = _start(fake.port, make_verifier(keys))
    yield p
    stop()


def _bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def _assert_master_key_only_on_admin_calls(fake: FakeLiteLLM, proxy: Proxy) -> None:
    for r in fake.requests:
        sent = json.dumps(r["raw_headers"])
        if r["path"] in ADMIN_PATHS:
            assert r["headers"]["authorization"] == f"Bearer {proxy.master_key}"
        else:
            assert proxy.master_key not in sent


# -- passthrough ----------------------------------------------------------------------------


@pytest.mark.parametrize("header", ["authorization", "x-api-key", "x-litellm-api-key"])
def test_non_jwt_credentials_forwarded_unchanged(
    proxy: Proxy, fake: FakeLiteLLM, header: str
) -> None:
    key = secrets.token_urlsafe(24)
    value = f"Bearer {key}" if header == "authorization" else key
    status, body, _ = proxy.request(
        path="/v1/chat/completions?x=1",
        body=b'{"model":"m"}',
        headers={header: value, "content-type": "application/json", "x-custom": "kept"},
    )
    assert status == 200 and json.loads(body) == {"ok": True}
    req = fake.requests[-1]
    assert req["path"] == "/v1/chat/completions?x=1"
    assert req["headers"][header] == value
    assert req["headers"]["x-custom"] == "kept"
    assert req["body"] == b'{"model":"m"}'
    assert not fake.calls(ap.KEY_GENERATE_PATH)
    _assert_master_key_only_on_admin_calls(fake, proxy)


def test_no_credential_is_proxied(proxy: Proxy, fake: FakeLiteLLM) -> None:
    status, _, resp = proxy.request(method="GET", path="/health/liveliness", body=None)
    assert status == 200
    assert resp.getheader("x-upstream") == "yes"
    assert "authorization" not in fake.requests[-1]["headers"]


def test_hop_by_hop_and_listed_headers_dropped(proxy: Proxy, fake: FakeLiteLLM) -> None:
    status, _, resp = proxy.request(
        headers={
            "Connection": "keep-alive, x-hop",
            "x-hop": "1",
            "keep-alive": "timeout=5",
            "te": "trailers",
            "proxy-authorization": "Basic <placeholder>",
            "x-end": "1",
        }
    )
    assert status == 200
    sent = fake.requests[-1]["headers"]
    for name in ("connection", "x-hop", "keep-alive", "te", "proxy-authorization"):
        assert name not in sent
    assert sent["x-end"] == "1"
    # Response headers listed in the upstream's Connection header are dropped too.
    assert resp.getheader("x-internal") is None
    assert resp.getheader("x-upstream") == "yes"


def test_repeated_headers_forwarded_as_sent(proxy: Proxy, fake: FakeLiteLLM) -> None:
    c = proxy.conn()
    c.putrequest("GET", "/v1/models", skip_host=True)
    c.putheader("x-multi", "a")
    c.putheader("x-multi", "b")
    c.endheaders()
    resp = c.getresponse()
    resp.read()
    assert resp.status == 200
    raw = fake.requests[-1]["raw_headers"]
    assert [v for k, v in raw if k == "x-multi"] == ["a", "b"]
    # No Host from the client: the upstream's is supplied.
    assert ("host", f"127.0.0.1:{fake.port}") in raw


def test_x_forwarded_for_overwritten(proxy: Proxy, fake: FakeLiteLLM) -> None:
    proxy.request(
        headers={"X-Forwarded-For": "203.0.113.9", "Forwarded": "for=203.0.113.9", "x-real-ip": "x"}
    )
    raw = fake.requests[-1]["raw_headers"]
    assert [v for k, v in raw if k == "x-forwarded-for"] == ["127.0.0.1"]
    assert not [k for k, _ in raw if k in ("forwarded", "x-real-ip")]


def test_x_forwarded_for_kept_from_trusted_proxy(fake: FakeLiteLLM, keys: Keys) -> None:
    nets = ap.ProxyConfig.from_env({"AEGISX9_AUTH_TRUSTED_PROXIES": "192.0.2.0/24, 127.0.0.0/8"})
    p, stop = _start(fake.port, make_verifier(keys), trusted_proxies=nets.trusted_proxies)
    try:
        p.request(headers={"X-Forwarded-For": "203.0.113.9"})
        raw = fake.requests[-1]["raw_headers"]
        assert [v for k, v in raw if k == "x-forwarded-for"] == ["203.0.113.9, 127.0.0.1"]
        p.request()  # nothing to keep: the peer alone
        raw = fake.requests[-1]["raw_headers"]
        assert [v for k, v in raw if k == "x-forwarded-for"] == ["127.0.0.1"]
    finally:
        stop()


def test_trusted_check_ignores_non_ip_peer() -> None:
    assert not ap._trusted("not-an-ip", (ap.ipaddress.ip_network("0.0.0.0/0"),))


# -- JWT exchange ---------------------------------------------------------------------------


@pytest.mark.parametrize("header", ["authorization", "x-api-key", "x-litellm-api-key"])
def test_jwt_exchanged_and_all_credentials_replaced(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys, header: str
) -> None:
    token = keys.token()
    other = secrets.token_urlsafe(16)
    headers = {
        "x-goog-api-key": other,
        "api-key": other,
        "x-api-key": other,
        "x-litellm-api-key": other,
    }
    headers[header] = f"Bearer {token}" if header == "authorization" else token
    status, _, _ = proxy.request(headers=headers)
    assert status == 200
    [enrol] = fake.calls(ap.TEAM_MEMBER_ADD_PATH)
    assert json.loads(enrol["body"]) == {
        "team_id": "developers",
        "member": {"user_id": "idp:alice", "role": "user"},
    }
    [mint] = fake.calls(ap.KEY_GENERATE_PATH)
    minted = json.loads(mint["body"])
    assert minted["user_id"] == "idp:alice" and minted["team_id"] == "developers"
    assert minted["metadata"] == {"aegisx9_auth": "jwt", "aegisx9_issuer": "idp"}
    [req] = fake.caller_requests()
    raw = req["raw_headers"]
    assert [v for k, v in raw if k == "authorization"] == [f"Bearer {fake.minted[0]}"]
    for name in ("x-api-key", "x-litellm-api-key", "api-key", "x-goog-api-key"):
        assert name not in req["headers"]
    blob = json.dumps(raw)
    assert token not in blob and other not in blob
    _assert_master_key_only_on_admin_calls(fake, proxy)


def test_duration_is_remaining_lifetime(proxy: Proxy, fake: FakeLiteLLM, keys: Keys) -> None:
    token = keys.token(lifetime=300)
    proxy.clock.offset = 100.0
    assert proxy.request(headers=_bearer(token))[0] == 200
    seconds = int(json.loads(fake.calls(ap.KEY_GENERATE_PATH)[0]["body"])["duration"][:-1])
    assert 195 <= seconds <= 200


def test_key_never_outlives_ceiling(proxy: Proxy, fake: FakeLiteLLM, keys: Keys) -> None:
    # iat 30 s in the future (allowed clock skew) and a full 15-minute lifetime.
    now = int(time.time())
    token = keys.token(iat=now + 30, exp=now + 930)
    assert proxy.request(headers=_bearer(token))[0] == 200
    seconds = int(json.loads(fake.calls(ap.KEY_GENERATE_PATH)[0]["body"])["duration"][:-1])
    assert seconds <= 900


def test_key_reused_until_expiry_then_new(proxy: Proxy, fake: FakeLiteLLM, keys: Keys) -> None:
    token = keys.token(lifetime=300)
    for _ in range(3):
        assert proxy.request(headers=_bearer(token))[0] == 200
    assert len(fake.calls(ap.KEY_GENERATE_PATH)) == 1
    assert len(fake.calls(ap.TEAM_MEMBER_ADD_PATH)) == 1
    callers = fake.caller_requests()
    assert all(c["headers"]["authorization"] == f"Bearer {fake.minted[0]}" for c in callers)
    # Past the token's exp as the exchanger sees it (the verifier still accepts it within
    # its clock-skew leeway): refused, nothing minted, nothing forwarded.
    proxy.clock.offset = 300.0 - ap.MIN_KEY_LIFETIME_S - ap.KEY_EXPIRY_MARGIN_S + 0.5
    status, body, _ = proxy.request(headers=_bearer(token))
    assert status == 401 and json.loads(body)["error"]["message"] == "Authentication failed"
    assert len(fake.calls(ap.KEY_GENERATE_PATH)) == 1
    assert len(fake.caller_requests()) == 3


@pytest.mark.parametrize(
    "path",
    [
        "/key/generate",
        "/key/regenerate",
        "/user/new",
        "/team/member_add",
        "/v1/chat/completions/../../key/generate",
        "/%6Bey/generate",
        "/v1/models/",
        "/V1/chat/completions",
    ],
)
def test_jwt_management_routes_refused(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys, path: str
) -> None:
    status, body, _ = proxy.request(path=path, headers=_bearer(keys.token()))
    assert status == 403 and json.loads(body)["error"]["message"] == "Route not allowed"
    assert fake.calls(ap.KEY_GENERATE_PATH) == [] and fake.caller_requests() == []


@pytest.mark.parametrize("path", sorted(ap.JWT_ROUTES))
def test_jwt_inference_routes_allowed(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys, path: str
) -> None:
    assert proxy.request(path=path, headers=_bearer(keys.token()))[0] == 200


def test_new_token_same_user_enrols_once(proxy: Proxy, fake: FakeLiteLLM, keys: Keys) -> None:
    assert proxy.request(headers=_bearer(keys.token()))[0] == 200
    assert proxy.request(headers=_bearer(keys.token()))[0] == 200
    assert len(fake.calls(ap.KEY_GENERATE_PATH)) == 2
    assert len(fake.calls(ap.TEAM_MEMBER_ADD_PATH)) == 1


@pytest.mark.parametrize(
    "error",
    [
        {"type": ap.ALREADY_IN_TEAM_TYPE, "message": "x"},
        {"type": "bad_request_error", "message": "User is already in the team"},
    ],
)
def test_already_in_team_accepted(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys, error: dict[str, str]
) -> None:
    fake.enrol_status = 400
    fake.enrol_body = {"error": error}
    assert proxy.request(headers=_bearer(keys.token()))[0] == 200
    assert len(fake.calls(ap.KEY_GENERATE_PATH)) == 1


def _assert_503(status: int, body: bytes) -> None:
    assert status == 503
    assert json.loads(body) == {
        "error": {
            "message": "Authentication backend unavailable",
            "type": "auth_error",
            "code": "503",
        }
    }


@pytest.mark.parametrize(
    "enrol_body", [{"error": {"type": "other", "message": "nope"}}, {"error": "flat"}, {}]
)
def test_enrol_failure_is_503(
    proxy: Proxy,
    fake: FakeLiteLLM,
    keys: Keys,
    caplog: pytest.LogCaptureFixture,
    enrol_body: dict[str, Any],
) -> None:
    fake.enrol_status = 500
    fake.enrol_body = enrol_body
    with caplog.at_level(logging.INFO, logger="aegisx9.auth_proxy"):
        status, body, _ = proxy.request(headers=_bearer(keys.token()))
    _assert_503(status, body)
    assert not fake.calls(ap.KEY_GENERATE_PATH)
    assert not fake.caller_requests()
    failed = [r for r in caplog.records if r.getMessage() == "jwt exchange failed"]
    assert failed[0].fields == {"reason": "enrol_rejected", "upstream_status": 500}  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("mint_status", "mint_body"), [(500, {"error": {}}), (200, {"nokey": 1}), (200, {"key": ""})]
)
def test_mint_failure_is_503_and_reenrols(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys, mint_status: int, mint_body: dict[str, Any]
) -> None:
    fake.mint_status = mint_status
    fake.mint_body = mint_body
    token = keys.token()
    _assert_503(*proxy.request(headers=_bearer(token))[:2])
    assert not fake.caller_requests()
    fake.mint_status, fake.mint_body = 200, None
    assert proxy.request(headers=_bearer(token))[0] == 200
    # A failed mint forgets the enrolment, so the retry enrols again.
    assert len(fake.calls(ap.TEAM_MEMBER_ADD_PATH)) == 2


def test_concurrent_first_requests_enrol_and_mint_once(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys
) -> None:
    fake.mint_delay = 0.3
    token = keys.token()
    statuses: list[int] = []
    lock = threading.Lock()

    def one() -> None:
        status = proxy.request(headers=_bearer(token))[0]
        with lock:
            statuses.append(status)

    threads = [threading.Thread(target=one) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert statuses == [200] * 8
    assert len(fake.calls(ap.TEAM_MEMBER_ADD_PATH)) == 1
    assert len(fake.calls(ap.KEY_GENERATE_PATH)) == 1
    assert {r["headers"]["authorization"] for r in fake.caller_requests()} == {
        f"Bearer {fake.minted[0]}"
    }


# -- rejection -------------------------------------------------------------------------------


def _wait_access(caplog: pytest.LogCaptureFixture, count: int) -> None:
    """The access line is written after the response is sent; wait for it."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if sum(r.getMessage() == "request" for r in caplog.records) >= count:
            return
        time.sleep(0.01)
    raise AssertionError("access log line missing")


AUTH_FAILED = {"error": {"message": "Authentication failed", "type": "auth_error", "code": "401"}}


def test_rejected_jwt_is_generic_401_and_never_logged(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys, caplog: pytest.LogCaptureFixture
) -> None:
    token = keys.token(aud="someone-else")
    with caplog.at_level(logging.DEBUG):
        status, body, _ = proxy.request(path="/v1/x?q=sensitive", headers=_bearer(token))
        _wait_access(caplog, 1)
    assert status == 401 and json.loads(body) == AUTH_FAILED
    assert not fake.requests
    rejected = [r for r in caplog.records if r.getMessage() == "jwt rejected"]
    assert rejected[0].levelno == logging.WARNING
    assert rejected[0].fields == {"reason": "audience"}  # type: ignore[attr-defined]
    lines = [JsonFormatter().format(r) for r in caplog.records]
    blob = caplog.text + "\n".join(lines)
    for part in token.split("."):
        assert part not in blob
    assert "sensitive" not in blob
    access = json.loads(next(line for line in lines if '"msg":"request"' in line))
    assert access["status"] == 401 and access["auth"] == "jwt" and access["path"] == "/v1/x"


def test_success_logs_identity_but_no_secrets(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys, caplog: pytest.LogCaptureFixture
) -> None:
    token = keys.token()
    plain_key = secrets.token_urlsafe(24)
    with caplog.at_level(logging.DEBUG):
        assert proxy.request(headers=_bearer(token))[0] == 200
        assert proxy.request(headers={"x-api-key": plain_key})[0] == 200
        assert proxy.request(body=None, method="GET")[0] == 200
        _wait_access(caplog, 3)
    lines = [JsonFormatter().format(r) for r in caplog.records]
    blob = caplog.text + "\n".join(lines)
    for secret in (token, plain_key, proxy.master_key, *fake.minted):
        assert secret not in blob
    access = [json.loads(line) for line in lines if '"msg":"request"' in line]
    assert [(a["auth"], a.get("user"), a.get("team")) for a in access] == [
        ("jwt", "idp:alice", "developers"),
        ("key", None, None),
        ("none", None, None),
    ]
    assert set(access[0]) == {
        "ts",
        "level",
        "logger",
        "msg",
        "method",
        "path",
        "status",
        "duration_ms",
        "remote",
        "auth",
        "user",
        "team",
    }


def test_jwt_disabled(fake: FakeLiteLLM, keys: Keys, caplog: pytest.LogCaptureFixture) -> None:
    p, stop = _start(fake.port, None, jwt_enabled=False)
    try:
        with caplog.at_level(logging.INFO, logger="aegisx9.auth_proxy"):
            status, body, _ = p.request(headers={"x-litellm-api-key": keys.token()})
        assert status == 401 and json.loads(body) == AUTH_FAILED
        assert not fake.requests
        assert any(getattr(r, "fields", {}) == {"reason": "jwt_disabled"} for r in caplog.records)
        key = secrets.token_urlsafe(24)
        assert p.request(headers=_bearer(key))[0] == 200
        assert fake.requests[-1]["headers"]["authorization"] == f"Bearer {key}"
    finally:
        stop()


def test_head_error_has_no_body(proxy: Proxy, keys: Keys) -> None:
    status, body, resp = proxy.request(method="HEAD", body=None, headers=_bearer("a.b.c"))
    # "a.b.c" is not JWT-shaped, so HEAD is proxied; a JWT-shaped one is refused bodiless.
    assert status == 200 and body == b""
    status, body, resp = proxy.request(
        method="HEAD", body=None, headers=_bearer(keys.token(aud="x"))
    )
    assert status == 401 and body == b""
    assert int(resp.getheader("content-length") or 0) > 0


# -- request shape ---------------------------------------------------------------------------


def test_healthz_answered_locally(proxy: Proxy, fake: FakeLiteLLM) -> None:
    status, body, _ = proxy.request(method="GET", path="/healthz?probe=1", body=None)
    assert status == 200 and json.loads(body) == {"status": "ok"}
    assert not fake.requests


def _raw(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(request)
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks)


def test_chunked_request_body_refused(proxy: Proxy, fake: FakeLiteLLM) -> None:
    out = _raw(
        proxy.port,
        b"POST /v1/x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    assert out.startswith(b"HTTP/1.1 411")
    assert not fake.requests


@pytest.mark.parametrize(
    "lengths", [["abc"], ["+3"], ["3", "4"]], ids=["text", "signed", "conflicting"]
)
def test_bad_content_length_refused(proxy: Proxy, fake: FakeLiteLLM, lengths: list[str]) -> None:
    headers = b"".join(b"Content-Length: " + v.encode() + b"\r\n" for v in lengths)
    out = _raw(proxy.port, b"POST /v1/x HTTP/1.1\r\nHost: a\r\n" + headers + b"\r\nabc")
    assert out.startswith(b"HTTP/1.1 400")
    assert not fake.requests


def test_truncated_body_refused(proxy: Proxy, fake: FakeLiteLLM) -> None:
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as s:
        s.sendall(b"POST /v1/x HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc")
        s.shutdown(socket.SHUT_WR)
        out = s.recv(65536)
    assert out.startswith(b"HTTP/1.1 400")
    # The body is streamed, so LiteLLM may have seen the start; never a complete request.
    assert all(len(r["body"]) < 10 for r in fake.requests)


def test_body_streamed_not_buffered(proxy: Proxy, fake: FakeLiteLLM) -> None:
    body = secrets.token_bytes(3 * 1024 * 1024)
    assert proxy.request(body=body)[0] == 200
    assert fake.requests[-1]["body"] == body


def test_healthz_with_body_closes_connection(proxy: Proxy, fake: FakeLiteLLM) -> None:
    # The unread body must never be parsed as a second request (desync / smuggling).
    smuggled = b"GET /v1/models HTTP/1.1\r\nHost: a\r\n\r\n"
    head = f"GET /healthz HTTP/1.1\r\nHost: a\r\nContent-Length: {len(smuggled)}\r\n\r\n"
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as s:
        s.sendall(head.encode() + smuggled)
        out = b""
        while chunk := s.recv(65536):
            out += chunk
    assert out.startswith(b"HTTP/1.1 200") and out.count(b"HTTP/1.1") == 1
    assert not fake.requests


def test_idle_client_times_out(fake: FakeLiteLLM, keys: Keys) -> None:
    p, stop = _start(fake.port, make_verifier(keys), client_timeout_s=0.3)
    try:
        with socket.create_connection(("127.0.0.1", p.port), timeout=5) as s:
            s.sendall(b"GET /v1/models HTTP/1.1\r\n")  # never finishes the headers
            started = time.monotonic()
            assert s.recv(65536) == b""
            assert time.monotonic() - started < 4
    finally:
        stop()


def test_connections_capped(fake: FakeLiteLLM, keys: Keys) -> None:
    cfg = ap.ProxyConfig(upstream_port=fake.port, listen_host="127.0.0.1", listen_port=0)
    server = ap.build_server(cfg, None, None, max_connections=1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as held:
            held.sendall(b"GET /v1/models HTTP/1.1\r\n")  # holds the only slot
            time.sleep(0.2)
            with socket.create_connection(("127.0.0.1", port), timeout=5) as refused:
                refused.sendall(b"GET /healthz HTTP/1.1\r\nHost: a\r\n\r\n")
                assert refused.recv(65536) == b""
        time.sleep(0.2)  # the held connection's slot is released
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/healthz")
        assert c.getresponse().status == 200
        c.close()
    finally:
        server.shutdown()
        server.server_close()


def test_process_request_failure_releases_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = ap.ProxyConfig(listen_host="127.0.0.1", listen_port=0)
    server = ap.build_server(cfg, None, None, max_connections=1)
    try:

        def boom(*args: Any) -> None:
            raise RuntimeError

        monkeypatch.setattr(ThreadingHTTPServer, "process_request", boom)
        with pytest.raises(RuntimeError):
            server.process_request(None, ("127.0.0.1", 1))
        assert server._slots.acquire(blocking=False)  # type: ignore[attr-defined]
    finally:
        server.server_close()


def test_body_limit(fake: FakeLiteLLM, keys: Keys) -> None:
    p, stop = _start(fake.port, make_verifier(keys), max_body_bytes=16)
    try:
        status, body, _ = p.request(body=b"x" * 17)
        assert status == 413
        assert json.loads(body)["error"]["code"] == "413"
        assert p.request(body=b"x" * 16)[0] == 200
        assert fake.requests[-1]["body"] == b"x" * 16
    finally:
        stop()


def test_empty_post_sends_zero_length(proxy: Proxy, fake: FakeLiteLLM) -> None:
    assert proxy.request(method="DELETE", body=None)[0] == 200
    assert "content-length" not in fake.requests[-1]["headers"]
    assert proxy.request(method="PUT", body=None)[0] == 200
    assert fake.requests[-1]["headers"]["content-length"] == "0"


def test_websocket_upgrade_refused(proxy: Proxy, fake: FakeLiteLLM) -> None:
    status, body, _ = proxy.request(
        method="GET",
        path="/v1/realtime",
        body=None,
        headers={"Connection": "Upgrade", "Upgrade": "websocket"},
    )
    assert status == 501 and json.loads(body)["error"]["code"] == "501"
    assert not fake.requests


@pytest.mark.parametrize("target", [b"http://evil.test/v1/x", b"*"])
def test_non_origin_form_target_refused(proxy: Proxy, fake: FakeLiteLLM, target: bytes) -> None:
    out = _raw(proxy.port, b"OPTIONS " + target + b" HTTP/1.1\r\nHost: a\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 400")
    assert not fake.requests


# -- response relay --------------------------------------------------------------------------


def test_streaming_relay_delivers_chunks(proxy: Proxy, fake: FakeLiteLLM) -> None:
    c = proxy.conn()
    c.request("GET", "/stream")
    resp = c.getresponse()
    assert resp.status == 200
    assert resp.getheader("content-type") == "text/event-stream"
    assert resp.getheader("connection") == "close"
    # The first event arrives while the upstream is still holding the second back.
    assert resp.read1(64) == b"data: one\n\n"
    fake.stream_gate.set()
    assert resp.read() == b"data: two\n\n"
    c.close()


def test_chunked_response_relayed(proxy: Proxy) -> None:
    status, body, resp = proxy.request(method="GET", path="/chunked", body=None)
    assert status == 200 and body == b"abcd"
    assert resp.getheader("transfer-encoding") is None


def test_interrupted_stream_closes_connection(
    proxy: Proxy, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="aegisx9.auth_proxy"):
        out = _raw(proxy.port, b"GET /broken HTTP/1.1\r\nHost: a\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 200")
    assert any(r.getMessage() == "stream interrupted" for r in caplog.records)


def test_upstream_down_is_502(keys: Keys) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free = s.getsockname()[1]
    p, stop = _start(free, make_verifier(keys))
    try:
        status, body, _ = p.request()
        assert status == 502
        assert json.loads(body)["error"] == {
            "message": "Upstream unavailable",
            "type": "api_error",
            "code": "502",
        }
        # The admin API is down too: a JWT gets the auth-backend 503.
        _assert_503(*p.request(headers=_bearer(keys.token()))[:2])
    finally:
        stop()


def test_handler_crash_logs_type_only(fake: FakeLiteLLM, caplog: pytest.LogCaptureFixture) -> None:
    class Exploding:
        def verify(self, token: str) -> Principal:
            raise RuntimeError(token)

    leaked = secrets.token_urlsafe(8)
    p, stop = _start(fake.port, Exploding())
    try:
        token = jwt.encode({"sub": leaked}, secrets.token_bytes(32), algorithm="HS256")
        with (
            caplog.at_level(logging.INFO, logger="aegisx9.auth_proxy"),
            pytest.raises((http.client.HTTPException, OSError)),
        ):
            p.request(headers=_bearer(token))
    finally:
        stop()
    failed = [r for r in caplog.records if r.getMessage() == "request handler failed"]
    assert failed[0].fields == {"error": "RuntimeError"}  # type: ignore[attr-defined]
    assert token not in caplog.text


# -- exchanger units -------------------------------------------------------------------------


@dataclass
class FakeAdmin:
    raise_on: str | None = None
    calls: list[str] = field(default_factory=list)

    def __call__(self, path: str, payload: Any) -> tuple[int, Any]:
        self.calls.append(path)
        if path == self.raise_on:
            raise ConnectionRefusedError()
        if path == ap.KEY_GENERATE_PATH:
            return 200, {"key": secrets.token_urlsafe(16)}
        return 200, None


def _principal(user: str = "idp:u", expires_at: float = 2000.0) -> Principal:
    return Principal(user_id=user, team_id="t", issuer="idp", expires_at=int(expires_at))


@pytest.mark.parametrize(
    ("path", "reason"),
    [(ap.TEAM_MEMBER_ADD_PATH, "enrol_unreachable"), (ap.KEY_GENERATE_PATH, "mint_unreachable")],
)
def test_exchanger_unreachable(path: str, reason: str) -> None:
    ex = ap.KeyExchanger(FakeAdmin(raise_on=path), now=lambda: 1000.0)
    with pytest.raises(ap.BackendError) as e:
        ex.key_for(secrets.token_urlsafe(16), _principal())
    assert e.value.reason == reason


def test_exchanger_cache_cap_and_eviction() -> None:
    now = [1000.0]
    admin = FakeAdmin()
    ex = ap.KeyExchanger(admin, now=lambda: now[0], max_entries=2)
    tokens = [secrets.token_urlsafe(16) for _ in range(3)]
    keys_ = [
        ex.key_for(t, _principal(f"idp:{i}", 1000.0 + 10 * (i + 1))) for i, t in enumerate(tokens)
    ]
    assert len(ex._keys) == 2
    # The oldest entry was dropped, so its token mints again; the others are reused.
    assert ex.key_for(tokens[2], _principal("idp:2", 1030.0)) == keys_[2]
    mints = admin.calls.count(ap.KEY_GENERATE_PATH)
    assert ex.key_for(tokens[0], _principal("idp:0", 1010.0)) != keys_[0]
    assert admin.calls.count(ap.KEY_GENERATE_PATH) == mints + 1
    # Expired entries are evicted on the next insert.
    now[0] = 1025.0
    ex.key_for(secrets.token_urlsafe(16), _principal("idp:3", 1100.0))
    assert len(ex._keys) == 2
    assert all(k.expires_at > now[0] for k in ex._keys.values())
    assert "cached=2" in repr(ex)
    assert all(k.value not in repr(k) for k in ex._keys.values())


def test_exchanger_enrolment_cap_and_ttl() -> None:
    mono = [0.0]
    admin = FakeAdmin()
    ex = ap.KeyExchanger(admin, now=lambda: 1000.0, monotonic=lambda: mono[0], max_entries=1)
    ex.key_for(secrets.token_urlsafe(16), _principal("idp:a"))
    ex.key_for(secrets.token_urlsafe(16), _principal("idp:b"))
    assert list(ex._enrolled) == [("idp:b", "t")]
    ex.key_for(secrets.token_urlsafe(16), _principal("idp:b"))
    assert admin.calls.count(ap.TEAM_MEMBER_ADD_PATH) == 2
    mono[0] = ap.ENROL_TTL_S + 1
    ex.key_for(secrets.token_urlsafe(16), _principal("idp:b"))
    assert admin.calls.count(ap.TEAM_MEMBER_ADD_PATH) == 3


def test_admin_client_sends_master_key_and_parses(fake: FakeLiteLLM) -> None:
    master = secrets.token_urlsafe(16)
    post = ap.admin_client(ap.ProxyConfig(upstream_port=fake.port, master_key=master))
    status, data = post(ap.KEY_GENERATE_PATH, {"user_id": "u"})
    assert status == 200 and data == {"key": fake.minted[0]}
    assert fake.requests[-1]["headers"]["authorization"] == f"Bearer {master}"
    fake.enrol_body = {}
    assert post(ap.TEAM_MEMBER_ADD_PATH, {}) == (200, {})


def test_admin_client_non_json(monkeypatch: pytest.MonkeyPatch, fake: FakeLiteLLM) -> None:
    post = ap.admin_client(ap.ProxyConfig(upstream_port=fake.port, master_key="<placeholder>"))
    monkeypatch.setattr(json, "loads", lambda raw: (_ for _ in ()).throw(ValueError()))
    assert post("/anything", {}) == (200, None)


def test_admin_client_empty_body() -> None:
    class Empty(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["content-length"]))
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Empty)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        post = ap.admin_client(
            ap.ProxyConfig(upstream_port=server.server_address[1], master_key="<placeholder>")
        )
        assert post("/x", {}) == (204, None)
    finally:
        server.shutdown()
        server.server_close()


# -- configuration and process ---------------------------------------------------------------


def _issuers_file(tmp_path: Path, content: Any = None) -> str:
    path = tmp_path / "issuers.json"
    path.write_text(json.dumps({"issuers": [ISSUER_MAPPING]} if content is None else content))
    return str(path)


def test_config_defaults() -> None:
    cfg = ap.ProxyConfig.from_env({})
    assert (cfg.listen_host, cfg.listen_port) == (ap.DEFAULT_LISTEN_HOST, 4000)
    assert (cfg.upstream_host, cfg.upstream_port) == ("127.0.0.1", 4001)
    assert cfg.max_body_bytes == 64 * 1024 * 1024
    assert cfg.master_key is None


def test_config_overrides_and_repr_hides_master_key(tmp_path: Path) -> None:
    master = secrets.token_urlsafe(16)
    cfg = ap.ProxyConfig.from_env(
        {
            "AEGISX9_AUTH_LISTEN_HOST": "127.0.0.1",
            "AEGISX9_AUTH_LISTEN_PORT": "8080",
            "AEGISX9_AUTH_UPSTREAM": "http://127.0.0.1/",
            "AEGISX9_AUTH_MAX_BODY_BYTES": "1024",
            "AEGISX9_AUTH_CONFIG": _issuers_file(tmp_path),
            "LITELLM_MASTER_KEY": master,
        }
    )
    assert (cfg.listen_host, cfg.listen_port, cfg.upstream_port) == ("127.0.0.1", 8080, 80)
    assert cfg.max_body_bytes == 1024 and cfg.master_key == master
    assert master not in repr(cfg)


@pytest.mark.parametrize(
    ("env", "names"),
    [
        ({"AEGISX9_AUTH_UPSTREAM": "http://192.0.2.5:4001"}, "AEGISX9_AUTH_UPSTREAM"),
        ({"AEGISX9_AUTH_UPSTREAM": "https://127.0.0.1:4001"}, "AEGISX9_AUTH_UPSTREAM"),
        ({"AEGISX9_AUTH_UPSTREAM": "http://localhost:4001"}, "AEGISX9_AUTH_UPSTREAM"),
        ({"AEGISX9_AUTH_UPSTREAM": "http://127.0.0.1:4001/v1"}, "AEGISX9_AUTH_UPSTREAM"),
        ({"AEGISX9_AUTH_UPSTREAM": "http://u@127.0.0.1:4001"}, "AEGISX9_AUTH_UPSTREAM"),
        ({"AEGISX9_AUTH_UPSTREAM": "http://127.0.0.1:99999"}, "AEGISX9_AUTH_UPSTREAM"),
        ({"AEGISX9_AUTH_LISTEN_PORT": "abc"}, "AEGISX9_AUTH_LISTEN_PORT"),
        ({"AEGISX9_AUTH_LISTEN_PORT": "70000"}, "AEGISX9_AUTH_LISTEN_PORT"),
        ({"AEGISX9_AUTH_LISTEN_PORT": "0"}, "AEGISX9_AUTH_LISTEN_PORT"),
        ({"AEGISX9_AUTH_LISTEN_HOST": " "}, "AEGISX9_AUTH_LISTEN_HOST"),
        ({"AEGISX9_AUTH_MAX_BODY_BYTES": "0"}, "AEGISX9_AUTH_MAX_BODY_BYTES"),
        ({"AEGISX9_AUTH_MAX_BODY_BYTES": "-5"}, "AEGISX9_AUTH_MAX_BODY_BYTES"),
        ({"AEGISX9_AUTH_CONFIG": "/x"}, "LITELLM_MASTER_KEY"),
        ({"AEGISX9_AUTH_TRUSTED_PROXIES": "192.0.2.0/33"}, "AEGISX9_AUTH_TRUSTED_PROXIES"),
    ],
)
def test_config_rejects(env: dict[str, str], names: str) -> None:
    with pytest.raises(ap.ProxyConfigError) as e:
        ap.ProxyConfig.from_env(env)
    assert names in str(e.value) and e.value.variable == names


def _reset_logging() -> None:
    logging.getLogger("aegisx9").handlers[:] = []
    logging.getLogger("aegisx9").propagate = True


def _last_line(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    return dict(json.loads(capsys.readouterr().err.strip().splitlines()[-1]))


@pytest.mark.parametrize(
    "case", ["non_loopback_upstream", "bad_port", "no_master_key", "bad_issuers", "unreadable"]
)
def test_main_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str], case: str) -> None:
    master = secrets.token_urlsafe(16)
    env = {
        "non_loopback_upstream": {"AEGISX9_AUTH_UPSTREAM": "http://192.0.2.1:4001"},
        "bad_port": {"AEGISX9_AUTH_LISTEN_PORT": "port"},
        "no_master_key": {"AEGISX9_AUTH_CONFIG": _issuers_file(tmp_path)},
        "bad_issuers": {
            "AEGISX9_AUTH_CONFIG": _issuers_file(tmp_path, {"issuers": [{"name": "x"}]}),
            "LITELLM_MASTER_KEY": master,
        },
        "unreadable": {
            "AEGISX9_AUTH_CONFIG": str(tmp_path / "missing.json"),
            "LITELLM_MASTER_KEY": master,
        },
    }[case]
    try:
        assert ap.main(env) == 2
        line = _last_line(capsys)
    finally:
        _reset_logging()
    assert line["msg"] == "invalid configuration"
    assert line["error"] in ("ProxyConfigError", "AuthConfigError")
    assert set(line) <= {"ts", "level", "logger", "msg", "error", "variable"}
    assert master not in json.dumps(line)


def test_main_runs_and_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    handlers: dict[int, Any] = {}
    stopped = threading.Event()
    built: list[tuple[Any, Any]] = []

    class FakeServer:
        def serve_forever(self) -> None:
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            assert stopped.wait(5)

        def shutdown(self) -> None:
            stopped.set()

        def server_close(self) -> None:
            pass

    def fake_build(cfg: Any, verifier: Any, exchanger: Any) -> FakeServer:
        built.append((verifier, exchanger))
        return FakeServer()

    monkeypatch.setattr(ap, "build_server", fake_build)
    monkeypatch.setattr(ap.signal, "signal", lambda sig, h: handlers.__setitem__(sig, h))
    master = secrets.token_urlsafe(16)
    env = {"AEGISX9_AUTH_CONFIG": _issuers_file(tmp_path), "LITELLM_MASTER_KEY": master}
    try:
        assert ap.main(env) == 0
        assert ap.main({}) == 0
        err = capsys.readouterr().err
    finally:
        _reset_logging()
    lines = [json.loads(line) for line in err.strip().splitlines()]
    listening = [line for line in lines if line["msg"] == "listening"]
    assert [line["jwt_enabled"] for line in listening] == [True, False]
    assert listening[0]["port"] == 4000 and listening[0]["host"] == ap.DEFAULT_LISTEN_HOST
    assert any(line["msg"] == "starting" and "version" in line for line in lines)
    assert isinstance(built[0][0], Verifier) and isinstance(built[0][1], ap.KeyExchanger)
    assert built[1] == (None, None)
    assert master not in err


def test_main_bind_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*args: Any) -> None:
        raise OSError("in use")

    monkeypatch.setattr(ap, "build_server", fail)
    try:
        assert ap.main({}) == 1
        assert _last_line(capsys)["error"] == "OSError"
    finally:
        _reset_logging()


def test_non_bearer_and_empty_credentials_passthrough(
    proxy: Proxy, fake: FakeLiteLLM, keys: Keys
) -> None:
    # A JWT under a non-Bearer scheme is still recognised; empty values are ignored.
    assert proxy.request(headers={"Authorization": keys.token(aud="x"), "x-api-key": ""})[0] == 401
    status, _, _ = proxy.request(headers={"Authorization": "Basic <placeholder>", "x-api-key": " "})
    assert status == 200
    assert fake.requests[-1]["headers"]["authorization"] == "Basic <placeholder>"
