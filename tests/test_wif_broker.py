from __future__ import annotations

import base64
import hashlib
import http.client
import json
import logging
import secrets
import socket
import stat
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aegisx9 import wif_broker as wb


def _ids() -> dict[str, str]:
    # Identifiers are generated per run; nothing credential-shaped lives in the repo.
    return {
        "ANTHROPIC_FEDERATION_RULE_ID": "fdrl_" + secrets.token_hex(8),
        "ANTHROPIC_ORGANIZATION_ID": secrets.token_hex(16),
        "ANTHROPIC_SERVICE_ACCOUNT_ID": "svac_" + secrets.token_hex(8),
    }


def _cfg(tmp_path: Path, upstream: str = "http://127.0.0.1:1", **kw: Any) -> wb.BrokerConfig:
    ids = _ids()
    return wb.BrokerConfig(
        identity_token_file=str(tmp_path / "token"),
        federation_rule_id=ids["ANTHROPIC_FEDERATION_RULE_ID"],
        organization_id=ids["ANTHROPIC_ORGANIZATION_ID"],
        service_account_id=ids["ANTHROPIC_SERVICE_ACCOUNT_ID"],
        upstream=upstream,
        listen_port=0,
        **kw,
    )


@dataclass
class Clock:
    now: float = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class FakeExchange:
    lifetime: float = 1000.0
    issued: list[str] = field(default_factory=list)
    assertions: list[str] = field(default_factory=list)
    fail_with: BaseException | None = None

    def __call__(self, assertion: str) -> tuple[str, float]:
        self.assertions.append(assertion)
        if self.fail_with is not None:
            raise self.fail_with
        token = secrets.token_urlsafe(32)
        self.issued.append(token)
        return token, self.lifetime


def _write_assertion(cfg: wb.BrokerConfig) -> str:
    value = secrets.token_urlsafe(48)
    Path(cfg.identity_token_file).write_text(value + "\n", encoding="ascii")
    return value


# -- configuration ---------------------------------------------------------------------------


VAULT_OIDC_PATH = "identity/oidc/token/anthropic-test"


def _env(tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {
        "AEGISX9_WIF_IDENTITY_SOURCE": "file",
        "AEGISX9_WIF_IDENTITY_TOKEN_FILE": str(tmp_path / "token"),
        **_ids(),
    }
    env.update(extra)
    return env


def _vault_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    env = {
        "VAULT_ADDR": "https://vault.example.invalid:8200/",
        "AEGISX9_VAULT_ROLE": "gateway-test",
        "AEGISX9_VAULT_AUTH_PATH": "k8s-test",
        "AEGISX9_VAULT_TOKEN_PATH": VAULT_OIDC_PATH,
        **_ids(),
    }
    env.update(extra)
    return env


def test_config_from_env_defaults(tmp_path: Path) -> None:
    cfg = wb.BrokerConfig.from_env(_env(tmp_path))
    assert cfg.identity_source == "file"
    assert cfg.upstream == wb.DEFAULT_UPSTREAM
    assert cfg.listen_host == "127.0.0.1"
    assert cfg.listen_port == 8787
    assert cfg.workspace_id is None
    assert cfg.refresh_fraction == pytest.approx(0.8)


def test_config_vault_source_is_default(tmp_path: Path) -> None:
    cfg = wb.BrokerConfig.from_env(_vault_env(tmp_path, VAULT_CACERT="/etc/ca.crt"))
    assert cfg.identity_source == "vault"
    assert cfg.vault_addr == "https://vault.example.invalid:8200"
    assert cfg.vault_role == "gateway-test"
    assert cfg.vault_token_path == VAULT_OIDC_PATH
    assert cfg.vault_auth_path == "k8s-test"
    assert cfg.vault_jwt_file == wb.DEFAULT_VAULT_JWT_FILE
    assert cfg.vault_cacert == "/etc/ca.crt"


def test_config_vault_missing_names(tmp_path: Path) -> None:
    with pytest.raises(wb.BrokerConfigError) as exc:
        wb.BrokerConfig.from_env(_ids())
    msg = str(exc.value)
    assert "VAULT_ADDR" in msg and "AEGISX9_VAULT_ROLE" in msg
    assert "AEGISX9_VAULT_TOKEN_PATH" in msg and "AEGISX9_VAULT_AUTH_PATH" in msg
    assert "AEGISX9_WIF_IDENTITY_TOKEN_FILE" not in msg


@pytest.mark.parametrize(
    "extra",
    [
        {"VAULT_ADDR": "http://vault.example.invalid:8200"},
        {"AEGISX9_VAULT_TOKEN_PATH": "kv/data/anything"},
        {"AEGISX9_VAULT_TOKEN_PATH": "identity/oidc/token/../../sys/raw"},
        {"AEGISX9_VAULT_TOKEN_PATH": "identity/oidc/token/"},
        {"AEGISX9_VAULT_AUTH_PATH": "k8s/../token"},
        {"AEGISX9_WIF_IDENTITY_SOURCE": "metadata"},
    ],
)
def test_config_vault_rejects_unsafe_values(tmp_path: Path, extra: dict[str, str]) -> None:
    with pytest.raises(wb.BrokerConfigError):
        wb.BrokerConfig.from_env(_vault_env(tmp_path, **extra))


def test_config_from_env_optional_values(tmp_path: Path) -> None:
    cfg = wb.BrokerConfig.from_env(
        _env(
            tmp_path,
            ANTHROPIC_WORKSPACE_ID="wrkspc_" + secrets.token_hex(6),
            AEGISX9_WIF_LISTEN_PORT="9999",
            AEGISX9_WIF_STATE_FILE=str(tmp_path / "state"),
            AEGISX9_WIF_UPSTREAM="https://api.anthropic.com/",
        )
    )
    assert cfg.workspace_id and cfg.workspace_id.startswith("wrkspc_")
    assert cfg.listen_port == 9999
    assert cfg.upstream == "https://api.anthropic.com"
    assert cfg.state_file == str(tmp_path / "state")


def test_config_reports_missing_names_only(tmp_path: Path) -> None:
    with pytest.raises(wb.BrokerConfigError) as exc:
        wb.BrokerConfig.from_env(
            {"AEGISX9_WIF_IDENTITY_SOURCE": "file", "ANTHROPIC_ORGANIZATION_ID": "x"}
        )
    msg = str(exc.value)
    assert "ANTHROPIC_FEDERATION_RULE_ID" in msg
    assert "AEGISX9_WIF_IDENTITY_TOKEN_FILE" in msg
    assert "ANTHROPIC_ORGANIZATION_ID" not in msg


@pytest.mark.parametrize("var", ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"])
def test_config_refuses_static_credential(tmp_path: Path, var: str) -> None:
    value = secrets.token_urlsafe(16)
    with pytest.raises(wb.BrokerConfigError) as exc:
        wb.BrokerConfig.from_env(_env(tmp_path, **{var: value}))
    assert value not in str(exc.value)


@pytest.mark.parametrize(
    "extra",
    [
        {"AEGISX9_WIF_UPSTREAM": "http://api.anthropic.com"},
        {"AEGISX9_WIF_LISTEN_HOST": "0.0.0.0"},  # noqa: S104 - asserting it is refused
        {"AEGISX9_WIF_LISTEN_HOST": "::1"},  # IPv4 listener only
        {"AEGISX9_WIF_LISTEN_HOST": "localhost"},
        {"AEGISX9_WIF_LISTEN_PORT": "eighty"},
        {"AEGISX9_WIF_REFRESH_FRACTION": "0.95"},
    ],
)
def test_config_rejects_unsafe_values(tmp_path: Path, extra: dict[str, str]) -> None:
    with pytest.raises(wb.BrokerConfigError):
        wb.BrokerConfig.from_env(_env(tmp_path, **extra))


def test_exchange_body_matches_reference(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    assertion = secrets.token_urlsafe(24)
    body = wb.build_exchange_body(cfg, assertion)
    assert body == {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": assertion,
        "federation_rule_id": cfg.federation_rule_id,
        "organization_id": cfg.organization_id,
        "service_account_id": cfg.service_account_id,
    }
    ws = "wrkspc_" + secrets.token_hex(6)
    with_ws = wb.build_exchange_body(_cfg(tmp_path, workspace_id=ws), assertion)
    assert with_ws["workspace_id"] == ws


# -- fake Anthropic API ----------------------------------------------------------------------


@dataclass
class Upstream:
    url: str
    requests: list[dict[str, Any]]
    token_response: dict[str, Any]
    token_status: list[int]
    release_stream: threading.Event
    first_event_sent: threading.Event


@pytest.fixture
def upstream() -> Iterator[Upstream]:
    requests: list[dict[str, Any]] = []
    state: dict[str, Any] = {
        "token_response": {
            "access_token": secrets.token_urlsafe(32),
            "token_type": "Bearer",
            "expires_in": 600,
            "scope": "workspace:inference",
        },
        "token_status": [200],
    }
    release = threading.Event()
    first_sent = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _record(self) -> bytes:
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length) if length else b""
            requests.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body,
                }
            )
            return body

        def _send(self, status: int, payload: bytes, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.send_header("anthropic-organization-id", secrets.token_hex(8))
            self.send_header("request-id", "req_test")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            self._record()
            self._send(200, b'{"data":[]}')

        def do_POST(self) -> None:
            self._record()
            if self.path == wb.TOKEN_PATH:
                status = state["token_status"][0]
                if status == 200 and isinstance(state["token_response"], dict):
                    self._send(200, json.dumps(state["token_response"]).encode())
                elif status == 200:
                    self._send(200, state["token_response"])
                else:
                    self._send(status, b'{"type":"error"}')
                return
            if self.path.startswith("/v1/messages") and b'"stream": true' in requests[-1]["body"]:
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("connection", "close")
                self.end_headers()
                self.wfile.write(b"event: message_start\ndata: {}\n\n")
                self.wfile.flush()
                first_sent.set()
                release.wait(5)
                self.wfile.write(b"event: message_stop\ndata: {}\n\n")
                self.wfile.flush()
                self.close_connection = True
                return
            self._send(200, b'{"type":"message"}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    up = Upstream(
        url=f"http://127.0.0.1:{server.server_address[1]}",
        requests=requests,
        token_response=state["token_response"],
        token_status=state["token_status"],
        release_stream=release,
        first_event_sent=first_sent,
    )
    up.__dict__["_state"] = state
    yield up
    release.set()
    server.shutdown()
    server.server_close()


def test_http_exchange_request_shape(tmp_path: Path, upstream: Upstream) -> None:
    cfg = _cfg(tmp_path, upstream=upstream.url, workspace_id="wrkspc_" + secrets.token_hex(4))
    assertion = secrets.token_urlsafe(40)
    token, expires_in = wb.http_exchange(cfg)(assertion)
    assert token == upstream.token_response["access_token"]
    assert expires_in == 600
    (req,) = upstream.requests
    assert req["method"] == "POST"
    assert req["path"] == "/v1/oauth/token"
    assert req["headers"]["content-type"] == "application/json"
    assert "authorization" not in req["headers"]
    assert "x-api-key" not in req["headers"]
    assert json.loads(req["body"]) == wb.build_exchange_body(cfg, assertion)


@pytest.mark.parametrize(
    "status,response",
    [
        (401, None),
        (200, b"not json"),
        (200, {"token_type": "Bearer", "expires_in": 600}),
        (200, {"access_token": "x", "token_type": "mac", "expires_in": 600}),
        (200, {"access_token": "x", "token_type": "Bearer", "expires_in": True}),
        (200, {"access_token": "x", "token_type": "Bearer", "expires_in": 0}),
        (200, ["not", "a", "dict"]),
    ],
)
def test_http_exchange_rejects_bad_answers(
    tmp_path: Path, upstream: Upstream, status: int, response: Any
) -> None:
    state = upstream.__dict__["_state"]
    state["token_status"][0] = status
    if response is not None:
        state["token_response"] = (
            response if isinstance(response, dict | bytes) else json.dumps(response).encode()
        )
    with pytest.raises(wb.TokenExchangeError) as exc:
        wb.http_exchange(_cfg(tmp_path, upstream=upstream.url))(secrets.token_urlsafe(8))
    assert exc.value.status == status


def test_open_connection_scheme() -> None:
    assert isinstance(
        wb.open_connection("https://api.anthropic.com", 1), http.client.HTTPSConnection
    )
    plain = wb.open_connection("http://127.0.0.1:8080", 1)
    assert not isinstance(plain, http.client.HTTPSConnection)


# -- token manager -------------------------------------------------------------------------


def test_refresh_schedule_and_validity(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    clock, ex = Clock(), FakeExchange(lifetime=1000.0)
    m = wb.TokenManager(cfg, ex, clock=clock, rng=lambda: 1.0)
    assert m.current_token() is None
    first = _write_assertion(cfg)
    assert m.step() == pytest.approx(800.0)
    assert ex.assertions == [first]
    assert m.current_token() == ex.issued[0]
    # Not due yet: no exchange.
    clock.now += 500
    assert m.step() == pytest.approx(300.0)
    assert len(ex.assertions) == 1
    # Due, but the kubelet has not rotated the assertion: never re-present it.
    clock.now += 300
    assert m.step() == wb.ASSERTION_POLL_S
    assert m.step() == wb.ASSERTION_POLL_S
    assert len(ex.assertions) == 1
    assert m.current_token() == ex.issued[0]
    # Rotated: exchanged once.
    second = _write_assertion(cfg)
    m.step()
    assert ex.assertions == [first, second]
    assert m.current_token() == ex.issued[1]


def test_token_invalid_inside_mandatory_margin(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    clock, ex = Clock(), FakeExchange(lifetime=100.0)
    m = wb.TokenManager(cfg, ex, clock=clock)
    _write_assertion(cfg)
    m.step()
    clock.now += 100 - wb.MANDATORY_MARGIN_S - 1
    assert m.is_valid()
    assert m.seconds_invalid() == 0.0
    clock.now += 2
    assert not m.is_valid()
    assert m.seconds_to_expiry() == pytest.approx(wb.MANDATORY_MARGIN_S - 1)
    clock.now += 50
    assert m.seconds_invalid() == pytest.approx(0.0)  # invalidity clock starts when observed
    clock.now += 40
    assert m.seconds_invalid() == pytest.approx(40.0)
    status = m.status_fields()
    assert status["valid"] is False
    assert status["invalid_for_s"] == 40
    assert status["event"] == "wif_token_status"


def test_rejected_exchange_backs_off_and_keeps_assertion_marked(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    ex = FakeExchange(fail_with=wb.TokenExchangeError(401))
    m = wb.TokenManager(cfg, ex, clock=Clock(), rng=lambda: 0.0)
    _write_assertion(cfg)
    assert m.step() == pytest.approx(0.5)  # 1 s base, jitter floor of 50 %
    assert m.step() == wb.ASSERTION_POLL_S  # same assertion is not presented again
    assert len(ex.assertions) == 1
    _write_assertion(cfg)
    assert m.step() == pytest.approx(1.0)  # second failure doubles
    assert len(ex.assertions) == 2


def test_backoff_is_capped_and_jittered(tmp_path: Path) -> None:
    m = wb.TokenManager(_cfg(tmp_path), FakeExchange(), clock=Clock(), rng=lambda: 1.0)
    delays = [m._backoff() for _ in range(10)]
    assert delays[0] == pytest.approx(1.0)
    assert max(delays) == pytest.approx(wb.BACKOFF_MAX_S)


def test_network_error_allows_retry_with_same_assertion(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    ex = FakeExchange(fail_with=ConnectionRefusedError())
    m = wb.TokenManager(cfg, ex, clock=Clock(), rng=lambda: 0.0)
    _write_assertion(cfg)
    m.step()
    ex.fail_with = None
    m.step()
    assert len(ex.assertions) == 2
    assert ex.assertions[0] == ex.assertions[1]
    assert m.is_valid()


@pytest.mark.parametrize("content", [None, "", "x" * (wb.MAX_ASSERTION_BYTES + 1)])
def test_unusable_identity_token_backs_off(tmp_path: Path, content: str | None) -> None:
    cfg = _cfg(tmp_path)
    if content is not None:
        Path(cfg.identity_token_file).write_text(content, encoding="ascii")
    ex = FakeExchange()
    m = wb.TokenManager(cfg, ex, clock=Clock(), rng=lambda: 0.0)
    assert m.step() == pytest.approx(0.5)
    assert ex.assertions == []


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt(header: object) -> str:
    # Shaped like a compact JWT, generated per run; the signature is random bytes.
    return ".".join(
        [
            _b64url(json.dumps(header).encode()),
            _b64url(json.dumps({"jti": secrets.token_hex(8)}).encode()),
            _b64url(secrets.token_bytes(32)),
        ]
    )


def test_jwt_kid() -> None:
    kid = str(uuid.uuid4())
    assert wb.jwt_kid(_jwt({"alg": "RS256", "kid": kid})) == kid
    assert wb.jwt_kid(_jwt({"alg": "RS256"})) is None
    assert wb.jwt_kid(_jwt({"alg": "RS256", "kid": 7})) is None
    assert wb.jwt_kid(_jwt(["not", "an", "object"])) is None
    assert wb.jwt_kid("%%%." + secrets.token_hex(4)) is None
    assert wb.jwt_kid(_b64url(b"not json") + ".x.y") is None
    assert wb.jwt_kid("") is None
    assert wb.jwt_kid("a" * (wb.MAX_JWT_HEADER_CHARS + 1) + ".x.y") is None


def test_config_uploaded_kids(tmp_path: Path) -> None:
    kids = [str(uuid.uuid4()), str(uuid.uuid4())]
    cfg = wb.BrokerConfig.from_env(
        _env(tmp_path, AEGISX9_WIF_UPLOADED_KIDS=f" {kids[0]},,{kids[1]} ,{kids[0]}")
    )
    assert cfg.uploaded_kids == tuple(kids)
    assert wb.BrokerConfig.from_env(_env(tmp_path)).uploaded_kids == ()


def _kid_events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [
        getattr(r, "fields", {})
        for r in caplog.records
        if getattr(r, "fields", {}).get("event") == "wif_kid_not_uploaded"
    ]


@pytest.mark.parametrize("scenario", ["uploaded", "other", "unsafe", "no_kid", "unchecked"])
def test_kid_check_on_each_new_identity_token(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, scenario: str
) -> None:
    uploaded, other = str(uuid.uuid4()), str(uuid.uuid4())
    header: dict[str, Any] = {"alg": "RS256"}
    if scenario != "no_kid":
        header["kid"] = {
            "uploaded": uploaded,
            "unchecked": other,
            "other": other,
            "unsafe": "bad kid\n" + "x" * 200,
        }[scenario]
    kids = () if scenario == "unchecked" else (uploaded,)
    cfg = _cfg(tmp_path, uploaded_kids=kids)
    assertion = _jwt(header)
    ex = FakeExchange()
    m = wb.TokenManager(cfg, ex, clock=Clock(), source=lambda: assertion)
    with caplog.at_level(logging.INFO, logger="aegisx9.wif_broker"):
        m.step()
    # The exchange always goes ahead: the provider is the one that refuses it.
    assert ex.assertions == [assertion]
    events = _kid_events(caplog)
    expected = {"uploaded": [], "unchecked": [], "other": [other], "unsafe": [None]}
    assert [e["kid"] for e in events] == expected.get(scenario, [None])
    # The identity token itself never reaches the log.
    assert assertion not in caplog.text
    assert assertion.split(".")[2] not in caplog.text


def test_state_file_survives_restart_without_secrets(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, state_file=str(tmp_path / "state"))
    ex = FakeExchange()
    m = wb.TokenManager(cfg, ex, clock=Clock())
    assertion = _write_assertion(cfg)
    m.step()
    state = Path(cfg.state_file or "")
    content = state.read_text(encoding="ascii")
    assert content == hashlib.sha256(assertion.encode()).hexdigest()
    assert assertion not in content and ex.issued[0] not in content
    assert stat.S_IMODE(state.stat().st_mode) == 0o600
    # A restarted broker must not re-present the assertion it already exchanged.
    restarted = wb.TokenManager(cfg, ex, clock=Clock())
    assert restarted.step() == wb.ASSERTION_POLL_S
    assert len(ex.assertions) == 1


def test_state_file_ignores_garbage_and_unwritable_paths(tmp_path: Path) -> None:
    bad = tmp_path / "state"
    bad.write_text("not-a-digest", encoding="ascii")
    m = wb.TokenManager(_cfg(tmp_path, state_file=str(bad)), FakeExchange(), clock=Clock())
    assert m._last_digest is None
    missing_dir = _cfg(tmp_path, state_file=str(tmp_path / "nope" / "state"))
    m2 = wb.TokenManager(missing_dir, FakeExchange(), clock=Clock())
    _write_assertion(missing_dir)
    m2.step()  # write fails, the broker carries on
    assert m2.is_valid()
    assert "valid=True" in repr(m2)


def test_run_loop_stops_and_reports_status(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = _cfg(tmp_path)
    _write_assertion(cfg)
    ex = FakeExchange()
    m = wb.TokenManager(cfg, ex)
    stop = threading.Event()
    with caplog.at_level(logging.INFO, logger="aegisx9.wif_broker"):
        t = threading.Thread(target=m.run, args=(stop, 0.05))
        t.start()
        for _ in range(100):
            if m.is_valid():
                break
            threading.Event().wait(0.01)
        stop.set()
        t.join(2)
    assert not t.is_alive()
    assert m.is_valid()
    assert any(getattr(r, "fields", {}).get("event") == "wif_token_status" for r in caplog.records)


# -- reverse proxy ---------------------------------------------------------------------------


@dataclass
class Broker:
    port: int
    manager: wb.TokenManager
    exchange: FakeExchange

    def conn(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)

    @property
    def token(self) -> str:
        return self.exchange.issued[-1]


def _start_broker(
    tmp_path: Path, upstream_url: str, with_token: bool = True, **kw: Any
) -> tuple[Broker, Callable[[], None]]:
    cfg = _cfg(tmp_path, upstream=upstream_url, **kw)
    ex = FakeExchange()
    m = wb.TokenManager(cfg, ex)
    if with_token:
        _write_assertion(cfg)
        m.step()
    server = wb.build_server(cfg, m)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    def stop() -> None:
        server.shutdown()
        server.server_close()

    return Broker(port=server.server_address[1], manager=m, exchange=ex), stop


@pytest.fixture
def broker(tmp_path: Path, upstream: Upstream) -> Iterator[Broker]:
    b, stop = _start_broker(tmp_path, upstream.url)
    yield b
    stop()


def test_proxy_replaces_credentials(broker: Broker, upstream: Upstream) -> None:
    caller_key = secrets.token_urlsafe(16)
    caller_bearer = secrets.token_urlsafe(16)
    c = broker.conn()
    c.request(
        "POST",
        "/v1/messages?beta=true",
        body=b'{"model": "claude-haiku-5-5"}',
        headers={
            "x-api-key": caller_key,
            "Authorization": f"Bearer {caller_bearer}",
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "some-beta",
            "content-type": "application/json",
            "anthropic-dangerous-direct-browser-access": "true",
        },
    )
    resp = c.getresponse()
    assert resp.status == 200
    assert resp.read() == b'{"type":"message"}'
    assert resp.getheader("anthropic-organization-id") is None
    assert resp.getheader("request-id") == "req_test"
    req = upstream.requests[-1]
    assert req["path"] == "/v1/messages?beta=true"
    assert req["headers"]["authorization"] == f"Bearer {broker.token}"
    assert "x-api-key" not in req["headers"]
    assert "anthropic-dangerous-direct-browser-access" not in req["headers"]
    assert req["headers"]["anthropic-version"] == "2023-06-01"
    assert req["headers"]["anthropic-beta"] == "some-beta"
    assert caller_key not in json.dumps(req["headers"])
    assert caller_bearer not in json.dumps(req["headers"])
    assert req["body"] == b'{"model": "claude-haiku-5-5"}'


def test_proxy_get_models(broker: Broker, upstream: Upstream) -> None:
    c = broker.conn()
    c.request("GET", "/v1/models")
    resp = c.getresponse()
    assert resp.status == 200
    assert resp.read() == b'{"data":[]}'
    assert upstream.requests[-1]["headers"]["authorization"] == f"Bearer {broker.token}"


def test_proxy_streams_sse_unbuffered(broker: Broker, upstream: Upstream) -> None:
    c = broker.conn()
    c.request("POST", "/v1/messages", body=b'{"stream": true}', headers={"x-api-key": "unused"})
    resp = c.getresponse()
    assert resp.status == 200
    assert resp.getheader("content-type") == "text/event-stream"
    first = resp.read1(4096)
    # The upstream is still holding the stream open: this proves nothing was buffered.
    assert b"message_start" in first
    assert b"message_stop" not in first
    assert not upstream.release_stream.is_set()
    upstream.release_stream.set()
    rest = resp.read()
    assert b"message_stop" in rest


def test_healthz_reflects_token_state(tmp_path: Path, upstream: Upstream) -> None:
    b, stop = _start_broker(tmp_path, upstream.url, with_token=False)
    try:
        c = b.conn()
        c.request("GET", "/healthz")
        r = c.getresponse()
        assert r.status == 503
        assert json.loads(r.read()) == {"status": "no_token"}
        c.request("POST", "/v1/messages", body=b"{}")
        r = c.getresponse()
        assert r.status == 503
        r.read()
        _write_assertion(b.manager.cfg)
        b.manager.step()
        c.request("GET", "/healthz")
        r = c.getresponse()
        assert r.status == 200
        assert json.loads(r.read()) == {"status": "ok"}
        assert upstream.requests == []
    finally:
        stop()


@pytest.mark.parametrize(
    "method,path,status",
    [
        ("POST", "/v1/oauth/token", 404),
        ("POST", "/v1/files", 404),
        ("GET", "/v1/messages/../organizations", 404),
        ("GET", "//v1/files", 404),
        ("DELETE", "/v1/messages", 405),
        ("PUT", "/v1/messages", 405),
    ],
)
def test_proxy_refuses_other_paths_and_methods(
    broker: Broker, upstream: Upstream, method: str, path: str, status: int
) -> None:
    c = broker.conn()
    c.request(method, path, body=b"{}")
    r = c.getresponse()
    assert r.status == status
    r.read()
    assert upstream.requests == []


def test_proxy_body_limits(tmp_path: Path, upstream: Upstream) -> None:
    b, stop = _start_broker(tmp_path, upstream.url, max_body_bytes=8)
    try:
        c = b.conn()
        c.request("POST", "/v1/messages", body=b"0123456789")
        r = c.getresponse()
        assert r.status == 413
        r.read()
        c = b.conn()
        c.putrequest("POST", "/v1/messages")
        c.putheader("transfer-encoding", "chunked")
        c.endheaders()
        c.send(b"0\r\n\r\n")
        r = c.getresponse()
        assert r.status == 411
        r.read()
        c = b.conn()
        c.putrequest("POST", "/v1/messages")
        c.putheader("content-length", "abc")
        c.endheaders()
        r = c.getresponse()
        assert r.status == 400
        r.read()
        assert upstream.requests == []
    finally:
        stop()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def test_proxy_upstream_down_is_502(tmp_path: Path) -> None:
    b, stop = _start_broker(tmp_path, f"http://127.0.0.1:{_free_port()}")
    try:
        c = b.conn()
        c.request("POST", "/v1/messages", body=b"{}")
        r = c.getresponse()
        assert r.status == 502
        assert json.loads(r.read())["error"]["type"] == "api_error"
    finally:
        stop()


def test_proxy_connect_error_is_502(tmp_path: Path, upstream: Upstream) -> None:
    cfg = _cfg(tmp_path, upstream=upstream.url)
    m = wb.TokenManager(cfg, FakeExchange())
    _write_assertion(cfg)
    m.step()

    def broken_connect(url: str, timeout: float) -> http.client.HTTPConnection:
        raise OSError

    handler = wb.make_handler(cfg, m, connect=broken_connect)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        c.request("POST", "/v1/messages", body=b"{}")
        r = c.getresponse()
        assert r.status == 502
        r.read()
    finally:
        server.shutdown()
        server.server_close()


def test_path_allowed() -> None:
    assert wb.path_allowed("/v1/messages")
    assert wb.path_allowed("/v1/messages/count_tokens?beta=true")
    assert wb.path_allowed("/v1/models/claude-haiku-5-5")
    assert not wb.path_allowed("/v1/messagesX")
    assert not wb.path_allowed("/v1/messages/..")
    assert not wb.path_allowed("/v1/messages\\x")
    assert not wb.path_allowed("/healthz")
    assert not wb.path_allowed("https://example.invalid/v1/messages")
    assert not wb.path_allowed("//example.invalid/v1/messages")


# -- logging -------------------------------------------------------------------------------


def test_no_token_or_assertion_in_logs(
    tmp_path: Path, upstream: Upstream, caplog: pytest.LogCaptureFixture
) -> None:
    formatter = wb.JsonFormatter()
    with caplog.at_level(logging.DEBUG):
        cfg = _cfg(tmp_path, upstream=upstream.url)
        m = wb.TokenManager(cfg, wb.http_exchange(cfg))
        assertion = _write_assertion(cfg)
        m.step()
        token = m.current_token()
        assert token
        server = wb.build_server(cfg, m)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            c.request("POST", "/v1/messages", body=b"{}", headers={"x-api-key": "unused"})
            c.getresponse().read()
        finally:
            server.shutdown()
            server.server_close()
        m.exchange = lambda _a: (_ for _ in ()).throw(wb.TokenExchangeError(401))
        m._refresh_at = 0
        _write_assertion(cfg)
        m.step()
    lines = [formatter.format(r) for r in caplog.records]
    assert any('"msg":"request"' in line and '"status":200' in line for line in lines)
    assert any('"status":401' in line for line in lines)
    blob = "\n".join(lines) + caplog.text
    assert token not in blob
    assert assertion not in blob
    for line in lines:
        json.loads(line)


def test_json_formatter_and_configure_logging() -> None:
    wb.configure_logging()
    root = logging.getLogger("aegisx9")
    assert isinstance(root.handlers[0].formatter, wb.JsonFormatter)
    record = logging.LogRecord("aegisx9.x", logging.INFO, __file__, 1, "hello", None, None)
    record.fields = {"a": 1}
    entry = json.loads(wb.JsonFormatter().format(record))
    assert entry["msg"] == "hello" and entry["a"] == 1 and entry["level"] == "info"
    root.handlers[:] = []
    root.propagate = True


def test_main_rejects_bad_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert wb.main({"ANTHROPIC_API_KEY": secrets.token_urlsafe(8)}) == 2
    err = capsys.readouterr().err
    assert "invalid configuration" in err
    logging.getLogger("aegisx9").handlers[:] = []
    logging.getLogger("aegisx9").propagate = True


@pytest.mark.parametrize(
    "missing", ["AEGISX9_VAULT_ROLE", "AEGISX9_VAULT_TOKEN_PATH", "AEGISX9_VAULT_AUTH_PATH"]
)
def test_main_fails_closed_without_vault_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], missing: str
) -> None:
    env = _vault_env(tmp_path)
    del env[missing]
    assert wb.main(env) == 2
    line = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
    assert line["error"] == "BrokerConfigError"
    assert missing in line["detail"]
    logging.getLogger("aegisx9").handlers[:] = []
    logging.getLogger("aegisx9").propagate = True


def test_main_runs_and_stops(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    served: list[bool] = []

    class FakeServer:
        def serve_forever(self) -> None:
            served.append(True)

        def shutdown(self) -> None:
            pass

        def server_close(self) -> None:
            pass

    monkeypatch.setattr(wb, "build_server", lambda cfg, manager: FakeServer())
    env = _vault_env(tmp_path, AEGISX9_VAULT_K8S_JWT_FILE=str(tmp_path / "missing"))
    assert wb.main(env) == 0
    assert served == [True]
    logging.getLogger("aegisx9").handlers[:] = []
    logging.getLogger("aegisx9").propagate = True


# -- Vault identity source -----------------------------------------------------------------


@dataclass
class FakeVault:
    lease: int = 600
    renewable: bool = True
    fail_login: bool = False
    refuse_renew: bool = False
    forbid_next_fetch: bool = False
    raise_error: BaseException | None = None
    identity_status: int = 200
    calls: list[tuple[str, str, str | None, Any]] = field(default_factory=list)
    issued_vault_tokens: list[str] = field(default_factory=list)
    issued_identity: list[str] = field(default_factory=list)

    def _auth(self) -> dict[str, Any]:
        token = secrets.token_urlsafe(24)
        self.issued_vault_tokens.append(token)
        return {
            "auth": {
                "client_token": token,
                "lease_duration": self.lease,
                "renewable": self.renewable,
            }
        }

    def __call__(self, method: str, path: str, token: str | None, body: Any) -> tuple[int, Any]:
        self.calls.append((method, path, token, body))
        if self.raise_error is not None:
            raise self.raise_error
        if path.endswith("/login"):
            return (403, None) if self.fail_login else (200, self._auth())
        if path == "auth/token/renew-self":
            return (403, None) if self.refuse_renew else (200, self._auth())
        if token not in self.issued_vault_tokens:
            return 403, None
        if self.forbid_next_fetch:
            self.forbid_next_fetch = False
            return 403, None
        if self.identity_status != 200:
            return self.identity_status, {"data": {}}
        identity = secrets.token_urlsafe(48)
        self.issued_identity.append(identity)
        return 200, {"data": {"token": identity, "client_id": "x", "ttl": 3600}}


def _vault_cfg(tmp_path: Path) -> wb.BrokerConfig:
    jwt = tmp_path / "sa-token"
    jwt.write_text(secrets.token_urlsafe(40), encoding="ascii")
    return wb.BrokerConfig.from_env(_vault_env(tmp_path, AEGISX9_VAULT_K8S_JWT_FILE=str(jwt)))


def test_vault_source_logs_in_and_fetches_fresh_tokens(tmp_path: Path) -> None:
    cfg = _vault_cfg(tmp_path)
    vault, clock = FakeVault(), Clock()
    source = wb.VaultIdentitySource(cfg, vault, clock=clock)
    first, second = source(), source()
    assert first != second
    assert vault.issued_identity == [first, second]
    login = vault.calls[0]
    assert login[:3] == ("POST", "auth/k8s-test/login", None)
    assert login[3] == {
        "role": "gateway-test",
        "jwt": Path(cfg.vault_jwt_file).read_text(encoding="ascii"),
    }
    fetches = [c for c in vault.calls if c[1] == VAULT_OIDC_PATH]
    assert [c[0] for c in fetches] == ["GET", "GET"]
    assert all(c[2] == vault.issued_vault_tokens[0] for c in fetches)
    assert len(vault.issued_vault_tokens) == 1  # one login, reused
    assert "logged_in=True" in repr(source)
    assert vault.issued_vault_tokens[0] not in repr(source)


def test_vault_source_renews_then_relogs_when_refused(tmp_path: Path) -> None:
    cfg = _vault_cfg(tmp_path)
    vault, clock = FakeVault(lease=600), Clock()
    source = wb.VaultIdentitySource(cfg, vault, clock=clock)
    source()
    clock.now += 450  # past 2/3 of the lease
    source()
    assert [c[1] for c in vault.calls].count("auth/token/renew-self") == 1
    vault.refuse_renew = True
    clock.now += 450
    source()
    assert [c[1] for c in vault.calls].count("auth/k8s-test/login") == 2
    clock.now += 10_000  # expired: straight to login
    source()
    assert [c[1] for c in vault.calls].count("auth/k8s-test/login") == 3


def test_vault_source_relogs_once_on_403(tmp_path: Path) -> None:
    vault = FakeVault(forbid_next_fetch=True)
    source = wb.VaultIdentitySource(_vault_cfg(tmp_path), vault, clock=Clock())
    assert source()
    assert [c[1] for c in vault.calls].count("auth/k8s-test/login") == 2


@pytest.mark.parametrize(
    "vault",
    [
        FakeVault(fail_login=True),
        FakeVault(identity_status=500),
        FakeVault(raise_error=ConnectionRefusedError()),
    ],
)
def test_vault_source_failures_raise_vault_error(tmp_path: Path, vault: FakeVault) -> None:
    source = wb.VaultIdentitySource(_vault_cfg(tmp_path), vault, clock=Clock())
    with pytest.raises(wb.VaultError):
        source()


def test_vault_source_rejects_malformed_auth(tmp_path: Path) -> None:
    def bad_login(method: str, path: str, token: str | None, body: Any) -> tuple[int, Any]:
        return 200, {"auth": {"lease_duration": 600}}

    source = wb.VaultIdentitySource(_vault_cfg(tmp_path), bad_login, clock=Clock())
    with pytest.raises(wb.VaultError):
        source()


def test_vault_source_missing_or_oversized_jwt(tmp_path: Path) -> None:
    cfg = _vault_cfg(tmp_path)
    Path(cfg.vault_jwt_file).write_text("x" * (wb.MAX_ASSERTION_BYTES + 1), encoding="ascii")
    with pytest.raises(wb.VaultError):
        wb.VaultIdentitySource(cfg, FakeVault(), clock=Clock())()
    Path(cfg.vault_jwt_file).unlink()
    with pytest.raises(wb.VaultError):
        wb.VaultIdentitySource(cfg, FakeVault(), clock=Clock())()


def test_manager_with_vault_source_never_reuses_assertions(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = _vault_cfg(tmp_path)
    vault, clock, ex = FakeVault(), Clock(), FakeExchange(lifetime=600)
    source = wb.VaultIdentitySource(cfg, vault, clock=clock)
    m = wb.TokenManager(cfg, ex, clock=clock, source=source)
    with caplog.at_level(logging.DEBUG):
        m.step()
        clock.now += 500
        m.step()
        ex.fail_with = wb.TokenExchangeError(401)
        clock.now += 500
        m.step()
        vault.fail_login = True
        vault.issued_vault_tokens.clear()
        m.step()
    assert len(ex.assertions) == 3
    assert len(set(ex.assertions)) == 3
    blob = caplog.text + "\n".join(wb.JsonFormatter().format(r) for r in caplog.records)
    for secret in [*vault.issued_vault_tokens, *vault.issued_identity, *ex.issued]:
        assert secret not in blob
    assert any(getattr(r, "fields", {}).get("error") == "VaultError" for r in caplog.records)


def test_manager_rejects_empty_source_value(tmp_path: Path) -> None:
    m = wb.TokenManager(
        _cfg(tmp_path), FakeExchange(), clock=Clock(), rng=lambda: 0.0, source=lambda: " "
    )
    assert m.step() == pytest.approx(0.5)


def test_manager_without_any_source(tmp_path: Path) -> None:
    cfg = wb.BrokerConfig(federation_rule_id="r", organization_id="o", service_account_id="s")
    m = wb.TokenManager(cfg, FakeExchange(), clock=Clock(), rng=lambda: 0.0)
    assert m.step() == pytest.approx(0.5)


def test_vault_http_request(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _reply(self, body: bytes) -> None:
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            seen.append(
                {"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}
            )
            self._reply(b"not json" if self.path.endswith("/text") else b'{"data": {"token": "t"}}')

        def do_POST(self) -> None:
            length = int(self.headers.get("content-length") or 0)
            seen.append({"path": self.path, "body": json.loads(self.rfile.read(length))})
            self._reply(b"")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = wb.BrokerConfig(
            federation_rule_id="r",
            organization_id="o",
            service_account_id="s",
            vault_addr=f"http://127.0.0.1:{server.server_address[1]}",
        )
        request = wb.vault_http_request(cfg, timeout=5)
        vault_token = secrets.token_urlsafe(16)
        assert request("GET", VAULT_OIDC_PATH, vault_token, None) == (
            200,
            {"data": {"token": "t"}},
        )
        assert seen[0]["path"] == "/v1/" + VAULT_OIDC_PATH
        assert seen[0]["headers"]["x-vault-token"] == vault_token
        assert request("POST", "auth/k8s-test/login", None, {"role": "r"}) == (200, None)
        assert seen[1] == {"path": "/v1/auth/k8s-test/login", "body": {"role": "r"}}
        assert request("GET", "x/text", None, None) == (200, None)
    finally:
        server.shutdown()
        server.server_close()


def test_backoff_survives_a_long_outage(tmp_path: Path) -> None:
    m = wb.TokenManager(_cfg(tmp_path), FakeExchange(), clock=Clock(), rng=lambda: 1.0)
    delays = [m._backoff() for _ in range(1100)]  # past the 2.0**1024 overflow point
    assert max(delays) == pytest.approx(wb.BACKOFF_MAX_S)
    assert delays[-1] == pytest.approx(wb.BACKOFF_MAX_S)


def test_short_token_is_refreshed_before_the_mandatory_margin(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    clock, ex = Clock(), FakeExchange(lifetime=60.0)
    m = wb.TokenManager(cfg, ex, clock=clock)
    _write_assertion(cfg)
    delay = m.step()
    # 80 % would be 48 s, but the token stops being served at 30 s.
    assert delay == pytest.approx(60.0 - wb.MANDATORY_MARGIN_S - wb.REFRESH_BUFFER_S)
    clock.now += delay - 0.1
    assert m.is_valid()
    assert m.step() == pytest.approx(0.1)
    clock.now += 0.1
    _write_assertion(cfg)
    m.step()
    assert len(ex.assertions) == 2
    assert m.is_valid()


def test_lifetime_at_or_below_margin(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    cfg = _cfg(tmp_path)
    m = wb.TokenManager(cfg, FakeExchange(lifetime=wb.MANDATORY_MARGIN_S), clock=Clock())
    _write_assertion(cfg)
    with caplog.at_level(logging.WARNING, logger="aegisx9.wif_broker"):
        assert m.step() == wb.ASSERTION_POLL_S
    assert not m.is_valid()
    assert any(r.getMessage() == "access token lifetime too short" for r in caplog.records)


@pytest.mark.parametrize(
    "lifetime,expected",
    [(3600.0, 2880.0), (120.0, 85.0), (60.0, 25.0), (36.0, wb.ASSERTION_POLL_S)],
)
def test_refresh_delay(tmp_path: Path, lifetime: float, expected: float) -> None:
    m = wb.TokenManager(_cfg(tmp_path), FakeExchange(), clock=Clock())
    assert m.refresh_delay(lifetime) == pytest.approx(expected)
