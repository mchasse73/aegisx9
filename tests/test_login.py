"""Tests for the developer login CLI (aegisx9.login)."""

from __future__ import annotations

import base64
import hashlib
import secrets
import socket
import stat
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from aegisx9 import login

ISSUER = "https://idp.example.com/application/o/gateway/"


def _discovery(**overrides: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "issuer": ISSUER,
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "code_challenge_methods_supported": ["S256"],
    }
    doc.update(overrides)
    return doc


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_pkce_pair_is_s256() -> None:
    verifier, challenge = login.pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    assert challenge == expected.decode()
    assert 43 <= len(verifier) <= 128


def test_discover_returns_endpoints() -> None:
    seen: list[str] = []

    def fetch(req: urllib.request.Request) -> dict[str, Any]:
        seen.append(req.full_url)
        return _discovery()

    ep = login.discover(ISSUER, fetch)
    assert ep == login.Endpoints(
        "https://idp.example.com/authorize", "https://idp.example.com/token"
    )
    assert seen == [ISSUER.rstrip("/") + "/.well-known/openid-configuration"]


@pytest.mark.parametrize(
    "issuer, doc",
    [
        ("http://idp.example.com/", _discovery()),
        (ISSUER, _discovery(issuer="https://other.example.com/")),
        (ISSUER, _discovery(**{"token_endpoint": "http://idp.example.com/token"})),
        (ISSUER, _discovery(authorization_endpoint="")),
        (ISSUER, _discovery(code_challenge_methods_supported=["plain"])),
    ],
    ids=["http-issuer", "issuer-mismatch", "http-token", "no-authorize", "no-s256"],
)
def test_discover_rejects(issuer: str, doc: dict[str, Any]) -> None:
    with pytest.raises(login.LoginError):
        login.discover(issuer, lambda _req: doc)


def test_authorization_url_has_pkce_and_state() -> None:
    ep = login.Endpoints("https://idp.example.com/authorize?x=1", "https://idp.example.com/token")
    url = login.authorization_url(ep, "cid", "http://127.0.0.1:8250", "openid", "st", "ch")
    parsed = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qs(parsed.query)
    assert q["x"] == ["1"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == ["ch"]
    assert q["state"] == ["st"]
    assert q["redirect_uri"] == ["http://127.0.0.1:8250"]


def test_exchange_code_posts_verifier() -> None:
    token = secrets.token_urlsafe(24)
    captured: dict[str, Any] = {}

    def fetch(req: urllib.request.Request) -> dict[str, Any]:
        captured["method"] = req.get_method()
        captured["body"] = urllib.parse.parse_qs((req.data or b"").decode())
        return {"access_token": token, "token_type": "Bearer", "expires_in": 900}

    ep = login.Endpoints("https://idp.example.com/a", "https://idp.example.com/t")
    got, lifetime = login.exchange_code(ep, "cid", "http://127.0.0.1:8250", "c0de", "ver", fetch)
    assert (got, lifetime) == (token, 900)
    assert captured["method"] == "POST"
    assert captured["body"]["code_verifier"] == ["ver"]
    assert captured["body"]["grant_type"] == ["authorization_code"]


@pytest.mark.parametrize(
    "response",
    [{"token_type": "Bearer"}, {"access_token": "x", "token_type": "mac"}],
    ids=["no-token", "not-bearer"],
)
def test_exchange_code_rejects(response: dict[str, Any]) -> None:
    ep = login.Endpoints("https://idp.example.com/a", "https://idp.example.com/t")
    with pytest.raises(login.LoginError):
        login.exchange_code(ep, "cid", "http://127.0.0.1:1", "c", "v", lambda _r: response)


def test_write_token_is_0600(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "token"
    value = secrets.token_urlsafe(24)
    login.write_token(target, value)
    login.write_token(target, value)  # replace works
    assert target.read_text() == value
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [p.name for p in target.parent.iterdir()] == ["token"]


def _callback(port: int, query: str, out: dict[str, int]) -> None:
    for _ in range(50):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/?{query}", timeout=5) as r:
                out["status"] = r.status
            return
        except urllib.error.HTTPError as e:
            out["status"] = e.code
            return
        except OSError:
            threading.Event().wait(0.05)


def test_wait_for_code_accepts_matching_state() -> None:
    port, state, out = _free_port(), secrets.token_urlsafe(8), {}
    server = login.CallbackServer(port, state)
    t = threading.Thread(target=_callback, args=(port, f"state={state}&code=abc", out))
    t.start()
    assert login.wait_for_code(server, 10) == "abc"
    t.join()
    assert out["status"] == 200


@pytest.mark.parametrize(
    "query", ["state={s}&error=access_denied", "state={s}"], ids=["idp-error", "no-code"]
)
def test_wait_for_code_rejects(query: str) -> None:
    port, state, out = _free_port(), secrets.token_urlsafe(8), {}
    server = login.CallbackServer(port, state)
    t = threading.Thread(target=_callback, args=(port, query.format(s=state), out))
    t.start()
    with pytest.raises(login.LoginError):
        login.wait_for_code(server, 10)
    t.join()
    assert out["status"] == 400


def test_stray_and_silent_requests_do_not_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(login._CallbackHandler, "timeout", 0.3)
    port, state = _free_port(), secrets.token_urlsafe(8)
    server = login.CallbackServer(port, state)
    silent = socket.create_connection(("127.0.0.1", port))  # sends nothing
    stray: dict[str, int] = {}
    real: dict[str, int] = {}

    def clients() -> None:
        _callback(port, "state=wrong&code=evil", stray)
        _callback(port, f"state={state}&code=good", real)

    t = threading.Thread(target=clients)
    t.start()
    try:
        assert login.wait_for_code(server, 10) == "good"
    finally:
        silent.close()
        t.join()
    assert stray["status"] == 404
    assert real["status"] == 200


def test_wait_for_code_times_out() -> None:
    with pytest.raises(login.LoginError):
        login.wait_for_code(login.CallbackServer(_free_port(), "s"), 0.2)


@pytest.mark.parametrize("port", [0, 70000])
def test_callback_port_range(port: int) -> None:
    with pytest.raises(login.LoginError):
        login.CallbackServer(port, "s")


@pytest.mark.parametrize(
    "value, expected",
    [(900, 900), ("900", 900), (899.7, 899), (True, 0), (float("inf"), 0), (None, 0), (-5, 0)],
    ids=["int", "str", "float", "bool", "inf", "none", "negative"],
)
def test_lifetime(value: Any, expected: int) -> None:
    assert login._lifetime(value) == expected


def test_fetch_refuses_plain_http() -> None:
    with pytest.raises(login.LoginError):
        login._fetch_json(urllib.request.Request("http://idp.example.com/x"))


def test_redirects_are_refused() -> None:
    handler = login._NoRedirect()
    with pytest.raises(login.LoginError):
        handler.redirect_request(None, None, 302, "Found", {}, "http://idp.example.com/")


def test_write_token_tightens_existing_dir(tmp_path: Path) -> None:
    parent = tmp_path / "aegisx9"
    parent.mkdir(mode=0o755)
    login.write_token(parent / "token", secrets.token_urlsafe(8))
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700


def test_main_requires_issuer_and_client(capsys: pytest.CaptureFixture[str]) -> None:
    assert login.main([], env={}) == 2


def test_main_reports_type_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_issuer: str) -> login.Endpoints:
        raise login.LoginError("https://idp.example.com/?code=leak")

    monkeypatch.setattr(login, "discover", boom)
    assert login.main(["--issuer", ISSUER, "--client-id", "cid"], env={}) == 1
    err = capsys.readouterr().err
    assert "LoginError" in err
    assert "leak" not in err


def test_main_happy_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    token = secrets.token_urlsafe(24)
    ep = login.Endpoints("https://idp.example.com/a", "https://idp.example.com/t")
    monkeypatch.setattr(login, "discover", lambda _i: ep)
    monkeypatch.setattr(login, "wait_for_code", lambda server, _t: server.server_close() or "code")
    monkeypatch.setattr(login, "exchange_code", lambda *_a: (token, 900))
    target = tmp_path / "token"
    rc = login.main(
        [
            "--issuer",
            ISSUER,
            "--client-id",
            "cid",
            "--no-browser",
            "--token-file",
            str(target),
            "--port",
            str(_free_port()),
        ],
        env={},
    )
    assert rc == 0
    assert target.read_text() == token
    captured = capsys.readouterr()
    assert token not in captured.err + captured.out
    assert "valid 900 s" in captured.err
