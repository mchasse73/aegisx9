import importlib.util
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "block_adapter", ROOT / "redteam/garak/block_adapter.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


adapter = _load()

# What the fake gateway answers, keyed by the request's first user message.
REPLIES = {
    "blocked": (
        400,
        {
            "error": {
                "message": "request blocked by encoded_payload (input guard)",
                "type": "invalid_request_error",
            }
        },
    ),
    "bad": (400, {"error": {"message": "unknown model", "type": "invalid_request_error"}}),
    "limited": (429, {"error": {"message": "rate limited"}}),
    "ok": (200, {"choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}}]}),
    "redirect": (307, {"error": {"message": "moved"}}),
}


class _Gateway(BaseHTTPRequestHandler):
    seen_auth: ClassVar[list[str | None]] = []

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Gateway.seen_auth.append(self.headers.get("Authorization"))
        prompt = body["messages"][0]["content"]
        status, reply = REPLIES[prompt]
        payload = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if prompt == "redirect":
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
        if prompt == "limited":
            self.send_header("Retry-After", "3")
            self.send_header("x-ratelimit-remaining-requests", "0")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _serve(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


@pytest.fixture
def proxy() -> Iterator[ModuleType]:
    gateway = ThreadingHTTPServer(("127.0.0.1", 0), _Gateway)
    _serve(gateway)
    server = adapter.Adapter(("127.0.0.1", 0), f"http://127.0.0.1:{gateway.server_address[1]}/")
    _serve(server)
    yield server
    server.shutdown()
    gateway.shutdown()


def _call(server: object, prompt: str, auth: str) -> tuple[int, dict]:  # type: ignore[type-arg]
    port = server.server_address[1]  # type: ignore[attr-defined]
    body = json.dumps({"model": "m1", "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": auth},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_a_guard_block_becomes_a_scoreable_completion(proxy) -> None:
    status, body = _call(proxy, "blocked", "Bearer x")
    assert status == 200
    assert body["model"] == "m1"
    content = body["choices"][0]["message"]["content"]
    assert content == (
        "[BLOCKED] I can't assist with that: request blocked by encoded_payload (input guard)"
    )


@pytest.mark.parametrize(
    ("prompt", "status"), [("bad", 400), ("limited", 429), ("ok", 200), ("redirect", 307)]
)
def test_everything_else_passes_through(proxy, prompt: str, status: int) -> None:
    got, body = _call(proxy, prompt, "Bearer x")
    assert got == status
    assert body == REPLIES[prompt][1]


def test_forwards_the_callers_authorization_and_counts(proxy) -> None:
    import secrets

    auth = f"Bearer {secrets.token_urlsafe(16)}"
    _Gateway.seen_auth.clear()
    for prompt in ("blocked", "blocked", "limited", "ok"):
        _call(proxy, prompt, auth)
    assert _Gateway.seen_auth == [auth] * 4
    assert dict(proxy.counts) == {"blocked": 2, "status_429": 1, "status_200": 1}


def test_unreachable_upstream_is_a_502(tmp_path: Path) -> None:
    server = adapter.Adapter(("127.0.0.1", 0), "http://127.0.0.1:9")
    _serve(server)
    try:
        status, _ = _call(server, "ok", "Bearer x")
    finally:
        server.shutdown()
    assert status == 502
    assert list(server.counts) == ["upstream_URLError"]


def test_refusal_phrase_is_one_mitigation_bypass_knows() -> None:
    # garak's MitigationBypass (dan probes) passes an output only when it holds a known
    # refusal phrase; "I can't assist" is on its list (garak 0.17.1 detectors/mitigation.py).
    assert "I can't assist" in adapter.completion("request blocked by x", "m").decode()


@pytest.mark.parametrize(
    "headers",
    [
        {"Transfer-Encoding": "chunked"},
        {"Content-Length": "-1"},
        {"Content-Length": "lots"},
        {"Content-Length": str(2 * 1024 * 1024)},
    ],
)
def test_bad_framing_is_refused(proxy, headers: dict[str, str]) -> None:
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", proxy.server_address[1], timeout=10)
    conn.putrequest("POST", "/v1/chat/completions", skip_accept_encoding=True)
    for k, v in headers.items():
        conn.putheader(k, v)
    conn.endheaders()
    assert conn.getresponse().status in (400, 411)
    conn.close()


# A leading "//" is collapsed to "/" by http.server itself (Python 3.12), so it stays on the
# upstream host; "@host" is the case the adapter must refuse.
@pytest.mark.parametrize("path", ["@attacker.invalid/x"])
def test_path_cannot_change_the_upstream_host(proxy, path: str) -> None:
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", proxy.server_address[1], timeout=10)
    conn.request("POST", path, body=b"{}", headers={"Content-Type": "application/json"})
    assert conn.getresponse().status == 400
    conn.close()


def test_rate_limit_headers_are_passed_back(proxy) -> None:
    port = proxy.server_address[1]
    body = json.dumps(
        {"model": "m1", "messages": [{"role": "user", "content": "limited"}]}
    ).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/chat/completions", data=body)
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(req, timeout=10)  # noqa: S310
    assert caught.value.headers.get("Retry-After") == "3"
    assert caught.value.headers.get("x-ratelimit-remaining-requests") == "0"


def test_upstream_must_be_http() -> None:
    with pytest.raises(ValueError):
        adapter.Adapter(("127.0.0.1", 0), "file:///etc/passwd")


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (400, b'{"error": {"message": "request blocked by x"}}', "request blocked by x"),
        (
            403,
            b'{"error": {"message": "Exception: request blocked by x"}}',
            "Exception: request blocked by x",
        ),
        (400, b'{"error": {"message": "nope"}}', None),
        (400, b'{"error": "request blocked by x"}', None),
        (400, b"not json", None),
        (400, b"[]", None),
        (500, b'{"error": {"message": "request blocked by x"}}', None),
    ],
)
def test_blocked_message(status: int, body: bytes, expected: str | None) -> None:
    assert adapter.blocked_message(status, body) == expected
