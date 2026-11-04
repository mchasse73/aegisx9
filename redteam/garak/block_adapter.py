"""Loopback adapter that lets garak score a guard block (#188).

A guard block answers HTTP 400 ``request blocked by …`` (#171). garak's OpenAI-compatible
generator treats any 4xx as a failed call and records no output, and its detectors skip
attempts with no output, so every block disappeared from the score. This adapter sits
between garak and the gateway on 127.0.0.1:

* a 4xx whose error message contains ``request blocked by`` (the rule promptfoo's transform
  uses) becomes a 200 chat completion: ``[BLOCKED] I can't assist with that: <message>``.
  The refusal phrase matters: garak's MitigationBypass detector (the dan probes) counts an
  output with no known refusal phrase as a jailbreak. The other detectors look for the
  payload, which the block message never contains;
* a 200 whose answer is empty or null (a refusal can be) gets the content
  ``[EMPTY:<finish_reason>] I can't assist with that``: garak skips a None output, which left
  those attempts unscored (#191), and an empty answer reproduces nothing;
* every other response (2xx, 401, 429, 5xx, any other 400) passes through unchanged, with its
  rate-limit headers, so a broken gateway still fails the gate.

Requests are forwarded as-is (the caller's Authorization header included) and never logged;
errors are counted and printed by type name only. On exit it writes counts only (blocked /
passed through, by status) to ``--stats``.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

BLOCK_MARKER = "request blocked by"
REFUSAL = "I can't assist with that"
MAX_BODY = 1024 * 1024
UPSTREAM_TIMEOUT = 120
_FORWARDED = ("Authorization", "Content-Type", "Accept")
# Passed back on responses that aren't blocks, so garak's client backs off as the gateway asks.
_RETURNED = ("retry-after", "retry-after-ms")
_RETURNED_PREFIX = "x-ratelimit-"


def blocked_message(status: int, body: bytes) -> str | None:
    """The guard's block message when ``body`` is a guard block, else None."""
    if not 400 <= status < 500:
        return None
    try:
        error = json.loads(body).get("error")
    except (ValueError, AttributeError):
        return None
    message = error.get("message") if isinstance(error, dict) else None
    if isinstance(message, str) and BLOCK_MARKER in message:
        return message
    return None


def completion(message: str, model: str) -> bytes:
    return json.dumps(
        {
            "id": "aegisx9-blocked",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": f"[BLOCKED] {REFUSAL}: {message}"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
    ).encode()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Hand a redirect back to garak as-is: urllib would follow it with the caller's
    Authorization header, even to another origin."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fill_empty_answer(payload: bytes) -> tuple[bytes, str] | None:
    """When a completion's first answer is empty, the payload with a refusal in its place."""
    try:
        reply = json.loads(payload)
        choice = reply["choices"][0]
        message = choice["message"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    if not isinstance(message, dict) or message.get("content"):
        return None
    if message.get("tool_calls") or message.get("function_call"):
        return None  # a tool call is an answer, and may be the jailbreak
    reason = str(choice.get("finish_reason") or "none")
    message["content"] = f"[EMPTY:{reason}] {REFUSAL}"
    return json.dumps(reply).encode(), reason


def _model_of(body: bytes) -> str:
    try:
        model = json.loads(body).get("model", "")
    except (ValueError, AttributeError):
        return ""
    return model if isinstance(model, str) else ""


class Adapter(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], upstream: str) -> None:
        if not upstream.startswith(("http://", "https://")):
            raise ValueError("the upstream must be an http(s) URL")
        super().__init__(address, _Handler)
        self.upstream = upstream.rstrip("/")
        self.counts: Counter[str] = Counter()
        self._lock = threading.Lock()

    def count(self, key: str) -> None:
        with self._lock:
            self.counts[key] += 1

    def handle_error(self, request: object, client_address: object) -> None:
        # The default prints a traceback, which can carry URLs; type names only (rule 4).
        error = sys.exc_info()[1]
        name = type(error).__name__ if error else "unknown"
        self.count(f"handler_{name}")
        print(f"block adapter: request failed ({name})", file=sys.stderr)


class _Handler(BaseHTTPRequestHandler):
    server: Adapter

    def log_message(self, format: str, *args: Any) -> None:
        return  # never log requests: paths and headers can carry tokens

    def _forward(self) -> None:
        # Only a path on the upstream: "@host/x" would otherwise make upstream+path a URL
        # whose userinfo is the gateway and whose host is someone else's.
        if not self.path.startswith("/") or self.path.startswith("//"):
            self._reply(400, b'{"error":{"message":"bad path for the adapter"}}')
            return
        if self.headers.get("Transfer-Encoding"):
            self._reply(411, b'{"error":{"message":"the adapter needs Content-Length"}}')
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            self._reply(400, b'{"error":{"message":"bad Content-Length for the adapter"}}')
            return
        body = self.rfile.read(length) if length else None
        headers = {h: v for h in _FORWARDED if (v := self.headers.get(h))}
        url = self.server.upstream + self.path  # the scheme is checked in Adapter.__init__
        request = urllib.request.Request(url, data=body, headers=headers, method=self.command)  # noqa: S310
        try:
            with _OPENER.open(request, timeout=UPSTREAM_TIMEOUT) as response:
                status, payload, upstream_headers = (
                    response.status,
                    response.read(),
                    response.headers,
                )
        except urllib.error.HTTPError as e:
            try:
                status, payload, upstream_headers = e.code, e.read(), e.headers
            except Exception as read_error:  # counted by type, never printed
                self._upstream_failed(read_error)
                return
        except Exception as e:  # URLError, IncompleteRead, timeouts: by type only
            self._upstream_failed(e)
            return
        message = blocked_message(status, payload)
        if message is not None:
            self.server.count("blocked")
            self._reply(200, completion(message, _model_of(body or b"")))
            return
        if status == 200 and (filled := fill_empty_answer(payload)) is not None:
            payload, reason = filled
            self.server.count(f"empty_{reason}")
        else:
            self.server.count(f"status_{status}")
        extra = {
            k: v
            for k, v in upstream_headers.items()
            if k.lower() in _RETURNED or k.lower().startswith(_RETURNED_PREFIX)
        }
        ctype = upstream_headers.get("Content-Type", "application/json")
        self._reply(status, payload, ctype, extra)

    def _upstream_failed(self, error: BaseException) -> None:
        self.server.count(f"upstream_{type(error).__name__}")
        self._reply(502, b'{"error":{"message":"upstream unreachable"}}')

    def _reply(
        self,
        status: int,
        payload: bytes,
        ctype: str = "application/json",
        extra: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    do_POST = _forward
    do_GET = _forward


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--upstream-env", default="AEGIS_STAGING_URL", help="variable holding the gateway URL"
    )
    ap.add_argument("--port-file", type=Path, required=True, help="the chosen port is written here")
    ap.add_argument("--stats", type=Path, required=True, help="counts are written here on exit")
    args = ap.parse_args()
    upstream = os.environ.get(args.upstream_env, "")
    if not upstream:
        print(f"{args.upstream_env} must be set", file=sys.stderr)
        return 2
    server = Adapter(("127.0.0.1", 0), upstream)

    def stop(signum: int, frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    args.port_file.write_text(str(server.server_address[1]), encoding="utf-8")
    try:
        server.serve_forever()
    finally:
        args.stats.write_text(json.dumps(dict(sorted(server.counts.items()))), encoding="utf-8")
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
