"""Short-lived JWT authentication sidecar in front of the LiteLLM proxy (ADR 0010).

LiteLLM's own JWT auth is an Enterprise feature, so the gateway authenticates OIDC JWTs
here. The sidecar owns the pod's service port; LiteLLM listens on loopback only. Per request:

* A caller credential (``Authorization: Bearer``, ``x-api-key`` or ``x-litellm-api-key``)
  that is not JWT-shaped is forwarded unchanged, so LiteLLM's own auth judges master and
  virtual keys exactly as before.
* A JWT-shaped credential is verified (``aegisx9.auth``). A valid one is exchanged for a
  LiteLLM virtual key that expires with the token: the caller is enrolled in its team once,
  then a key is minted for the token's remaining lifetime and cached by the token's digest.
  Every caller credential header is replaced by that key before the request is forwarded.
  JWT callers may use inference routes only (``JWT_ROUTES``); anything else is a 403.
* Anything that goes wrong fails closed: an invalid token is a generic 401 and an
  unreachable or refusing admin API a generic 503. Logs carry reason codes only.

Security properties:

* The master key is used only on the two admin calls (``/team/member_add`` and
  ``/key/generate``) and never on a caller's request. Virtual keys live in memory only.
  Neither is ever logged; tokens, headers, bodies and query strings are never logged either.
* Client-supplied forwarding headers are dropped and ``x-forwarded-for`` is set to the
  real peer address, so LiteLLM's IP rules can't be spoofed through the sidecar.
* Chunked request bodies (411), protocol upgrades (501) and bodies over the limit (413) are
  refused before anything reaches LiteLLM. Bodies are streamed, never buffered; idle
  clients time out and concurrent connections are capped.

Standard library plus ``aegisx9.auth``; nothing here imports LiteLLM.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import signal
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import FrameType
from typing import Any, Final
from urllib.parse import urlsplit

from aegisx9 import __version__
from aegisx9.auth import (
    CONFIG_ENV,
    MAX_LIFETIME_S,
    AuthConfigError,
    AuthError,
    Principal,
    Verifier,
    load_verifier,
    looks_like_jwt,
)
from aegisx9.wif_broker import CHUNK_BYTES, configure_logging

DEFAULT_LISTEN_HOST: Final = "0.0.0.0"  # noqa: S104 - the sidecar owns the pod's service port
DEFAULT_LISTEN_PORT: Final = 4000
DEFAULT_UPSTREAM: Final = "http://127.0.0.1:4001"
# Bodies are streamed to LiteLLM, never buffered, so this bounds the request, not memory.
DEFAULT_MAX_BODY_BYTES: Final = 64 * 1024 * 1024
# A client that sends nothing for this long is dropped (slowloris); it also bounds a
# single write to a client that stopped reading.
CLIENT_TIMEOUT_S: Final = 60.0
# Connections served at once; more are closed straight away instead of queueing threads.
MAX_CONNECTIONS: Final = 256
# LiteLLM is reachable on IPv4 loopback only; anything else would send the master key
# (admin calls) or callers' traffic off the pod.
UPSTREAM_HOSTS: Final = frozenset({"127.0.0.1"})
UPSTREAM_TIMEOUT_S: Final = 600.0
ADMIN_TIMEOUT_S: Final = 10.0
MAX_ADMIN_RESPONSE_BYTES: Final = 1024 * 1024
KEY_CACHE_MAX: Final = 10_000
ENROL_TTL_S: Final = 600.0
# Exchanges for one (user, team) are serialised on one of these locks; a fixed set keeps
# memory bounded however many callers there are.
LOCK_STRIPES: Final = 64
TEAM_MEMBER_ADD_PATH: Final = "/team/member_add"
KEY_GENERATE_PATH: Final = "/key/generate"
ALREADY_IN_TEAM_TYPE: Final = "team_member_already_in_team"
BODY_METHODS: Final = frozenset({"POST", "PUT", "PATCH"})
# The only routes a JWT caller may use: inference and the model list. Management routes
# (/key/*, /user/*, /team/*, ...) are refused before a key is minted, so a short-lived
# token can never be turned into a longer-lived credential. Exact match on the raw path:
# encoded or otherwise unusual spellings are refused too.
JWT_ROUTES: Final = frozenset(
    {
        "/v1/chat/completions",
        "/chat/completions",
        "/v1/completions",
        "/completions",
        "/v1/embeddings",
        "/embeddings",
        "/v1/messages",
        "/v1/messages/count_tokens",
        "/v1/models",
        "/models",
    }
)
# A key must live at least this long to be worth minting; a token closer to its exp
# (accepted within the verifier's clock-skew leeway) is refused instead.
MIN_KEY_LIFETIME_S: Final = 5
# A cached key is dropped this long before LiteLLM expires it, so the sidecar never
# forwards a key LiteLLM has already expired.
KEY_EXPIRY_MARGIN_S: Final = 2

# Where a caller's credential is looked for (case-insensitive).
CREDENTIAL_HEADERS: Final = ("authorization", "x-api-key", "x-litellm-api-key")
# Every header LiteLLM may read a credential from; all are dropped once a JWT is exchanged.
STRIPPED_CREDENTIAL_HEADERS: Final = frozenset({*CREDENTIAL_HEADERS, "api-key", "x-goog-api-key"})
HOP_BY_HOP_HEADERS: Final = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
# Also never forwarded: the length (recomputed), Expect (answered here) and client-supplied
# forwarding headers (x-forwarded-for is set from the real peer).
STRIPPED_REQUEST_HEADERS: Final = HOP_BY_HOP_HEADERS | {
    "content-length",
    "expect",
    "forwarded",
    "x-forwarded-for",
    "x-real-ip",
}
# The sidecar's own response line already carries Server and Date.
STRIPPED_RESPONSE_HEADERS: Final = HOP_BY_HOP_HEADERS | {"content-length", "date", "server"}

logger = logging.getLogger("aegisx9.auth_proxy")


class ProxyConfigError(ValueError):
    """The sidecar's environment is invalid. The message starts with the variable's name
    and never contains a value; ``variable`` is that name, the only part that is logged."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.variable = message.split(" ", 1)[0]


class TokenExpiringError(Exception):
    """The token is valid but has less than ``MIN_KEY_LIFETIME_S`` left: nothing to mint."""


class BackendError(Exception):
    """LiteLLM's admin API could not enrol a caller or mint a key. ``reason`` is safe to log."""

    def __init__(self, reason: str, status: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class ProxyConfig:
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 4001
    listen_host: str = DEFAULT_LISTEN_HOST
    listen_port: int = DEFAULT_LISTEN_PORT
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    # Peers whose X-Forwarded-For is kept (the ingress); every other peer's is replaced.
    trusted_proxies: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    master_key: str | None = field(default=None, repr=False)
    upstream_timeout_s: float = UPSTREAM_TIMEOUT_S
    client_timeout_s: float = CLIENT_TIMEOUT_S
    admin_timeout_s: float = ADMIN_TIMEOUT_S

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> ProxyConfig:
        host, port = _parse_upstream(env.get("AEGISX9_AUTH_UPSTREAM", DEFAULT_UPSTREAM))
        listen_host = env.get("AEGISX9_AUTH_LISTEN_HOST", DEFAULT_LISTEN_HOST).strip()
        if not listen_host:
            raise ProxyConfigError("AEGISX9_AUTH_LISTEN_HOST must not be empty")
        listen_port = _int_env(env, "AEGISX9_AUTH_LISTEN_PORT", DEFAULT_LISTEN_PORT)
        if not 0 < listen_port < 65536:
            raise ProxyConfigError("AEGISX9_AUTH_LISTEN_PORT must be 1..65535")
        max_body = _int_env(env, "AEGISX9_AUTH_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)
        if max_body <= 0:
            raise ProxyConfigError("AEGISX9_AUTH_MAX_BODY_BYTES must be positive")
        trusted = _networks(env, "AEGISX9_AUTH_TRUSTED_PROXIES")
        master_key = env.get("LITELLM_MASTER_KEY", "").strip() or None
        if env.get(CONFIG_ENV, "").strip() and master_key is None:
            # Without it no virtual key can be minted: every JWT would fail at runtime.
            raise ProxyConfigError(f"LITELLM_MASTER_KEY is required when {CONFIG_ENV} is set")
        return cls(
            upstream_host=host,
            upstream_port=port,
            listen_host=listen_host,
            listen_port=listen_port,
            max_body_bytes=max_body,
            trusted_proxies=trusted,
            master_key=master_key,
        )


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    # int() would also accept "+1", "1_0" and non-ASCII digits.
    if not (raw.isascii() and raw.isdigit()):
        raise ProxyConfigError(f"{name} must be a whole number")
    return int(raw)


def _networks(
    env: Mapping[str, str], name: str
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    try:
        return tuple(
            ipaddress.ip_network(part.strip())
            for part in env.get(name, "").split(",")
            if part.strip()
        )
    except ValueError:
        raise ProxyConfigError(f"{name} must be a comma-separated list of CIDRs") from None


def _parse_upstream(url: str) -> tuple[str, int]:
    name = "AEGISX9_AUTH_UPSTREAM"
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        raise ProxyConfigError(f"{name} is not a valid URL") from None
    if (
        parts.scheme != "http"
        or parts.hostname not in UPSTREAM_HOSTS
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise ProxyConfigError(f"{name} must be http://127.0.0.1[:port]")
    return "127.0.0.1", port or 80


# -- virtual-key exchange ----------------------------------------------------------------

AdminPost = Callable[[str, Mapping[str, Any]], tuple[int, Any]]


def admin_client(cfg: ProxyConfig) -> AdminPost:
    """Return a callable performing one LiteLLM admin call with the master key:
    (path, json body) -> (status, parsed JSON or None)."""

    def _post(path: str, payload: Mapping[str, Any]) -> tuple[int, Any]:
        conn = http.client.HTTPConnection(
            cfg.upstream_host, cfg.upstream_port, timeout=cfg.admin_timeout_s
        )
        try:
            conn.request(
                "POST",
                path,
                body=json.dumps(payload).encode(),
                headers={
                    "authorization": f"Bearer {cfg.master_key}",
                    "content-type": "application/json",
                    "accept": "application/json",
                },
            )
            resp = conn.getresponse()
            raw = resp.read(MAX_ADMIN_RESPONSE_BYTES)
        finally:
            conn.close()
        try:
            return resp.status, json.loads(raw) if raw else None
        except ValueError:
            return resp.status, None

    return _post


@dataclass(frozen=True)
class VirtualKey:
    value: str = field(repr=False)  # never logged, never written anywhere
    expires_at: float


def _already_in_team(data: Any) -> bool:
    error = data.get("error") if isinstance(data, dict) else None
    if not isinstance(error, dict):
        return False
    if error.get("type") == ALREADY_IN_TEAM_TYPE:
        return True
    message = error.get("message")
    return isinstance(message, str) and "already in" in message.lower()


class KeyExchanger:
    """Turns a verified JWT into a LiteLLM virtual key that dies with the token.

    * Keys are cached by the token's SHA-256 digest and reused until the token expires.
      Expired entries are evicted on insert and the cache is capped (oldest dropped).
    * A caller is enrolled in its team at most once per ``ENROL_TTL_S`` per process.
    * Exchanges for one (user, team) are serialised, so concurrent first requests with the
      same token enrol and mint once; the admin calls run outside the cache lock.
    """

    def __init__(
        self,
        admin: AdminPost,
        now: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        max_entries: int = KEY_CACHE_MAX,
    ) -> None:
        self._admin = admin
        self._now = now
        self._monotonic = monotonic
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._keys: OrderedDict[str, VirtualKey] = OrderedDict()
        self._enrolled: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._stripes = [threading.Lock() for _ in range(LOCK_STRIPES)]

    def __repr__(self) -> str:
        return f"KeyExchanger(cached={len(self._keys)})"

    def _check_remaining(self, principal: Principal) -> None:
        if principal.expires_at - self._now() < MIN_KEY_LIFETIME_S + KEY_EXPIRY_MARGIN_S:
            raise TokenExpiringError

    def key_for(self, token: str, principal: Principal) -> str:
        self._check_remaining(principal)
        digest = hashlib.sha256(token.encode()).hexdigest()
        cached = self._cached(digest)
        if cached is not None:
            return cached
        member = (principal.user_id, principal.team_id)
        with self._stripes[hash(member) % LOCK_STRIPES]:
            cached = self._cached(digest)  # another request may have minted it meanwhile
            if cached is not None:
                return cached
            self._enrol(member)
            # Waiting for the lock and enrolling take time: check the lifetime again.
            self._check_remaining(principal)
            try:
                key = self._mint(principal)
            except BackendError:
                # The membership may be what LiteLLM refused: enrol again next time.
                with self._lock:
                    self._enrolled.pop(member, None)
                raise
            if self._now() >= key.expires_at:
                # The admin call outlasted the token: never forward a key that has expired.
                raise TokenExpiringError
            self._store(digest, key)
            return key.value

    def _cached(self, digest: str) -> str | None:
        with self._lock:
            entry = self._keys.get(digest)
            if entry is not None and self._now() < entry.expires_at:
                return entry.value
        return None

    def _store(self, digest: str, key: VirtualKey) -> None:
        with self._lock:
            now = self._now()
            for stale in [d for d, k in self._keys.items() if k.expires_at <= now]:
                del self._keys[stale]
            self._keys[digest] = key
            self._keys.move_to_end(digest)
            while len(self._keys) > self._max_entries:
                self._keys.popitem(last=False)

    def _call(self, path: str, payload: Mapping[str, Any], step: str) -> tuple[int, Any]:
        try:
            return self._admin(path, payload)
        except (OSError, http.client.HTTPException):
            raise BackendError(f"{step}_unreachable") from None

    def _enrol(self, member: tuple[str, str]) -> None:
        with self._lock:
            at = self._enrolled.get(member)
            if at is not None and self._monotonic() - at < ENROL_TTL_S:
                return
        user_id, team_id = member
        status, data = self._call(
            TEAM_MEMBER_ADD_PATH,
            {"team_id": team_id, "member": {"user_id": user_id, "role": "user"}},
            "enrol",
        )
        if status != 200 and not _already_in_team(data):
            raise BackendError("enrol_rejected", status)
        with self._lock:
            self._enrolled[member] = self._monotonic()
            self._enrolled.move_to_end(member)
            while len(self._enrolled) > self._max_entries:
                self._enrolled.popitem(last=False)

    def _mint(self, principal: Principal) -> VirtualKey:
        # The key dies with the token and never outlives the 15-minute ceiling, even for a
        # token whose iat is slightly in the future (clock skew).
        started = self._now()
        duration = int(min(principal.expires_at - started, MAX_LIFETIME_S))
        status, data = self._call(
            KEY_GENERATE_PATH,
            {
                "user_id": principal.user_id,
                "team_id": principal.team_id,
                "duration": f"{duration}s",
                "metadata": {"aegisx9_auth": "jwt", "aegisx9_issuer": principal.issuer},
            },
            "mint",
        )
        if status != 200:
            raise BackendError("mint_rejected", status)
        value = data.get("key") if isinstance(data, dict) else None
        if not isinstance(value, str) or not value:
            raise BackendError("mint_invalid", status)
        return VirtualKey(value=value, expires_at=started + duration - KEY_EXPIRY_MARGIN_S)


# -- reverse proxy -----------------------------------------------------------------------


def _error_body(status: int, error_type: str, message: str) -> dict[str, Any]:
    return {"error": {"message": message, "type": error_type, "code": str(status)}}


_BODY_ERRORS: Final = {
    400: "Invalid request body",
    411: "Chunked request bodies are not supported",
    413: "Request body too large",
}


def _connection_tokens(values: list[str] | None) -> set[str]:
    return {t.strip().lower() for v in values or [] for t in v.split(",") if t.strip()}


def make_handler(
    cfg: ProxyConfig, verifier: Verifier | None, exchanger: KeyExchanger | None
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "aegisx9-auth-proxy"
        sys_version = ""
        timeout = cfg.client_timeout_s

        def log_message(self, format: str, *args: Any) -> None:
            """Silence the default access log; ``_handle`` writes a structured one."""

        def _handle(self) -> None:
            started = time.monotonic()
            self._log_fields: dict[str, Any] = {"auth": "none"}
            status = self._serve()
            logger.info(
                "request",
                extra={
                    "fields": {
                        "method": self.command,
                        "path": urlsplit(self.path).path,
                        "status": status,
                        "duration_ms": round((time.monotonic() - started) * 1000, 1),
                        "remote": self.client_address[0],
                        **self._log_fields,
                    }
                },
            )

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle

        def _json(self, status: int, payload: Mapping[str, Any]) -> int:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return status

        def _error(self, status: int, error_type: str, message: str) -> int:
            return self._json(status, _error_body(status, error_type, message))

        def _serve(self) -> int:
            # Origin-form targets only ("/path?query"); absolute-form and "*" are refused.
            # (http.server already collapses a leading "//" to "/".)
            if not self.path.startswith("/"):
                self.close_connection = True
                return self._error(400, "invalid_request_error", "Invalid request target")
            if self.headers.get("upgrade") is not None:
                self.close_connection = True
                return self._error(501, "invalid_request_error", "Protocol upgrades not supported")
            length = self._body_length()
            if length < 0:
                self.close_connection = True
                return self._error(-length, "invalid_request_error", _BODY_ERRORS[-length])
            # The body is read only while forwarding; any earlier answer leaves it unread,
            # so the connection must not be reused (its bytes would parse as a request).
            if length:
                self.close_connection = True
            if self.command == "GET" and urlsplit(self.path).path == "/healthz":
                return self._json(200, {"status": "ok"})
            credentials = self._credentials()
            token = next((c for c in credentials if looks_like_jwt(c)), None)
            virtual_key: str | None = None
            if token is not None:
                self._log_fields["auth"] = "jwt"
                outcome = self._authenticate(token)
                if isinstance(outcome, int):
                    return outcome
                virtual_key = outcome
            elif credentials:
                self._log_fields["auth"] = "key"
            return self._proxy(length, self._forward_headers(virtual_key))

        def _body_length(self) -> int:
            """The declared body length, or minus the status of the error to send."""
            if self.headers.get("transfer-encoding") is not None:
                return -411
            lengths = {v.strip() for v in self.headers.get_all("content-length") or []}
            if not lengths:
                return 0
            raw = lengths.pop()
            # Conflicting duplicates and anything but plain digits are refused (smuggling).
            if lengths or not (raw.isascii() and raw.isdigit()):
                return -400
            length = int(raw)
            return -413 if length > cfg.max_body_bytes else length

        def _credentials(self) -> list[str]:
            found: list[str] = []
            for name in CREDENTIAL_HEADERS:
                for raw in self.headers.get_all(name) or []:
                    value = raw.strip()
                    if name == "authorization":
                        scheme, _, rest = value.partition(" ")
                        if scheme.lower() == "bearer":
                            value = rest.strip()
                    if value:
                        found.append(value)
            return found

        def _authenticate(self, token: str) -> str | int:
            """The virtual key for a JWT, or the status of the error response sent."""
            if verifier is None or exchanger is None:
                logger.warning("jwt rejected", extra={"fields": {"reason": "jwt_disabled"}})
                return self._error(401, "auth_error", "Authentication failed")
            try:
                principal = verifier.verify(token)
            except AuthError as e:
                logger.warning("jwt rejected", extra={"fields": {"reason": e.reason}})
                return self._error(401, "auth_error", "Authentication failed")
            self._log_fields.update(user=principal.user_id, team=principal.team_id)
            if urlsplit(self.path).path not in JWT_ROUTES:
                logger.warning("jwt rejected", extra={"fields": {"reason": "route"}})
                return self._error(403, "auth_error", "Route not allowed")
            try:
                return exchanger.key_for(token, principal)
            except TokenExpiringError:
                logger.warning("jwt rejected", extra={"fields": {"reason": "expired"}})
                return self._error(401, "auth_error", "Authentication failed")
            except BackendError as e:
                logger.warning(
                    "jwt exchange failed",
                    extra={"fields": {"reason": e.reason, "upstream_status": e.status}},
                )
                return self._error(503, "auth_error", "Authentication backend unavailable")

        def _forward_headers(self, virtual_key: str | None) -> list[tuple[str, str]]:
            # Headers named in Connection are hop-by-hop too (RFC 9110 7.6.1).
            listed = _connection_tokens(self.headers.get_all("connection"))
            out: list[tuple[str, str]] = []
            for name, value in self.headers.items():
                lower = name.lower()
                if lower in STRIPPED_REQUEST_HEADERS or lower in listed:
                    continue
                if virtual_key is not None and lower in STRIPPED_CREDENTIAL_HEADERS:
                    continue
                out.append((name, value))
            if virtual_key is not None:
                out.append(("authorization", f"Bearer {virtual_key}"))
            peer = self.client_address[0]
            chain = [v.strip() for v in self.headers.get_all("x-forwarded-for") or [] if v.strip()]
            if chain and _trusted(peer, cfg.trusted_proxies):
                out.append(("x-forwarded-for", ", ".join([*chain, peer])))
            else:
                out.append(("x-forwarded-for", peer))
            return out

        def _proxy(self, length: int, headers: list[tuple[str, str]]) -> int:
            conn = http.client.HTTPConnection(
                cfg.upstream_host, cfg.upstream_port, timeout=cfg.upstream_timeout_s
            )
            try:
                # Header by header, so repeated headers reach LiteLLM as sent.
                conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                if not any(name.lower() == "host" for name, _ in headers):
                    conn.putheader("host", f"{cfg.upstream_host}:{cfg.upstream_port}")
                for name, value in headers:
                    conn.putheader(name, value)
                if length or self.command in BODY_METHODS:
                    conn.putheader("content-length", str(length))
                conn.endheaders()
                if not self._stream_body(conn, length):
                    conn.close()
                    return self._error(400, "invalid_request_error", _BODY_ERRORS[400])
                resp = conn.getresponse()
            except (OSError, ValueError, http.client.HTTPException) as e:
                conn.close()
                logger.warning(
                    "upstream request failed", extra={"fields": {"error": type(e).__name__}}
                )
                return self._error(502, "api_error", "Upstream unavailable")
            try:
                self._relay(resp)
            except (OSError, http.client.HTTPException) as e:
                # Headers are already sent; all that is left is to drop the connection.
                self.close_connection = True
                logger.warning("stream interrupted", extra={"fields": {"error": type(e).__name__}})
            finally:
                conn.close()
            return resp.status

        def _stream_body(self, conn: http.client.HTTPConnection, length: int) -> bool:
            """Copy the body to LiteLLM in chunks; False if the client sent less."""
            remaining = length
            while remaining:
                chunk = self.rfile.read(min(CHUNK_BYTES, remaining))
                if not chunk:
                    return False
                conn.send(chunk)
                remaining -= len(chunk)
            return True

        def _relay(self, resp: http.client.HTTPResponse) -> None:
            length = resp.getheader("content-length")
            chunked = (resp.getheader("transfer-encoding") or "").lower() == "chunked"
            listed = _connection_tokens(resp.headers.get_all("connection"))
            self.send_response(resp.status, resp.reason)
            for name, value in resp.getheaders():
                lower = name.lower()
                if lower not in STRIPPED_RESPONSE_HEADERS and lower not in listed:
                    self.send_header(name, value)
            if length is not None and not chunked:
                self.send_header("content-length", length)
            else:
                # Streaming (SSE) bodies have no length: delimit by closing the connection
                # and pass every chunk through as soon as it arrives.
                self.send_header("connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.flush()
            expected = int(length) if length is not None and length.isdigit() else None
            sent = 0
            while True:
                chunk = resp.read1(CHUNK_BYTES)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                sent += len(chunk)
            if expected is not None and not chunked and sent < expected:
                # LiteLLM closed early: drop the client too instead of leaving it waiting.
                raise http.client.IncompleteRead(b"", expected - sent)

    return Handler


# -- process -----------------------------------------------------------------------------


def _trusted(
    peer: str, networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
) -> bool:
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(address in network for network in networks)


class AuthProxyServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args: Any, max_connections: int = MAX_CONNECTIONS, **kw: Any) -> None:
        super().__init__(*args, **kw)
        self._slots = threading.BoundedSemaphore(max_connections)

    def process_request(self, request: Any, client_address: Any) -> None:
        # Bounded: a flood of (slow) connections can't grow threads and memory without limit.
        if not self._slots.acquire(blocking=False):
            logger.warning("connection refused", extra={"fields": {"reason": "busy"}})
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # The default prints a traceback, and exception text can carry request data.
        logger.error(
            "request handler failed",
            extra={"fields": {"error": type(sys.exc_info()[1]).__name__}},
        )


def build_server(
    cfg: ProxyConfig,
    verifier: Verifier | None,
    exchanger: KeyExchanger | None,
    max_connections: int = MAX_CONNECTIONS,
) -> ThreadingHTTPServer:
    return AuthProxyServer(
        (cfg.listen_host, cfg.listen_port),
        make_handler(cfg, verifier, exchanger),
        max_connections=max_connections,
    )


def main(env: Mapping[str, str] | None = None) -> int:
    configure_logging()
    logger.info("starting", extra={"fields": {"version": __version__}})
    source = os.environ if env is None else env
    try:
        cfg = ProxyConfig.from_env(source)
        verifier = load_verifier(source)
    except (ProxyConfigError, AuthConfigError) as e:
        # Only the exception type and, for the environment, the variable's name. Fail closed.
        fields = {"error": type(e).__name__}
        if isinstance(e, ProxyConfigError):
            fields["variable"] = e.variable
        logger.error("invalid configuration", extra={"fields": fields})
        return 2
    exchanger = KeyExchanger(admin_client(cfg)) if verifier is not None else None
    try:
        server = build_server(cfg, verifier, exchanger)
    except OSError as e:
        logger.error("listen failed", extra={"fields": {"error": type(e).__name__}})
        return 1

    def _shutdown(signum: int, frame: FrameType | None) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    logger.info(
        "listening",
        extra={
            "fields": {
                "host": cfg.listen_host,
                "port": cfg.listen_port,
                "jwt_enabled": verifier is not None,
            }
        },
    )
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()
    server.server_close()
    logger.info("stopped")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
