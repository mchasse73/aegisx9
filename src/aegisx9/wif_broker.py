"""Workload Identity Federation token broker for the Anthropic provider.

Runs as a sidecar in the gateway pod. Before every exchange it obtains a fresh OIDC
identity token (by default from Vault's identity token endpoint, after logging in to Vault
with the pod's Kubernetes service-account token), exchanges it for a short-lived Anthropic
access token (RFC 7523 ``jwt-bearer`` grant on ``POST /v1/oauth/token``), keeps that fresh,
and serves a loopback-only reverse proxy that LiteLLM uses as its Anthropic ``api_base``.
The proxy strips whatever credential LiteLLM sends and injects
``Authorization: Bearer <access token>``, so no Anthropic credential ever exists in
LiteLLM's process, environment or configuration.

Security properties:

* The access token, the Vault token and the identity assertion are held in memory only
  and are never logged or printed. Assertions carrying ``jti`` are single-use, so the
  broker never presents the same assertion twice (it compares SHA-256 digests; with the
  optional file source the last digest can be persisted for restarts).
* Errors are logged by exception type name only.
* Each new identity token's header (only the header) is decoded to read its ``kid``; a key
  id missing from ``AEGISX9_WIF_UPLOADED_KIDS`` (the keys uploaded to the federation
  issuer) is logged as a ``wif_kid_not_uploaded`` event. Key ids are public identifiers.
* Only ``/v1/messages*`` and ``/v1/models*`` are forwarded; anything else is refused.
* Response headers that identify the Anthropic organization are dropped, so they cannot
  surface to gateway callers.

Standard library only: the gateway package has no runtime dependencies of its own.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import http.client
import json
import logging
import os
import random
import re
import signal
import ssl
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import FrameType
from typing import Any, Final
from urllib.parse import urlsplit

from aegisx9 import __version__

GRANT_TYPE: Final = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_PATH: Final = "/v1/oauth/token"  # noqa: S105 - an endpoint path, not a credential
DEFAULT_UPSTREAM: Final = "https://api.anthropic.com"
# Anthropic rejects assertions larger than 16 KiB.
MAX_ASSERTION_BYTES: Final = 16 * 1024
# A token this close to expiry is treated as invalid (the SDKs' "mandatory refresh" margin).
MANDATORY_MARGIN_S: Final = 30.0
# How often the broker looks for a rotated assertion when the current one is already used.
ASSERTION_POLL_S: Final = 2.0
BACKOFF_BASE_S: Final = 1.0
BACKOFF_MAX_S: Final = 60.0
# 2**6 already exceeds BACKOFF_MAX_S; capping the exponent keeps the arithmetic bounded
# however long an outage lasts (2.0 ** 1024 raises OverflowError).
BACKOFF_MAX_EXPONENT: Final = 16
# Refresh at least this long before a token reaches the mandatory margin.
REFRESH_BUFFER_S: Final = 5.0
STATUS_INTERVAL_S: Final = 30.0
# IPv4 loopback only: the listener is an AF_INET ThreadingHTTPServer.
LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1"})
ALLOWED_PATH_PREFIXES: Final = ("/v1/messages", "/v1/models")
ALLOWED_METHODS: Final = frozenset({"GET", "POST"})
CHUNK_BYTES: Final = 64 * 1024
# A key id is logged only when it looks like one (the store uses UUIDs).
KID_PATTERN: Final = re.compile(r"[A-Za-z0-9._:-]{1,128}")
MAX_JWT_HEADER_CHARS: Final = 4096

# Never forwarded upstream: credentials the caller sent, hop-by-hop headers and headers
# http.client sets itself.
STRIPPED_REQUEST_HEADERS: Final = frozenset(
    {
        "authorization",
        "x-api-key",
        "proxy-authorization",
        "cookie",
        "anthropic-dangerous-direct-browser-access",
        "host",
        "content-length",
        "accept-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
# Never returned to LiteLLM (which may relay provider headers to its callers).
STRIPPED_RESPONSE_HEADERS: Final = frozenset(
    {
        "anthropic-organization-id",
        "set-cookie",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)

logger = logging.getLogger("aegisx9.wif_broker")


class BrokerConfigError(ValueError):
    """The broker's environment is incomplete or unsafe. Carries variable names only."""


class AssertionUnavailableError(Exception):
    """No usable identity token: missing, empty, too large or not issued."""


class VaultError(AssertionUnavailableError):
    """Vault refused or failed a login, renewal or identity-token request."""

    def __init__(self, operation: str, status: int | None = None) -> None:
        super().__init__(f"vault {operation} failed" + (f" ({status})" if status else ""))
        self.operation = operation
        self.status = status


class TokenExchangeError(Exception):
    """The token endpoint answered, but not with a usable token."""

    def __init__(self, status: int) -> None:
        super().__init__(f"token exchange failed with HTTP {status}")
        self.status = status


IDENTITY_SOURCES: Final = frozenset({"vault", "file"})
VAULT_OIDC_TOKEN_PREFIX: Final = "identity/oidc/token/"  # noqa: S105 - an API path prefix
DEFAULT_VAULT_JWT_FILE: Final = "/var/run/secrets/vault/token"


@dataclass(frozen=True)
class BrokerConfig:
    federation_rule_id: str
    organization_id: str
    service_account_id: str
    workspace_id: str | None = None
    identity_source: str = "vault"
    identity_token_file: str | None = None
    vault_addr: str = ""
    vault_role: str = ""
    vault_token_path: str = ""
    vault_auth_path: str = ""
    vault_jwt_file: str = DEFAULT_VAULT_JWT_FILE
    vault_cacert: str | None = None
    upstream: str = DEFAULT_UPSTREAM
    listen_host: str = "127.0.0.1"
    listen_port: int = 8787
    refresh_fraction: float = 0.8
    state_file: str | None = None
    # Key ids of the public keys uploaded to the Anthropic federation issuer.
    uploaded_kids: tuple[str, ...] = ()
    upstream_timeout_s: float = 600.0
    max_body_bytes: int = 32 * 1024 * 1024

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> BrokerConfig:
        source = env.get("AEGISX9_WIF_IDENTITY_SOURCE", "vault").strip()
        if source not in IDENTITY_SOURCES:
            raise BrokerConfigError("AEGISX9_WIF_IDENTITY_SOURCE must be vault or file")
        required = {
            "federation_rule_id": "ANTHROPIC_FEDERATION_RULE_ID",
            "organization_id": "ANTHROPIC_ORGANIZATION_ID",
            "service_account_id": "ANTHROPIC_SERVICE_ACCOUNT_ID",
        }
        if source == "vault":
            required |= {
                "vault_addr": "VAULT_ADDR",
                "vault_role": "AEGISX9_VAULT_ROLE",
                "vault_token_path": "AEGISX9_VAULT_TOKEN_PATH",
                "vault_auth_path": "AEGISX9_VAULT_AUTH_PATH",
            }
        else:
            required["identity_token_file"] = "AEGISX9_WIF_IDENTITY_TOKEN_FILE"  # noqa: S105
        missing = sorted(name for name in required.values() if not env.get(name, "").strip())
        if missing:
            raise BrokerConfigError("missing environment variables: " + ", ".join(missing))
        if env.get("ANTHROPIC_API_KEY") or env.get("ANTHROPIC_AUTH_TOKEN"):
            # A static credential would shadow federation in every Anthropic SDK; refuse
            # to run beside one so a leftover key is noticed instead of silently used.
            raise BrokerConfigError("a static Anthropic credential is set; unset it")
        upstream = env.get("AEGISX9_WIF_UPSTREAM", DEFAULT_UPSTREAM).rstrip("/")
        if urlsplit(upstream).scheme != "https":
            raise BrokerConfigError("AEGISX9_WIF_UPSTREAM must be an https URL")
        listen_host = env.get("AEGISX9_WIF_LISTEN_HOST", "127.0.0.1")
        if listen_host not in LOOPBACK_HOSTS:
            raise BrokerConfigError("AEGISX9_WIF_LISTEN_HOST must be 127.0.0.1")
        try:
            listen_port = int(env.get("AEGISX9_WIF_LISTEN_PORT", "8787"))
            refresh_fraction = float(env.get("AEGISX9_WIF_REFRESH_FRACTION", "0.8"))
        except ValueError as e:
            raise BrokerConfigError("listen port or refresh fraction is not a number") from e
        if not 0.1 <= refresh_fraction <= 0.9:
            raise BrokerConfigError("AEGISX9_WIF_REFRESH_FRACTION must be between 0.1 and 0.9")
        vault_addr = env.get("VAULT_ADDR", "").strip().rstrip("/")
        vault_token_path = env.get("AEGISX9_VAULT_TOKEN_PATH", "").strip().strip("/")
        auth_path = env.get("AEGISX9_VAULT_AUTH_PATH", "").strip().strip("/")
        if source == "vault":
            if urlsplit(vault_addr).scheme != "https":
                raise BrokerConfigError("VAULT_ADDR must be an https URL")
            # The broker may only read identity tokens, never arbitrary Vault paths.
            name = vault_token_path.removeprefix(VAULT_OIDC_TOKEN_PREFIX)
            if not vault_token_path.startswith(VAULT_OIDC_TOKEN_PREFIX) or not _safe_segment(name):
                raise BrokerConfigError(
                    "AEGISX9_VAULT_TOKEN_PATH must be identity/oidc/token/<role>"
                )
            if not all(_safe_segment(part) for part in auth_path.split("/")):
                raise BrokerConfigError("AEGISX9_VAULT_AUTH_PATH is not a valid mount path")
        return cls(
            identity_source=source,
            identity_token_file=env.get("AEGISX9_WIF_IDENTITY_TOKEN_FILE", "").strip() or None,
            vault_addr=vault_addr,
            vault_role=env.get("AEGISX9_VAULT_ROLE", "").strip(),
            vault_token_path=vault_token_path,
            vault_auth_path=auth_path,
            vault_jwt_file=env.get("AEGISX9_VAULT_K8S_JWT_FILE", "").strip()
            or DEFAULT_VAULT_JWT_FILE,
            vault_cacert=env.get("VAULT_CACERT", "").strip() or None,
            federation_rule_id=env[required["federation_rule_id"]].strip(),
            organization_id=env[required["organization_id"]].strip(),
            service_account_id=env[required["service_account_id"]].strip(),
            workspace_id=env.get("ANTHROPIC_WORKSPACE_ID", "").strip() or None,
            upstream=upstream,
            listen_host=listen_host,
            listen_port=listen_port,
            refresh_fraction=refresh_fraction,
            state_file=env.get("AEGISX9_WIF_STATE_FILE", "").strip() or None,
            uploaded_kids=tuple(
                dict.fromkeys(
                    k.strip()
                    for k in env.get("AEGISX9_WIF_UPLOADED_KIDS", "").split(",")
                    if k.strip()
                )
            ),
        )


def _safe_segment(value: str) -> bool:
    return (
        bool(value) and all(c.isalnum() or c in "-_." for c in value) and value not in {".", ".."}
    )


def build_exchange_body(cfg: BrokerConfig, assertion: str) -> dict[str, str]:
    """The RFC 7523 request body documented in Anthropic's WIF reference."""
    body = {
        "grant_type": GRANT_TYPE,
        "assertion": assertion,
        "federation_rule_id": cfg.federation_rule_id,
        "organization_id": cfg.organization_id,
        "service_account_id": cfg.service_account_id,
    }
    if cfg.workspace_id:
        body["workspace_id"] = cfg.workspace_id
    return body


def open_connection(
    base_url: str, timeout: float, cafile: str | None = None
) -> http.client.HTTPConnection:
    parts = urlsplit(base_url)
    host = parts.hostname or ""
    if parts.scheme == "https":
        context = ssl.create_default_context(cafile=cafile)
        return http.client.HTTPSConnection(
            host, parts.port or 443, timeout=timeout, context=context
        )
    # Plain HTTP is reachable only through a directly constructed config (tests); from_env
    # refuses it.
    return http.client.HTTPConnection(host, parts.port or 80, timeout=timeout)


Exchange = Callable[[str], tuple[str, float]]


def http_exchange(cfg: BrokerConfig, timeout: float = 30.0) -> Exchange:
    """Return a callable that performs one token exchange and yields (token, expires_in)."""

    def _exchange(assertion: str) -> tuple[str, float]:
        conn = open_connection(cfg.upstream, timeout)
        try:
            payload = json.dumps(build_exchange_body(cfg, assertion)).encode()
            conn.request(
                "POST",
                TOKEN_PATH,
                body=payload,
                headers={"content-type": "application/json", "accept": "application/json"},
            )
            resp = conn.getresponse()
            raw = resp.read(1024 * 1024)
            if resp.status != 200:
                raise TokenExchangeError(resp.status)
            try:
                data = json.loads(raw)
            except ValueError as e:
                raise TokenExchangeError(resp.status) from e
            token = data.get("access_token") if isinstance(data, dict) else None
            expires_in = data.get("expires_in") if isinstance(data, dict) else None
            token_type = data.get("token_type", "Bearer") if isinstance(data, dict) else ""
            if (
                not isinstance(token, str)
                or not token
                or isinstance(expires_in, bool)
                or not isinstance(expires_in, int | float)
                or expires_in <= 0
                or not isinstance(token_type, str)
                or token_type.lower() != "bearer"
            ):
                raise TokenExchangeError(resp.status)
            return token, float(expires_in)
        finally:
            conn.close()

    return _exchange


def jwt_kid(token: str) -> str | None:
    """The ``kid`` from a compact JWT's header, or None when there is none.

    Only the header segment is decoded (base64url, no signature verification): the issuer
    signed it and Anthropic verifies it. The token itself is never logged.
    """
    header = token.split(".", 1)[0]
    if not header or len(header) > MAX_JWT_HEADER_CHARS:
        return None
    try:
        decoded = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
    except (binascii.Error, ValueError):
        return None
    kid = decoded.get("kid") if isinstance(decoded, dict) else None
    return kid if isinstance(kid, str) else None


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass
class TokenManager:
    """Holds the current access token and decides when to exchange a new assertion."""

    cfg: BrokerConfig
    exchange: Exchange
    clock: Callable[[], float] = time.monotonic
    rng: Callable[[], float] = random.random
    # Produces a fresh identity token per exchange; None reads cfg.identity_token_file.
    source: Callable[[], str] | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _token: str | None = field(default=None, repr=False)
    _expires_at: float = 0.0
    _refresh_at: float = 0.0
    _failures: int = 0
    _last_digest: str | None = None
    _invalid_since: float | None = None
    _waiting_logged: bool = False

    def __post_init__(self) -> None:
        self._invalid_since = self.clock()
        self._last_digest = self._load_state()

    def __repr__(self) -> str:
        return f"TokenManager(valid={self.is_valid()})"

    # -- state ---------------------------------------------------------------------------

    def _load_state(self) -> str | None:
        if not self.cfg.state_file:
            return None
        try:
            value = Path(self.cfg.state_file).read_text(encoding="ascii").strip()
        except OSError:
            return None
        return value if len(value) == 64 else None

    def _save_state(self, digest: str | None) -> None:
        if not self.cfg.state_file:
            return
        try:
            path = Path(self.cfg.state_file)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as fh:
                fh.write(digest or "")
        except OSError as e:
            logger.warning("state file not written", extra={"fields": {"error": type(e).__name__}})

    # -- token access --------------------------------------------------------------------

    def current_token(self) -> str | None:
        with self._lock:
            if self._token is not None and self.clock() < self._expires_at - MANDATORY_MARGIN_S:
                return self._token
            return None

    def is_valid(self) -> bool:
        return self.current_token() is not None

    def seconds_invalid(self) -> float:
        valid = self.is_valid()
        with self._lock:
            if valid:
                self._invalid_since = None
                return 0.0
            if self._invalid_since is None:
                self._invalid_since = self.clock()
            return max(0.0, self.clock() - self._invalid_since)

    def seconds_to_expiry(self) -> float:
        with self._lock:
            if self._token is None:
                return 0.0
            return max(0.0, self._expires_at - self.clock())

    # -- refresh -------------------------------------------------------------------------

    def _read_assertion(self) -> str:
        if self.source is not None:
            value = self.source().strip()
            if not value or len(value.encode()) > MAX_ASSERTION_BYTES:
                raise AssertionUnavailableError("identity token empty or too large")
            return value
        if not self.cfg.identity_token_file:
            raise AssertionUnavailableError("no identity token source")
        path = Path(self.cfg.identity_token_file)
        if path.stat().st_size > MAX_ASSERTION_BYTES:
            raise AssertionUnavailableError("identity token too large")
        value = path.read_text(encoding="ascii").strip()
        if not value:
            raise AssertionUnavailableError("identity token empty")
        return value

    def _backoff(self) -> float:
        self._failures += 1
        exponent = min(self._failures - 1, BACKOFF_MAX_EXPONENT)
        delay = min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2.0**exponent))
        # Jitter in [delay/2, delay] so replicas do not retry in lockstep.
        return delay * (0.5 + 0.5 * self.rng())

    def step(self) -> float:
        """Exchange if a refresh is due; return the number of seconds until the next step."""
        now = self.clock()
        with self._lock:
            has_token = self._token is not None
            refresh_at = self._refresh_at
        if has_token and now < refresh_at:
            return refresh_at - now
        try:
            assertion = self._read_assertion()
        except (OSError, UnicodeDecodeError, AssertionUnavailableError) as e:
            logger.warning(
                "identity token unavailable", extra={"fields": {"error": type(e).__name__}}
            )
            return self._backoff()
        digest = _digest(assertion)
        if digest == self._last_digest:
            # Assertions with a jti are single-use: wait for a new one (the file source
            # rotates on the kubelet's schedule) rather than re-presenting this one.
            if not self._waiting_logged:
                logger.info("waiting for a rotated identity token")
                self._waiting_logged = True
            return ASSERTION_POLL_S
        self._waiting_logged = False
        self._last_digest = digest
        self._save_state(digest)
        self._check_kid(assertion)
        try:
            token, expires_in = self.exchange(assertion)
        except TokenExchangeError as e:
            # The endpoint answered, so the assertion may have been consumed; keep it marked.
            logger.warning(
                "token exchange rejected",
                extra={"fields": {"error": type(e).__name__, "status": e.status}},
            )
            return self._backoff()
        except (OSError, http.client.HTTPException, ValueError) as e:
            # No usable answer: allow one more attempt with the same assertion. If the
            # server did record it, the retry is refused and the broker waits for rotation.
            self._last_digest = None
            self._save_state(None)
            logger.warning(
                "token endpoint unreachable", extra={"fields": {"error": type(e).__name__}}
            )
            return self._backoff()
        now = self.clock()
        delay = self.refresh_delay(expires_in)
        with self._lock:
            self._token = token
            self._expires_at = now + expires_in
            self._refresh_at = now + delay
            self._invalid_since = None
        self._failures = 0
        if expires_in <= MANDATORY_MARGIN_S + REFRESH_BUFFER_S:
            logger.warning(
                "access token lifetime too short",
                extra={"fields": {"expires_in_s": int(expires_in)}},
            )
        logger.info("access token acquired", extra={"fields": {"expires_in_s": int(expires_in)}})
        return delay

    def _check_kid(self, assertion: str) -> None:
        """Warn when the identity token is signed by a key the issuer does not know.

        The exchange still goes ahead (Anthropic refuses it anyway); the structured
        ``wif_kid_not_uploaded`` line is what the alert rules key on. Key ids are public.
        """
        if not self.cfg.uploaded_kids:
            return
        kid = jwt_kid(assertion)
        if kid is not None and kid in self.cfg.uploaded_kids:
            return
        safe = kid if kid is not None and KID_PATTERN.fullmatch(kid) else None
        logger.warning(
            "identity token signed by a key not uploaded to the federation issuer",
            extra={"fields": {"event": "wif_kid_not_uploaded", "kid": safe}},
        )

    def refresh_delay(self, expires_in: float) -> float:
        """Seconds until the next refresh: at the configured fraction of the lifetime, but
        always before the token enters the mandatory margin (when it stops being served).
        Lifetimes at or below the margin are refreshed after the assertion poll interval."""
        before_margin = expires_in - MANDATORY_MARGIN_S - REFRESH_BUFFER_S
        return max(ASSERTION_POLL_S, min(expires_in * self.cfg.refresh_fraction, before_margin))

    def status_fields(self) -> dict[str, Any]:
        return {
            "event": "wif_token_status",
            "valid": self.is_valid(),
            "invalid_for_s": int(self.seconds_invalid()),
            "expires_in_s": int(self.seconds_to_expiry()),
        }

    def run(self, stop: threading.Event, status_interval: float = STATUS_INTERVAL_S) -> None:
        next_status = self.clock()
        while not stop.is_set():
            delay = self.step()
            now = self.clock()
            if now >= next_status:
                logger.info("wif token status", extra={"fields": self.status_fields()})
                next_status = now + status_interval
            stop.wait(max(0.05, min(delay, next_status - now)))


# -- Vault identity source ---------------------------------------------------------------

VaultRequest = Callable[[str, str, str | None, Mapping[str, Any] | None], tuple[int, Any]]


def vault_http_request(cfg: BrokerConfig, timeout: float = 15.0) -> VaultRequest:
    """Return a callable performing one Vault API call: (method, path, token, body)."""

    def _request(
        method: str, path: str, token: str | None, body: Mapping[str, Any] | None
    ) -> tuple[int, Any]:
        conn = open_connection(cfg.vault_addr, timeout, cafile=cfg.vault_cacert)
        try:
            headers = {"accept": "application/json"}
            if token is not None:
                headers["x-vault-token"] = token
            payload = None
            if body is not None:
                payload = json.dumps(body).encode()
                headers["content-type"] = "application/json"
            conn.request(method, "/v1/" + path, body=payload, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(1024 * 1024)
        finally:
            conn.close()
        try:
            return resp.status, json.loads(raw) if raw else None
        except ValueError:
            return resp.status, None

    return _request


@dataclass
class VaultIdentitySource:
    """Fetches a fresh Vault-signed OIDC identity token for every Anthropic exchange.

    Logs in with the pod's Kubernetes service-account token (Vault Kubernetes auth), keeps
    the resulting Vault token in memory only, renews it before its lease ends and logs in
    again when renewal is refused. Each identity token Vault issues carries a new ``jti``.
    """

    cfg: BrokerConfig
    request: VaultRequest
    clock: Callable[[], float] = time.monotonic
    _token: str | None = field(default=None, repr=False)
    _expires_at: float = 0.0
    _renew_at: float = 0.0
    _renewable: bool = False

    def __repr__(self) -> str:
        return f"VaultIdentitySource(logged_in={self._token is not None})"

    def _store(self, auth: object, operation: str) -> None:
        token = auth.get("client_token") if isinstance(auth, dict) else None
        lease = auth.get("lease_duration") if isinstance(auth, dict) else None
        if not isinstance(token, str) or not token:
            raise VaultError(operation, 200)
        lease_s = float(lease) if isinstance(lease, int | float) and lease > 0 else 3600.0
        now = self.clock()
        self._token = token
        self._expires_at = now + lease_s
        self._renew_at = now + lease_s * 2 / 3
        self._renewable = bool(isinstance(auth, dict) and auth.get("renewable"))

    def _login(self) -> None:
        self._token = None
        path = Path(self.cfg.vault_jwt_file)
        if path.stat().st_size > MAX_ASSERTION_BYTES:
            raise VaultError("login")
        jwt = path.read_text(encoding="ascii").strip()
        status, data = self.request(
            "POST",
            f"auth/{self.cfg.vault_auth_path}/login",
            None,
            {"role": self.cfg.vault_role, "jwt": jwt},
        )
        if status != 200 or not isinstance(data, dict):
            raise VaultError("login", status)
        self._store(data.get("auth"), "login")
        logger.info("vault login succeeded")

    def _renew(self) -> bool:
        status, data = self.request("POST", "auth/token/renew-self", self._token, {})
        if status != 200 or not isinstance(data, dict):
            logger.info("vault token renewal refused", extra={"fields": {"status": status}})
            return False
        try:
            self._store(data.get("auth"), "renew")
        except VaultError:
            return False
        return True

    def _ensure_token(self) -> str:
        now = self.clock()
        expired = self._token is None or now >= self._expires_at - MANDATORY_MARGIN_S
        # Renew when due; a refused or impossible renewal falls back to a fresh login.
        if expired or (now >= self._renew_at and not (self._renewable and self._renew())):
            self._login()
        if self._token is None:  # pragma: no cover - _login/_store set it or raise
            raise VaultError("login")
        return self._token

    def _fetch(self) -> tuple[int, Any]:
        return self.request("GET", self.cfg.vault_token_path, self._ensure_token(), None)

    def __call__(self) -> str:
        try:
            status, data = self._fetch()
            if status == 403:
                # Token revoked or expired early: log in again once.
                self._token = None
                status, data = self._fetch()
        except (OSError, http.client.HTTPException, UnicodeDecodeError) as e:
            raise VaultError("request") from e
        inner = data.get("data") if isinstance(data, dict) else None
        token = inner.get("token") if isinstance(inner, dict) else None
        if status != 200 or not isinstance(token, str) or not token:
            raise VaultError("identity token", status)
        return token


# -- reverse proxy -----------------------------------------------------------------------


def path_allowed(target: str) -> bool:
    # Origin-form only ("/v1/..."); absolute-form targets are refused outright.
    if not target.startswith("/") or target.startswith("//"):
        return False
    path = urlsplit(target).path
    if "//" in path or "/../" in path or path.endswith("/..") or "\\" in path:
        return False
    return any(path == prefix or path.startswith(prefix + "/") for prefix in ALLOWED_PATH_PREFIXES)


def forward_request_headers(headers: Mapping[str, str] | Any, token: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() not in STRIPPED_REQUEST_HEADERS:
            out[name] = value
    out["authorization"] = f"Bearer {token}"
    return out


def make_handler(
    cfg: BrokerConfig,
    manager: TokenManager,
    connect: Callable[[str, float], http.client.HTTPConnection] = open_connection,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "aegisx9-wif-broker"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:
            """Silence the default access log; ``_access`` writes a structured one."""

        def _access(self, status: int, started: float) -> None:
            logger.info(
                "request",
                extra={
                    "fields": {
                        "method": self.command,
                        "path": urlsplit(self.path).path,
                        "status": status,
                        "duration_ms": round((time.monotonic() - started) * 1000, 1),
                        "remote": self.client_address[0],
                    }
                },
            )

        def _json(self, status: int, payload: Mapping[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, error_type: str, message: str) -> None:
            self._json(status, {"type": "error", "error": {"type": error_type, "message": message}})

        def do_GET(self) -> None:
            started = time.monotonic()
            if urlsplit(self.path).path == "/healthz":
                ok = manager.is_valid()
                self._json(200 if ok else 503, {"status": "ok" if ok else "no_token"})
                return
            self._access(self._proxy(), started)

        def do_POST(self) -> None:
            started = time.monotonic()
            self._access(self._proxy(), started)

        def _refuse_method(self) -> None:
            started = time.monotonic()
            self._error(405, "invalid_request_error", "method not allowed")
            self._access(405, started)

        do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _refuse_method

        def _read_body(self) -> bytes | int:
            if self.headers.get("transfer-encoding"):
                return 411
            length_header = self.headers.get("content-length")
            if length_header is None:
                return b""
            try:
                length = int(length_header)
            except ValueError:
                return 400
            if length < 0:
                return 400
            if length > cfg.max_body_bytes:
                return 413
            return self.rfile.read(length)

        def _proxy(self) -> int:
            if self.command not in ALLOWED_METHODS or not path_allowed(self.path):
                self.close_connection = True
                self._error(404, "not_found_error", "path not served by the broker")
                return 404
            body = self._read_body()
            if isinstance(body, int):
                self.close_connection = True
                self._error(body, "invalid_request_error", "unsupported request body")
                return body
            token = manager.current_token()
            if token is None:
                self._error(503, "api_error", "provider credential unavailable")
                return 503
            headers = forward_request_headers(self.headers, token)
            if body or self.command == "POST":
                headers["content-length"] = str(len(body))
            try:
                conn = connect(cfg.upstream, cfg.upstream_timeout_s)
            except (OSError, http.client.HTTPException) as e:
                logger.warning(
                    "upstream connect failed", extra={"fields": {"error": type(e).__name__}}
                )
                self._error(502, "api_error", "upstream unavailable")
                return 502
            try:
                conn.request(self.command, self.path, body=body or None, headers=headers)
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException) as e:
                conn.close()
                logger.warning(
                    "upstream request failed", extra={"fields": {"error": type(e).__name__}}
                )
                self._error(502, "api_error", "upstream unavailable")
                return 502
            try:
                self._relay(resp)
            except (OSError, http.client.HTTPException) as e:
                # Headers are already sent; all that is left is to drop the connection.
                self.close_connection = True
                logger.warning("stream interrupted", extra={"fields": {"error": type(e).__name__}})
            finally:
                conn.close()
            return resp.status

        def _relay(self, resp: http.client.HTTPResponse) -> None:
            length = resp.getheader("content-length")
            chunked = (resp.getheader("transfer-encoding") or "").lower() == "chunked"
            self.send_response(resp.status, resp.reason)
            for name, value in resp.getheaders():
                if name.lower() not in STRIPPED_RESPONSE_HEADERS:
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
            while True:
                chunk = resp.read1(CHUNK_BYTES)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()

    return Handler


# -- process -----------------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Records carry only the message and explicit fields."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": round(record.created, 3),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            entry.update(fields)
        return json.dumps(entry, separators=(",", ":"))


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("aegisx9")
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
    root.propagate = False


def build_server(cfg: BrokerConfig, manager: TokenManager) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((cfg.listen_host, cfg.listen_port), make_handler(cfg, manager))
    server.daemon_threads = True
    return server


def main(env: Mapping[str, str] | None = None) -> int:
    configure_logging()
    logger.info("starting", extra={"fields": {"version": __version__}})
    try:
        cfg = BrokerConfig.from_env(os.environ if env is None else env)
    except BrokerConfigError as e:
        # The message holds variable names only, never values.
        # Fail closed: without its full configuration the broker never starts serving.
        logger.error(
            "invalid configuration",
            extra={"fields": {"error": type(e).__name__, "detail": e.args[0]}},
        )
        return 2
    source = (
        VaultIdentitySource(cfg, vault_http_request(cfg))
        if cfg.identity_source == "vault"
        else None
    )
    manager = TokenManager(cfg, http_exchange(cfg), source=source)
    logger.info(
        "identity source",
        extra={"fields": {"source": cfg.identity_source, "uploaded_kids": list(cfg.uploaded_kids)}},
    )
    stop = threading.Event()
    refresher = threading.Thread(target=manager.run, args=(stop,), name="wif-refresh", daemon=True)
    refresher.start()
    server = build_server(cfg, manager)

    def _shutdown(signum: int, frame: FrameType | None) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    logger.info("listening", extra={"fields": {"host": cfg.listen_host, "port": cfg.listen_port}})
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()
    stop.set()
    server.server_close()
    logger.info("stopped")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
