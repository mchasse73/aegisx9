"""Short-lived JWT verification for the gateway's auth sidecar (ADR 0010).

A JWT must come from a configured issuer, be signed by a key in that issuer's JWKS with an
allow-listed asymmetric algorithm, carry the expected audience, and be short-lived: ``exp``
and ``iat`` are required and ``exp - iat`` may not exceed the lifetime ceiling
(``MAX_LIFETIME_S``, which configuration can lower but never raise). The caller is the
issuer-namespaced subject, and its groups pick one LiteLLM team.

Rejections carry a short reason code that is safe to log, never the token, its claims or an
exception message. Needs PyJWT and cryptography; nothing here imports LiteLLM.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import ssl
import threading
import time
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import jwt

logger = logging.getLogger("aegisx9.auth")

# Owner decision 2026-10-27: tokens are short-lived only. This ceiling is code, not
# configuration; an issuer's maxLifetimeSeconds may only lower it.
MAX_LIFETIME_S: Final = 900
CLOCK_SKEW_S: Final = 30
MAX_TOKEN_BYTES: Final = 8192
MAX_JWKS_BYTES: Final = 65536
JWKS_TTL_S: Final = 300.0
JWKS_MIN_REFRESH_S: Final = 30.0
JWKS_TIMEOUT_S: Final = 5.0
# Longest the last good keys are trusted while the JWKS can't be fetched.
JWKS_MAX_STALE_S: Final = 3600.0
# Asymmetric only: an HMAC algorithm would let anyone holding the public JWKS forge tokens.
ALLOWED_ALGORITHMS: Final = frozenset({"RS256", "RS384", "RS512", "PS256", "ES256", "ES384"})
CONFIG_ENV: Final = "AEGISX9_AUTH_CONFIG"
_LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1", "::1", "localhost"})


class AuthConfigError(ValueError):
    """The authentication configuration is invalid. Raised at startup, never per request."""


class AuthError(Exception):
    """A token was rejected. ``reason`` is a short code that is safe to log."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class JwksUnavailableError(AuthError):
    def __init__(self) -> None:
        super().__init__("jwks_unavailable")


@dataclass(frozen=True)
class IssuerConfig:
    name: str
    issuer: str
    jwks_url: str
    audience: str
    user_claim: str = "sub"
    groups_claim: str = "groups"
    # Ordered: the first of the caller's groups found here picks the team.
    group_teams: tuple[tuple[str, str], ...] = ()
    max_lifetime_s: int = MAX_LIFETIME_S
    ca_file: str | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], env: Mapping[str, str]) -> IssuerConfig:
        name = str(data.get("name", "")).strip()
        if not name or not name.replace("-", "").isalnum():
            raise AuthConfigError("issuer name must be letters, digits and dashes")
        issuer = _value_or_env(data, "issuer", env, name)
        jwks_url = _value_or_env(data, "jwksUrl", env, name)
        _check_jwks_url(jwks_url, name)
        audience = str(data.get("audience", "")).strip()
        if not audience:
            raise AuthConfigError(f"issuer {name}: audience is required")
        lifetime = int(data.get("maxLifetimeSeconds", MAX_LIFETIME_S))
        if not 0 < lifetime <= MAX_LIFETIME_S:
            raise AuthConfigError(f"issuer {name}: maxLifetimeSeconds must be 1..{MAX_LIFETIME_S}")
        teams = data.get("groupTeams", [])
        if not isinstance(teams, list):
            raise AuthConfigError(f"issuer {name}: groupTeams must be a list")
        group_teams = tuple((str(t["group"]), str(t["team"])) for t in teams)
        if not group_teams:
            raise AuthConfigError(f"issuer {name}: groupTeams must map at least one group")
        ca_file = data.get("caFile") or None
        return cls(
            name=name,
            issuer=issuer,
            jwks_url=jwks_url,
            audience=audience,
            user_claim=str(data.get("userClaim", "sub")),
            groups_claim=str(data.get("groupsClaim", "groups")),
            group_teams=group_teams,
            max_lifetime_s=lifetime,
            ca_file=str(ca_file) if ca_file else None,
        )


def _value_or_env(data: Mapping[str, Any], key: str, env: Mapping[str, str], name: str) -> str:
    """Literal ``key`` or the environment variable named by ``<key>Env`` (Secret-sourced)."""
    value = str(data.get(key, "") or "").strip()
    env_name = str(data.get(f"{key}Env", "") or "").strip()
    if env_name:
        value = env.get(env_name, "").strip()
    if not value:
        raise AuthConfigError(f"issuer {name}: {key} is required")
    return value


def _check_jwks_url(url: str, name: str) -> None:
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    # Plain HTTP only to the pod itself (CI boot smoke, a sidecar).
    if parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS:
        return
    raise AuthConfigError(f"issuer {name}: jwksUrl must be https (or http on loopback)")


@dataclass(frozen=True)
class Principal:
    user_id: str
    team_id: str
    issuer: str
    expires_at: int


Fetcher = Callable[[str, float, str | None], bytes]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the https-only rule for the JWKS URL must hold for the URL
    actually fetched, and a redirect to plain HTTP would let the network path inject keys."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def fetch_url(url: str, timeout: float, ca_file: str | None) -> bytes:
    context = ssl.create_default_context(cafile=ca_file) if url.startswith("https:") else None
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), _NoRedirect)
    request = urllib.request.Request(url, headers={"accept": "application/json"})  # noqa: S310 - scheme checked in config
    with opener.open(request, timeout=timeout) as response:
        body: bytes = response.read(MAX_JWKS_BYTES + 1)
    if len(body) > MAX_JWKS_BYTES:
        raise ValueError("jwks too large")
    return body


# Algorithms a key may verify when its JWK does not name one. An EC key is bound to its
# curve's algorithm; an RSA key to the RSA families in the allow-list.
_RSA_ALGORITHMS: Final = frozenset({"RS256", "RS384", "RS512", "PS256"})


@dataclass(frozen=True)
class SigningKey:
    key: Any  # the public key object PyJWT verifies with
    algorithms: frozenset[str]


def _signing_key(entry: dict[str, Any]) -> SigningKey:
    jwk = jwt.PyJWK(entry)
    declared = entry.get("alg")
    if isinstance(declared, str):
        algorithms = frozenset({declared})
    elif entry.get("kty") == "RSA":
        algorithms = _RSA_ALGORITHMS
    else:
        algorithms = frozenset({jwk.algorithm_name})
    return SigningKey(key=jwk.key, algorithms=algorithms & ALLOWED_ALGORITHMS)


@dataclass
class JwksCache:
    """Signing keys of one issuer.

    * Fresh for ``JWKS_TTL_S``; a token naming an unknown key id triggers an early refetch,
      at most every ``JWKS_MIN_REFRESH_S`` (failed attempts count, so an outage or a flood
      of unknown key ids can't turn into a fetch per request).
    * One fetch at a time and never under the lock: callers whose key is already known are
      answered from the cache (stale-while-revalidate) while the fetch runs.
    * After a failed refresh the last good keys are used for at most ``JWKS_MAX_STALE_S``;
      after that every token for this issuer is refused until a fetch succeeds.
    """

    issuer: IssuerConfig
    fetch: Fetcher = fetch_url
    clock: Callable[[], float] = time.monotonic
    _keys: dict[str, SigningKey] = field(default_factory=dict)
    _good_at: float | None = None
    _attempt_at: float | None = None
    _inflight: threading.Event | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def key(self, kid: str) -> SigningKey:
        with self._lock:
            now = self.clock()
            usable = self._good_at is not None and now - self._good_at < JWKS_MAX_STALE_S
            known = self._keys.get(kid) if usable else None
            fresh = self._good_at is not None and now - self._good_at < JWKS_TTL_S
            if known is not None and fresh:
                return known
            may_try = self._attempt_at is None or now - self._attempt_at >= JWKS_MIN_REFRESH_S
            leader = may_try and self._inflight is None
            if leader:
                self._inflight = threading.Event()
                self._attempt_at = now
            wait_for = self._inflight
        if leader:
            self._refresh()
        elif known is not None:
            return known  # stale but within the bound; someone else is refreshing
        elif wait_for is not None:
            wait_for.wait(JWKS_TIMEOUT_S + 1.0)
        return self._lookup(kid)

    def _lookup(self, kid: str) -> SigningKey:
        with self._lock:
            now = self.clock()
            if self._good_at is None or now - self._good_at >= JWKS_MAX_STALE_S:
                raise JwksUnavailableError()
            found = self._keys.get(kid)
        if found is None:
            raise AuthError("unknown_kid")
        return found

    def _refresh(self) -> None:
        keys: dict[str, SigningKey] | None = None
        try:
            document = json.loads(
                self.fetch(self.issuer.jwks_url, JWKS_TIMEOUT_S, self.issuer.ca_file)
            )
            parsed: dict[str, SigningKey] = {}
            for entry in document.get("keys", []) if isinstance(document, dict) else []:
                if not isinstance(entry, dict) or entry.get("use", "sig") != "sig":
                    continue
                kid = entry.get("kid")
                if not isinstance(kid, str) or not kid:
                    continue
                try:
                    parsed[kid] = _signing_key(entry)
                except jwt.PyJWTError:
                    continue  # unsupported key type or algorithm: skip it, keep the others
            if not parsed:
                raise ValueError("no usable keys")
            # Only a complete, non-empty document replaces the last good keys.
            keys = parsed
        except Exception as e:  # any fetch or parse failure is the same outcome
            logger.warning(
                "jwks fetch failed issuer=%s error=%s",
                self.issuer.name,
                type(e).__name__,
                extra={"fields": {"issuer": self.issuer.name, "error": type(e).__name__}},
            )
        finally:
            with self._lock:
                if keys is not None:
                    self._keys = keys
                    self._good_at = self.clock()
                event, self._inflight = self._inflight, None
            if event is not None:
                event.set()


def _segment_json(segment: str) -> Any:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


def looks_like_jwt(token: str) -> bool:
    """True for three base64url segments whose header is a JSON object with ``alg``."""
    parts = token.split(".")
    if len(parts) != 3 or not all(parts[:2]):
        return False
    try:
        header = _segment_json(parts[0])
    except (ValueError, binascii.Error, UnicodeError):
        return False
    return isinstance(header, dict) and "alg" in header


class Verifier:
    def __init__(
        self,
        issuers: list[IssuerConfig],
        fetch: Fetcher = fetch_url,
        now: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not issuers:
            raise AuthConfigError("at least one issuer is required")
        by_iss: dict[str, IssuerConfig] = {}
        names: set[str] = set()
        for cfg in issuers:
            if cfg.issuer in by_iss or cfg.name in names:
                raise AuthConfigError(f"issuer {cfg.name}: duplicate issuer or name")
            by_iss[cfg.issuer] = cfg
            names.add(cfg.name)
        self._issuers = by_iss
        self._jwks = {iss: JwksCache(cfg, fetch, monotonic) for iss, cfg in by_iss.items()}
        self._now = now

    def verify(self, token: str) -> Principal:
        if len(token) > MAX_TOKEN_BYTES:
            raise AuthError("too_large")
        try:
            header = jwt.get_unverified_header(token)
            # Read only to pick the issuer's keys; the verified decode below is what counts.
            unverified = jwt.decode(token, options={"verify_signature": False})  # nosemgrep
        except jwt.PyJWTError:
            raise AuthError("malformed") from None
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in ALLOWED_ALGORITHMS:
            raise AuthError("algorithm")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthError("no_kid")
        cfg = self._issuers.get(str(unverified.get("iss", "")))
        if cfg is None:
            raise AuthError("unknown_issuer")
        key = self._jwks[cfg.issuer].key(kid)
        if alg not in key.algorithms:
            raise AuthError("algorithm")
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=[alg],
                audience=cfg.audience,
                issuer=cfg.issuer,
                leeway=CLOCK_SKEW_S,
                options={"require": ["exp", "iat", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            raise AuthError("expired") from None
        except jwt.InvalidAudienceError:
            raise AuthError("audience") from None
        except jwt.ImmatureSignatureError:
            raise AuthError("not_yet_valid") from None
        except jwt.PyJWTError:
            raise AuthError("invalid") from None
        self._check_lifetime(claims, cfg)
        return Principal(
            user_id=self._user(claims, cfg),
            team_id=self._team(claims, cfg),
            issuer=cfg.name,
            expires_at=int(claims["exp"]),
        )

    def _check_lifetime(self, claims: Mapping[str, Any], cfg: IssuerConfig) -> None:
        exp, iat = claims["exp"], claims["iat"]
        if not isinstance(exp, int | float) or not isinstance(iat, int | float):
            raise AuthError("invalid")
        now = self._now()
        if iat > now + CLOCK_SKEW_S:
            raise AuthError("not_yet_valid")
        # With iat at most CLOCK_SKEW_S ahead, this also bounds the remaining lifetime.
        if exp - iat > cfg.max_lifetime_s:
            raise AuthError("lifetime")

    @staticmethod
    def _user(claims: Mapping[str, Any], cfg: IssuerConfig) -> str:
        user = claims.get(cfg.user_claim)
        if not isinstance(user, str) or not user.strip():
            raise AuthError("no_user")
        # Namespaced by issuer: the same subject from two issuers is two different callers.
        return f"{cfg.name}:{user}"

    @staticmethod
    def _team(claims: Mapping[str, Any], cfg: IssuerConfig) -> str:
        groups = claims.get(cfg.groups_claim)
        if isinstance(groups, str):
            groups = [groups]
        if not isinstance(groups, list):
            raise AuthError("no_team")
        held = {g for g in groups if isinstance(g, str)}
        for group, team in cfg.group_teams:
            if group in held:
                return team
        raise AuthError("no_team")


def load_verifier(env: Mapping[str, str], fetch: Fetcher = fetch_url) -> Verifier | None:
    """The verifier configured by the JSON file named in ``AEGISX9_AUTH_CONFIG``, or None
    when the variable is unset (JWTs are then rejected). A set but unreadable or invalid
    configuration raises, so the proxy fails at startup instead of serving without it."""
    path = env.get(CONFIG_ENV, "").strip()
    if not path:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise AuthConfigError(f"{CONFIG_ENV}: unreadable ({type(e).__name__})") from None
    issuers = data.get("issuers") if isinstance(data, dict) else None
    if not isinstance(issuers, list):
        raise AuthConfigError(f"{CONFIG_ENV}: 'issuers' must be a list")
    try:
        return Verifier([IssuerConfig.from_mapping(i, env) for i in issuers], fetch=fetch)
    except (AttributeError, KeyError, TypeError, ValueError) as e:
        if isinstance(e, AuthConfigError):
            raise
        raise AuthConfigError(f"{CONFIG_ENV}: invalid issuer ({type(e).__name__})") from None
