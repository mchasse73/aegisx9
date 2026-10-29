"""Tests for the short-lived JWT custom_auth hook. Signing keys are generated per run."""

import json
import threading
import urllib.error
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from aegisx9 import auth
from aegisx9.auth import (
    MAX_LIFETIME_S,
    AuthConfigError,
    AuthError,
    IssuerConfig,
    Verifier,
    load_verifier,
    looks_like_jwt,
)

ISS = "https://idp.example.test/app/"
AUD = "aegisx9"
NOW = 1_800_000_000.0


class Keys:
    def __init__(self) -> None:
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.extra: list[dict[str, Any]] = []
        self.fetches = 0
        self.fail = False
        self.document: Any = None  # when set, served instead of the real JWKS

    def jwks(self) -> dict[str, Any]:
        r = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.rsa.public_key()))
        e = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.ec.public_key()))
        return {"keys": [r | {"kid": "r1", "use": "sig"}, e | {"kid": "e1"}, *self.extra]}

    def fetch(self, url: str, timeout: float, ca_file: str | None) -> bytes:
        self.fetches += 1
        if self.fail:
            raise OSError("down")
        return json.dumps(self.jwks() if self.document is None else self.document).encode()


def issuer(**kw: Any) -> IssuerConfig:
    base: dict[str, Any] = {
        "name": "idp",
        "issuer": ISS,
        "jwksUrl": "https://idp.example.test/jwks",
        "audience": AUD,
        "groupTeams": [
            {"group": "chat", "team": "public-chat"},
            {"group": "dev", "team": "developers"},
        ],
    }
    return IssuerConfig.from_mapping(base | kw, {})


class Clock:
    def __init__(self) -> None:
        self.t = NOW
        self.mono = 1000.0

    def now(self) -> float:
        return self.t

    def monotonic(self) -> float:
        return self.mono


@pytest.fixture
def keys() -> Keys:
    return Keys()


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    c = Clock()
    # PyJWT reads the wall clock itself for exp/nbf/iat.
    monkeypatch.setattr(jwt.api_jwt, "datetime", _FrozenDatetime(c))
    return c


class _FrozenDatetime:
    def __init__(self, c: Clock) -> None:
        self._c = c

    def now(self, tz: Any = None) -> Any:
        import datetime as dt

        return dt.datetime.fromtimestamp(self._c.t, tz=tz or dt.UTC)

    def __getattr__(self, name: str) -> Any:
        import datetime as dt

        return getattr(dt.datetime, name)


def verifier(keys: Keys, clock: Clock, *cfgs: IssuerConfig) -> Verifier:
    return Verifier(
        list(cfgs) or [issuer()], fetch=keys.fetch, now=clock.now, monotonic=clock.monotonic
    )


def claims(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "iss": ISS,
        "aud": AUD,
        "sub": "alice",
        "groups": ["dev"],
        "iat": int(NOW),
        "exp": int(NOW) + 600,
    }
    for k, v in kw.items():
        if v is None:
            base.pop(k, None)
        else:
            base[k] = v
    return base


def sign(keys: Keys, payload: dict[str, Any], alg: str = "RS256", kid: str = "r1") -> str:
    key = keys.ec if alg.startswith("ES") else keys.rsa
    return jwt.encode(payload, key, algorithm=alg, headers={"kid": kid})


# --- happy paths -------------------------------------------------------------------------


def test_valid_rs256_token(keys: Keys, clock: Clock) -> None:
    p = verifier(keys, clock).verify(sign(keys, claims()))
    assert (p.user_id, p.team_id, p.issuer, p.expires_at) == (
        "idp:alice",
        "developers",
        "idp",
        int(NOW) + 600,
    )


def test_valid_es256_token(keys: Keys, clock: Clock) -> None:
    token = sign(keys, claims(), alg="ES256", kid="e1")
    assert verifier(keys, clock).verify(token).user_id == "idp:alice"


def test_team_follows_configured_order_and_string_groups(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    assert v.verify(sign(keys, claims(groups=["dev", "chat"]))).team_id == "public-chat"
    assert v.verify(sign(keys, claims(groups="chat"))).team_id == "public-chat"


def test_list_audience_containing_ours(keys: Keys, clock: Clock) -> None:
    assert (
        verifier(keys, clock).verify(sign(keys, claims(aud=["other", AUD]))).user_id == "idp:alice"
    )


def test_full_ceiling_is_allowed(keys: Keys, clock: Clock) -> None:
    token = sign(keys, claims(exp=int(NOW) + MAX_LIFETIME_S))
    assert verifier(keys, clock).verify(token).user_id == "idp:alice"


# --- short-lived only --------------------------------------------------------------------


def _reason(v: Verifier, token: str) -> str:
    with pytest.raises(AuthError) as e:
        v.verify(token)
    return e.value.reason


def test_lifetime_over_ceiling_rejected(keys: Keys, clock: Clock) -> None:
    token = sign(keys, claims(exp=int(NOW) + MAX_LIFETIME_S + 1))
    assert _reason(verifier(keys, clock), token) == "lifetime"


def test_backdated_iat_cannot_extend_lifetime(keys: Keys, clock: Clock) -> None:
    # Issued long ago with a far expiry: exp - iat is over the ceiling even though the
    # remaining time alone might look acceptable at some point.
    token = sign(keys, claims(iat=int(NOW) - 3000, exp=int(NOW) + 600))
    assert _reason(verifier(keys, clock), token) == "lifetime"


def test_remaining_lifetime_bound_with_future_iat(keys: Keys, clock: Clock) -> None:
    # iat inside the skew allowance, exp beyond ceiling + skew from now.
    token = sign(keys, claims(iat=int(NOW) + 20, exp=int(NOW) + 20 + MAX_LIFETIME_S))
    assert verifier(keys, clock).verify(token).user_id == "idp:alice"
    clock.t = NOW - 15  # now the same token is 35 s early: iat beyond skew
    assert _reason(verifier(keys, clock), token) == "not_yet_valid"


def test_issuer_can_lower_but_not_raise_ceiling(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock, issuer(maxLifetimeSeconds=300))
    assert _reason(v, sign(keys, claims(exp=int(NOW) + 301))) == "lifetime"
    with pytest.raises(AuthConfigError):
        issuer(maxLifetimeSeconds=MAX_LIFETIME_S + 1)
    with pytest.raises(AuthConfigError):
        issuer(maxLifetimeSeconds=0)


@pytest.mark.parametrize("missing", ["exp", "iat", "iss", "aud"])
def test_required_claims(keys: Keys, clock: Clock, missing: str) -> None:
    reason = _reason(verifier(keys, clock), sign(keys, claims(**{missing: None})))
    assert reason in {"invalid", "unknown_issuer"}


def test_expired(keys: Keys, clock: Clock) -> None:
    token = sign(keys, claims(iat=int(NOW) - 700, exp=int(NOW) - 60))
    assert _reason(verifier(keys, clock), token) == "expired"


def test_expiry_within_skew_still_accepted(keys: Keys, clock: Clock) -> None:
    token = sign(keys, claims(iat=int(NOW) - 600, exp=int(NOW) - 10))
    assert verifier(keys, clock).verify(token).user_id == "idp:alice"


def test_iat_in_future(keys: Keys, clock: Clock) -> None:
    token = sign(keys, claims(iat=int(NOW) + 120, exp=int(NOW) + 300))
    assert _reason(verifier(keys, clock), token) == "not_yet_valid"


def test_nbf_in_future(keys: Keys, clock: Clock) -> None:
    token = sign(keys, claims(nbf=int(NOW) + 120))
    assert _reason(verifier(keys, clock), token) == "not_yet_valid"


def test_non_numeric_times_rejected(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    assert _reason(v, sign(keys, claims(iat="soon"))) == "invalid"
    with pytest.raises(AuthError):
        v._check_lifetime({"exp": "x", "iat": 1}, issuer())


# --- signature, algorithm, issuer, audience ----------------------------------------------


def test_alg_none_rejected(keys: Keys, clock: Clock) -> None:
    # An unsigned token on purpose: the verifier must refuse it.
    token = jwt.encode(claims(), None, algorithm="none", headers={"kid": "r1"})  # nosemgrep
    assert _reason(verifier(keys, clock), token) == "algorithm"


def test_hmac_with_public_key_rejected(keys: Keys, clock: Clock) -> None:
    # Classic confusion: HS256 keyed with the published RSA public key.
    import base64

    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": "r1"}).encode())
    body = base64.urlsafe_b64encode(json.dumps(claims()).encode())
    token = f"{header.decode().rstrip('=')}.{body.decode().rstrip('=')}.c2ln"
    assert _reason(verifier(keys, clock), token) == "algorithm"


@pytest.mark.parametrize("alg", [["RS256"], {"a": "RS256"}, 256])
def test_non_string_alg_rejected(keys: Keys, clock: Clock, alg: Any) -> None:
    import base64

    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "kid": "r1"}).encode())
    body = base64.urlsafe_b64encode(json.dumps(claims()).encode())
    token = f"{header.decode().rstrip('=')}.{body.decode().rstrip('=')}.c2ln"
    assert _reason(verifier(keys, clock), token) == "algorithm"


def test_header_alg_must_match_declared_key_alg(keys: Keys, clock: Clock) -> None:
    pub = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(keys.rsa.public_key()))
    keys.extra.append(pub | {"kid": "r-declared", "alg": "RS256"})
    token = sign(keys, claims(), alg="PS256", kid="r-declared")
    assert _reason(verifier(keys, clock), token) == "algorithm"


@pytest.mark.parametrize("alg", ["RS384", "RS512", "PS256"])
def test_rsa_key_without_declared_alg_accepts_rsa_family(
    keys: Keys, clock: Clock, alg: str
) -> None:
    token = sign(keys, claims(), alg=alg, kid="r1")  # the r1 JWK carries no "alg"
    assert verifier(keys, clock).verify(token).user_id == "idp:alice"


def test_ec_key_is_bound_to_its_curve(keys: Keys, clock: Clock) -> None:
    other = ec.generate_private_key(ec.SECP384R1())
    token = jwt.encode(claims(), other, algorithm="ES384", headers={"kid": "e1"})
    assert _reason(verifier(keys, clock), token) == "algorithm"


def test_same_subject_from_two_issuers_is_two_callers(keys: Keys, clock: Clock) -> None:
    vault = issuer(name="vault", issuer="https://vault.example.test/v1/identity/oidc")
    v = verifier(keys, clock, issuer(), vault)
    a = v.verify(sign(keys, claims()))
    b = v.verify(sign(keys, claims(iss="https://vault.example.test/v1/identity/oidc")))
    assert (a.user_id, b.user_id) == ("idp:alice", "vault:alice")


def test_tampered_signature(keys: Keys, clock: Clock) -> None:
    token = sign(keys, claims())
    head, _body, sig = token.split(".")
    other = sign(keys, claims(sub="mallory")).split(".")[1]
    assert _reason(verifier(keys, clock), f"{head}.{other}.{sig}") == "invalid"


def test_signed_by_unpublished_key(keys: Keys, clock: Clock) -> None:
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims(), rogue, algorithm="RS256", headers={"kid": "r1"})
    assert _reason(verifier(keys, clock), token) == "invalid"


def test_unknown_issuer_and_wrong_audience(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    assert _reason(v, sign(keys, claims(iss="https://evil.example.test/"))) == "unknown_issuer"
    assert _reason(v, sign(keys, claims(aud="someone-else"))) == "audience"


def test_missing_kid_and_unknown_kid(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    no_kid = jwt.encode(claims(), keys.rsa, algorithm="RS256")
    assert _reason(v, no_kid) == "no_kid"
    assert _reason(v, sign(keys, claims(), kid="nope")) == "unknown_kid"


def test_malformed_and_oversized(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    assert _reason(v, "a.b.c") == "malformed"
    assert _reason(v, "x" * (auth.MAX_TOKEN_BYTES + 1)) == "too_large"


def test_user_and_team_claims(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    assert _reason(v, sign(keys, claims(sub=None))) == "no_user"
    assert _reason(v, sign(keys, claims(sub="  "))) == "no_user"
    assert _reason(v, sign(keys, claims(groups=["other"]))) == "no_team"
    assert _reason(v, sign(keys, claims(groups=None))) == "no_team"


# --- JWKS cache --------------------------------------------------------------------------


def test_jwks_cached_then_refreshed_after_ttl(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    v.verify(sign(keys, claims()))
    v.verify(sign(keys, claims()))
    assert keys.fetches == 1
    clock.mono += auth.JWKS_TTL_S
    v.verify(sign(keys, claims()))
    assert keys.fetches == 2


def test_unknown_kid_refetch_is_rate_limited(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    v.verify(sign(keys, claims()))
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims(), rotated, algorithm="RS256", headers={"kid": "r2"})
    assert _reason(v, token) == "unknown_kid"  # too soon after the first fetch
    assert keys.fetches == 1
    keys.extra.append(
        json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rotated.public_key())) | {"kid": "r2"}
    )
    clock.mono += auth.JWKS_MIN_REFRESH_S
    assert v.verify(token).user_id == "idp:alice"  # rotation picked up
    assert keys.fetches == 2


def test_jwks_unavailable_first_time(keys: Keys, clock: Clock) -> None:
    keys.fail = True
    assert _reason(verifier(keys, clock), sign(keys, claims())) == "jwks_unavailable"


def test_jwks_outage_keeps_last_good_keys_with_backoff(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    v.verify(sign(keys, claims()))
    keys.fail = True
    clock.mono += auth.JWKS_TTL_S
    assert v.verify(sign(keys, claims())).user_id == "idp:alice"
    assert keys.fetches == 2
    # A failed attempt counts: no refetch per request during the outage.
    for _ in range(5):
        v.verify(sign(keys, claims()))
    assert keys.fetches == 2
    clock.mono += auth.JWKS_MIN_REFRESH_S
    v.verify(sign(keys, claims()))
    assert keys.fetches == 3


@pytest.mark.parametrize(
    "document", [{"keys": None}, {"keys": []}, {"keys": [{"kid": "x", "kty": "nope"}]}, []]
)
def test_jwks_bad_document_keeps_last_good_keys(keys: Keys, clock: Clock, document: Any) -> None:
    v = verifier(keys, clock)
    v.verify(sign(keys, claims()))
    keys.document = document
    clock.mono += auth.JWKS_TTL_S
    assert v.verify(sign(keys, claims())).user_id == "idp:alice"
    assert keys.fetches == 2


def test_jwks_last_good_keys_expire_after_max_staleness(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    v.verify(sign(keys, claims()))
    keys.fail = True
    clock.mono += auth.JWKS_MAX_STALE_S
    assert _reason(v, sign(keys, claims())) == "jwks_unavailable"
    keys.fail = False
    clock.mono += auth.JWKS_MIN_REFRESH_S
    assert v.verify(sign(keys, claims())).user_id == "idp:alice"


def test_known_key_served_while_another_caller_refreshes(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    token = sign(keys, claims())
    v.verify(token)
    clock.mono += auth.JWKS_TTL_S
    entered, release = threading.Event(), threading.Event()
    real_fetch = keys.fetch

    def slow_fetch(url: str, timeout: float, ca_file: str | None) -> bytes:
        entered.set()
        release.wait(5)
        return real_fetch(url, timeout, ca_file)

    cache = v._jwks[ISS]
    cache.fetch = slow_fetch
    leader = threading.Thread(target=v.verify, args=(token,))
    leader.start()
    assert entered.wait(5)
    # The refresh is in flight and holds no lock: a known key is answered at once.
    assert v.verify(token).user_id == "idp:alice"
    release.set()
    leader.join(5)
    assert keys.fetches == 2


def test_unknown_kid_waits_for_inflight_refresh(keys: Keys, clock: Clock) -> None:
    v = verifier(keys, clock)
    v.verify(sign(keys, claims()))
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys.extra.append(
        json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rotated.public_key())) | {"kid": "r2"}
    )
    clock.mono += auth.JWKS_MIN_REFRESH_S
    entered, release = threading.Event(), threading.Event()
    real_fetch = keys.fetch

    def slow_fetch(url: str, timeout: float, ca_file: str | None) -> bytes:
        entered.set()
        release.wait(5)
        return real_fetch(url, timeout, ca_file)

    v._jwks[ISS].fetch = slow_fetch
    token = jwt.encode(claims(), rotated, algorithm="RS256", headers={"kid": "r2"})
    results: list[str] = []
    leader = threading.Thread(target=lambda: results.append(v.verify(token).user_id))
    leader.start()
    assert entered.wait(5)
    follower = threading.Thread(target=lambda: results.append(v.verify(token).user_id))
    follower.start()
    release.set()
    leader.join(5)
    follower.join(5)
    assert results == ["idp:alice", "idp:alice"]
    assert keys.fetches == 2


def test_jwks_skips_unusable_entries(keys: Keys, clock: Clock) -> None:
    keys.extra += [
        {"kid": "enc", "use": "enc", "kty": "RSA"},
        {"kty": "RSA"},
        {"kid": "bad", "kty": "nope"},
        "junk",
    ]
    assert verifier(keys, clock).verify(sign(keys, claims())).user_id == "idp:alice"


def test_jwks_document_not_an_object(clock: Clock) -> None:
    v = Verifier([issuer()], fetch=lambda *_: b"[]", now=clock.now, monotonic=clock.monotonic)
    # Never a usable document, so no keys at all: the issuer is unavailable (still a 401).
    assert _reason(v, sign(Keys(), claims())) == "jwks_unavailable"


# --- configuration -----------------------------------------------------------------------


def test_issuer_and_jwks_from_env() -> None:
    cfg = IssuerConfig.from_mapping(
        {
            "name": "vault",
            "issuerEnv": "VAULT_ISS",
            "jwksUrlEnv": "VAULT_JWKS",
            "audience": AUD,
            "groupTeams": [{"group": "dev", "team": "developers"}],
            "caFile": "/etc/ca.pem",
        },
        {
            "VAULT_ISS": "https://vault.example.test/v1/identity/oidc",
            "VAULT_JWKS": "https://vault.example.test/keys",
        },
    )
    assert cfg.issuer.startswith("https://vault.") and cfg.ca_file == "/etc/ca.pem"


def test_audience_and_group_teams_from_env() -> None:
    cfg = IssuerConfig.from_mapping(
        {
            "name": "idp",
            "issuerEnv": "ISS",
            "jwksUrlEnv": "JWKS",
            "audienceEnv": "AUD_ENV",
            "groupTeamsEnv": "TEAMS",
        },
        {
            "ISS": "https://idp.example.test/",
            "JWKS": "https://idp.example.test/jwks",
            "AUD_ENV": AUD,
            "TEAMS": " admins = developers ; devs=developers;",
        },
    )
    assert cfg.audience == AUD
    assert cfg.group_teams == (("admins", "developers"), ("devs", "developers"))


@pytest.mark.parametrize(
    "env",
    [
        {"TEAMS": ""},
        {"TEAMS": "admins"},
        {"TEAMS": "=developers"},
        {"TEAMS": "admins="},
        {},
    ],
)
def test_invalid_group_teams_env(env: dict[str, str]) -> None:
    with pytest.raises(AuthConfigError):
        IssuerConfig.from_mapping(
            {
                "name": "idp",
                "issuer": "https://idp.example.test/",
                "jwksUrl": "https://idp.example.test/jwks",
                "audience": AUD,
                "groupTeamsEnv": "TEAMS",
            },
            env,
        )


@pytest.mark.parametrize(
    "override",
    [
        {"audienceEnv": "UNSET_VAR"},
        {"name": ""},
        {"name": "has space"},
        {"name": "a:b"},
        {"issuer": ""},
        {"jwksUrl": "http://idp.example.test/jwks"},
        {"jwksUrl": "ftp://idp.example.test/jwks"},
        {"jwksUrl": "https:///nohost"},
        {"audience": ""},
        {"groupTeams": []},
        {"groupTeams": "dev"},
        {"issuerEnv": "UNSET_VAR"},
    ],
)
def test_invalid_issuer_config(override: dict[str, Any]) -> None:
    with pytest.raises(AuthConfigError):
        issuer(**override)


def test_loopback_http_jwks_allowed() -> None:
    assert issuer(jwksUrl="http://127.0.0.1:9000/jwks").jwks_url.startswith("http://127.")


def test_verifier_needs_unique_issuers_and_names() -> None:
    with pytest.raises(AuthConfigError):
        Verifier([])
    with pytest.raises(AuthConfigError):
        Verifier([issuer(), issuer(name="again")])
    with pytest.raises(AuthConfigError):
        Verifier([issuer(), issuer(issuer="https://other.example.test/")])


def test_load_verifier(tmp_path: Path) -> None:
    assert load_verifier({}) is None
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "issuers": [
                    {
                        "name": "idp",
                        "issuer": ISS,
                        "jwksUrl": "https://idp.example.test/jwks",
                        "audience": AUD,
                        "groupTeams": [{"group": "dev", "team": "developers"}],
                    }
                ]
            }
        )
    )
    assert isinstance(load_verifier({auth.CONFIG_ENV: str(path)}), Verifier)


@pytest.mark.parametrize(
    "content",
    [
        None,
        "not json",
        '{"issuers": ["not-a-mapping"]}',
        "[]",
        '{"issuers": {}}',
        '{"issuers": [{"name": "x", "issuer": "i", '
        '"jwksUrl": "https://h/j", "audience": "a", "groupTeams": [{"group": "g"}]}]}',
        '{"issuers": [{"name": "x", "issuer": "i", "jwksUrl": "https://h/j", "audience": "a", '
        '"groupTeams": [{"group": "g", "team": "t"}], "maxLifetimeSeconds": "long"}]}',
    ],
)
def test_load_verifier_fails_closed(tmp_path: Path, content: str | None) -> None:
    path = tmp_path / "auth.json"
    if content is not None:
        path.write_text(content)
    with pytest.raises(AuthConfigError):
        load_verifier({auth.CONFIG_ENV: str(path)})


def test_looks_like_jwt() -> None:
    assert not looks_like_jwt("sk-" + "a" * 20)
    assert not looks_like_jwt("a.b")
    assert not looks_like_jwt(".b.c")
    assert not looks_like_jwt("!!!.b.c")
    assert not looks_like_jwt("eyJ4IjoxfQ.e30.c2ln")  # header without alg
    assert looks_like_jwt("eyJhbGciOiJub25lIn0.e30.")


# --- fetch_url ---------------------------------------------------------------------------


@pytest.fixture
def jwks_server() -> Iterator[tuple[str, dict[str, bytes]]]:
    bodies: dict[str, bytes] = {"/jwks": b'{"keys": []}', "/big": b"x" * (auth.MAX_JWKS_BYTES + 1)}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("location", "/jwks")
                self.end_headers()
                return
            body = bodies.get(self.path, b"")
            self.send_response(200 if body else 404)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", bodies
    server.shutdown()


def test_fetch_url(jwks_server: tuple[str, dict[str, bytes]]) -> None:
    base, _ = jwks_server
    assert json.loads(auth.fetch_url(f"{base}/jwks", 5, None)) == {"keys": []}
    with pytest.raises(ValueError):
        auth.fetch_url(f"{base}/big", 5, None)


def test_fetch_url_refuses_redirects(jwks_server: tuple[str, dict[str, bytes]]) -> None:
    base, _ = jwks_server
    with pytest.raises(urllib.error.HTTPError) as e:
        auth.fetch_url(f"{base}/redirect", 5, None)
    assert e.value.code == 302


def test_lifetime_check_rejects_future_iat_on_its_own(keys: Keys, clock: Clock) -> None:
    # PyJWT checks iat too; this guard holds even if that check ever changes.
    with pytest.raises(AuthError) as e:
        verifier(keys, clock)._check_lifetime({"exp": NOW + 200, "iat": NOW + 100}, issuer())
    assert e.value.reason == "not_yet_valid"


def test_load_verifier_keeps_config_error_message(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps({"issuers": [{"name": "idp", "issuer": ISS}]}))
    with pytest.raises(AuthConfigError, match="jwksUrl is required"):
        load_verifier({auth.CONFIG_ENV: str(path)})
