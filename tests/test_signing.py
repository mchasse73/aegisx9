import base64
import hashlib
import hmac
import secrets
from collections.abc import Mapping
from typing import Any

import pytest

from aegisx9.audit import AuditEvent
from aegisx9.guards import Direction, Verdict
from aegisx9.signing import (
    AuditSigner,
    AuditSigningError,
    LocalHmacSigner,
    Signature,
    VaultTransitSigner,
    sign_event,
    verify_envelope,
)


def _event() -> AuditEvent:
    return AuditEvent.for_content(
        content="hello",
        request_id="r",
        direction=Direction.INPUT,
        verdict=Verdict.ALLOW,
        model="m",
        principal="p",
        latency_ms=1.0,
    )


class FakeTransit:
    """In-memory stand-in for Vault's transit sign/verify endpoints."""

    def __init__(self) -> None:
        self.key = secrets.token_bytes(32)
        self.calls: list[tuple[str, Mapping[str, str]]] = []
        self.token = secrets.token_urlsafe(16)

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        self.calls.append((url, headers))
        assert method == "POST"
        assert headers["X-Vault-Token"] == self.token
        raw = base64.b64decode(body["input"])
        mac = "vault:v1:" + hmac.new(self.key, raw, hashlib.sha256).hexdigest()
        if "/sign/" in url:
            return {"data": {"signature": mac}}
        if "/verify/" in url:
            return {"data": {"valid": hmac.compare_digest(mac, body["signature"])}}
        raise AssertionError("unexpected url")


def test_signers_satisfy_protocol() -> None:
    fake = FakeTransit()
    assert isinstance(LocalHmacSigner(), AuditSigner)
    assert isinstance(VaultTransitSigner("https://v", "k", lambda: fake.token), AuditSigner)


@pytest.mark.parametrize("kind", ["local", "transit"])
def test_sign_and_verify_envelope(kind: str) -> None:
    fake = FakeTransit()
    signer: AuditSigner = (
        LocalHmacSigner()
        if kind == "local"
        else VaultTransitSigner(
            "https://vault.invalid/", "aegisx9-audit", lambda: fake.token, transport=fake
        )
    )
    envelope = sign_event(_event(), signer)
    assert verify_envelope(envelope, signer)

    envelope["event"]["verdict"] = "block"  # tamper
    assert not verify_envelope(envelope, signer)


def test_transit_url_and_key_id() -> None:
    fake = FakeTransit()
    signer = VaultTransitSigner(
        "https://vault.invalid/", "audit", lambda: fake.token, mount="/transit/", transport=fake
    )
    sig = signer.sign(b"x")
    assert sig.key_id == "transit/audit"
    assert fake.calls[0][0] == "https://vault.invalid/v1/transit/sign/audit"


def test_wrong_key_id_or_algorithm_rejected() -> None:
    local = LocalHmacSigner("a")
    sig = local.sign(b"x")
    assert not local.verify(b"x", Signature("b", sig.algorithm, sig.value))
    fake = FakeTransit()
    transit = VaultTransitSigner("https://v", "k", lambda: fake.token, transport=fake)
    assert not transit.verify(b"x", sig)


def test_transport_error_hides_details() -> None:
    marker = secrets.token_urlsafe(12)

    def boom(*_: object) -> Mapping[str, Any]:
        raise ConnectionError(f"https://vault.invalid/?token={marker}")

    signer = VaultTransitSigner("https://v", "k", lambda: "t", transport=boom)
    with pytest.raises(AuditSigningError) as exc:
        signer.sign(b"x")
    assert marker not in str(exc.value)
    assert "ConnectionError" in str(exc.value)


def test_transport_signing_error_passthrough_and_empty_data() -> None:
    def refuse(*_: object) -> Mapping[str, Any]:
        raise AuditSigningError("vault address must use https")

    with pytest.raises(AuditSigningError, match="https"):
        VaultTransitSigner("http://v", "k", lambda: "t", transport=refuse).sign(b"x")

    def empty(*_: object) -> Mapping[str, Any]:
        return {"data": None}

    with pytest.raises(AuditSigningError, match="no data"):
        VaultTransitSigner("https://v", "k", lambda: "t", transport=empty).sign(b"x")
