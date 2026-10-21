"""Tamper-evident audit records.

Every :class:`~aegisx9.audit.AuditEvent` is signed before it is shipped. In production
the signature comes from Vault's **transit** engine, so the signing key never leaves
Vault and an attacker with write access to Loki cannot forge or silently alter records.
Tests and local development use :class:`LocalHmacSigner`.

Nothing here logs or returns key material, tokens or request bodies. Errors carry only
the exception type name, because HTTP library messages can contain URLs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from aegisx9.audit import AuditEvent


class AuditSigningError(RuntimeError):
    """Signing or verification could not be performed (not the same as 'invalid')."""


@dataclass(frozen=True)
class Signature:
    key_id: str
    algorithm: str
    value: str


@runtime_checkable
class AuditSigner(Protocol):
    def sign(self, payload: bytes) -> Signature: ...

    def verify(self, payload: bytes, signature: Signature) -> bool: ...


def sign_event(event: AuditEvent, signer: AuditSigner) -> dict[str, Any]:
    """Return the signed envelope that is written to the audit log."""
    payload = event.to_json()
    sig = signer.sign(payload.encode("utf-8"))
    return {
        "event": json.loads(payload),
        "signature": {"key_id": sig.key_id, "algorithm": sig.algorithm, "value": sig.value},
    }


def verify_envelope(envelope: Mapping[str, Any], signer: AuditSigner) -> bool:
    payload = json.dumps(envelope["event"], sort_keys=True, separators=(",", ":"))
    s = envelope["signature"]
    return signer.verify(
        payload.encode("utf-8"), Signature(s["key_id"], s["algorithm"], s["value"])
    )


class LocalHmacSigner:
    """Test double / local-dev signer. The key is random per instance and never exported."""

    algorithm = "hmac-sha256"

    def __init__(self, key_id: str = "local") -> None:
        self._key = secrets.token_bytes(32)
        self.key_id = key_id

    def sign(self, payload: bytes) -> Signature:
        mac = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return Signature(self.key_id, self.algorithm, mac)

    def verify(self, payload: bytes, signature: Signature) -> bool:
        if signature.key_id != self.key_id or signature.algorithm != self.algorithm:
            return False
        expected = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature.value)


# (method, url, headers, json_body) -> parsed JSON response
Transport = Callable[[str, str, Mapping[str, str], Mapping[str, Any]], Mapping[str, Any]]


def _urllib_transport(
    method: str, url: str, headers: Mapping[str, str], body: Mapping[str, Any]
) -> Mapping[str, Any]:  # pragma: no cover - exercised only against a real Vault
    if not url.startswith("https://"):
        raise AuditSigningError("vault address must use https")
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        url, data=json.dumps(body).encode(), headers=dict(headers), method=method
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310  # nosemgrep
        data: Mapping[str, Any] = json.loads(resp.read())
        return data


class VaultTransitSigner:
    """Signs with a Vault transit key (e.g. ed25519, non-exportable).

    ``token_provider`` returns a current Vault token, typically read from the file that
    Vault Agent maintains; it is called per request so renewals are picked up.
    """

    algorithm = "vault-transit"

    def __init__(
        self,
        address: str,
        key_name: str,
        token_provider: Callable[[], str],
        mount: str = "transit",
        transport: Transport | None = None,
    ) -> None:
        self._base = address.rstrip("/")
        self._key = key_name
        self._mount = mount.strip("/")
        self._token = token_provider
        self._transport = transport or _urllib_transport
        self.key_id = f"{self._mount}/{self._key}"

    def _call(self, op: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        url = f"{self._base}/v1/{self._mount}/{op}/{self._key}"
        headers = {"X-Vault-Token": self._token(), "Content-Type": "application/json"}
        try:
            resp = self._transport("POST", url, headers, body)
            data = resp["data"]
        except AuditSigningError:
            raise
        except Exception as exc:
            raise AuditSigningError(f"vault transit {op} failed: {type(exc).__name__}") from None
        if not isinstance(data, Mapping):
            raise AuditSigningError(f"vault transit {op} returned no data")
        return data

    def sign(self, payload: bytes) -> Signature:
        data = self._call("sign", {"input": base64.b64encode(payload).decode()})
        return Signature(self.key_id, self.algorithm, str(data["signature"]))

    def verify(self, payload: bytes, signature: Signature) -> bool:
        if signature.key_id != self.key_id or signature.algorithm != self.algorithm:
            return False
        data = self._call(
            "verify",
            {"input": base64.b64encode(payload).decode(), "signature": signature.value},
        )
        return bool(data.get("valid", False))
