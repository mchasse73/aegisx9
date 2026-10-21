"""Audit-event schema.

One :class:`AuditEvent` is emitted per guarded request and direction. It is shipped
as an OpenTelemetry log record to Loki. It deliberately has **no field that can hold
prompt or completion text**: content is represented by a SHA-256 digest and a length,
and findings by category counts. :meth:`AuditEvent.to_json` re-scans its own output
and refuses to serialise anything that looks like a credential.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from aegisx9.guards.base import Direction, Finding, Verdict
from aegisx9.guards.redaction import contains_secret

SCHEMA_VERSION = "1.0"


class AuditSecretLeakError(ValueError):
    """Raised when an audit record would contain a secret-shaped value."""


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def pseudonymise(subject: str, salt: str) -> str:
    """Stable, non-reversible principal identifier (salted SHA-256, 16 hex chars)."""
    return hashlib.sha256(f"{salt}:{subject}".encode()).hexdigest()[:16]


@dataclass(frozen=True)
class FindingSummary:
    guard: str
    category: str
    count: int

    @classmethod
    def from_finding(cls, f: Finding) -> FindingSummary:
        return cls(f.guard, f.category, f.count)


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    direction: Direction
    verdict: Verdict
    model: str
    principal: str
    content_sha256: str
    content_chars: int
    latency_ms: float
    findings: tuple[FindingSummary, ...] = ()
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    schema_version: str = SCHEMA_VERSION

    @classmethod
    def for_content(
        cls,
        *,
        content: str,
        request_id: str,
        direction: Direction,
        verdict: Verdict,
        model: str,
        principal: str,
        latency_ms: float,
        findings: tuple[Finding, ...] = (),
    ) -> AuditEvent:
        return cls(
            request_id=request_id,
            direction=direction,
            verdict=verdict,
            model=model,
            principal=principal,
            content_sha256=sha256_hex(content),
            content_chars=len(content),
            latency_ms=round(latency_ms, 3),
            findings=tuple(FindingSummary.from_finding(f) for f in findings),
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["direction"] = self.direction.value
        d["verdict"] = self.verdict.value
        return d

    def to_json(self) -> str:
        payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        if contains_secret(payload):
            raise AuditSecretLeakError("audit event contains a secret-shaped value")
        return payload

    def to_otel_attributes(self) -> dict[str, str | int | float]:
        """Flat attributes for an OpenTelemetry LogRecord (``aegisx9.*`` namespace)."""
        attrs: dict[str, str | int | float] = {
            "aegisx9.schema_version": self.schema_version,
            "aegisx9.event_id": self.event_id,
            "aegisx9.request_id": self.request_id,
            "aegisx9.direction": self.direction.value,
            "aegisx9.verdict": self.verdict.value,
            "aegisx9.model": self.model,
            "aegisx9.principal": self.principal,
            "aegisx9.content_sha256": self.content_sha256,
            "aegisx9.content_chars": self.content_chars,
            "aegisx9.latency_ms": self.latency_ms,
            "aegisx9.findings_total": sum(f.count for f in self.findings),
        }
        for f in self.findings:
            key = f"aegisx9.finding.{f.guard}.{f.category}"
            attrs[key] = int(attrs.get(key, 0)) + f.count
        return attrs
