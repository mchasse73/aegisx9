import json

import pytest

import samples
from aegisx9.audit import (
    SCHEMA_VERSION,
    AuditEvent,
    AuditSecretLeakError,
    pseudonymise,
    sha256_hex,
)
from aegisx9.guards import Direction, Finding, Verdict


def _event(**overrides: object) -> AuditEvent:
    kwargs: dict[str, object] = {
        "content": "some prompt",
        "request_id": "r",
        "direction": Direction.INPUT,
        "verdict": Verdict.REDACT,
        "model": "m",
        "principal": pseudonymise("user-1", "salt"),
        "latency_ms": 1.23456,
        "findings": (Finding("pii_redaction", "email", 2), Finding("pii_redaction", "email", 1)),
    }
    kwargs.update(overrides)
    return AuditEvent.for_content(**kwargs)  # type: ignore[arg-type]


def test_schema_has_no_content_field() -> None:
    event = _event()
    data = json.loads(event.to_json())
    assert "content" not in data
    assert data["content_sha256"] == sha256_hex("some prompt")
    assert data["content_chars"] == len("some prompt")
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["direction"] == "input" and data["verdict"] == "redact"
    assert data["latency_ms"] == 1.235


def test_otel_attributes_aggregate_findings() -> None:
    attrs = _event().to_otel_attributes()
    assert attrs["aegisx9.finding.pii_redaction.email"] == 3
    assert attrs["aegisx9.findings_total"] == 3
    assert all(k.startswith("aegisx9.") for k in attrs)


def test_refuses_to_serialise_secret_shaped_values() -> None:
    event = _event(model=samples.aws_access_key_id())
    with pytest.raises(AuditSecretLeakError):
        event.to_json()


def test_pseudonymise_is_stable_and_salted() -> None:
    assert pseudonymise("a", "s") == pseudonymise("a", "s")
    assert pseudonymise("a", "s") != pseudonymise("a", "t")
    assert len(pseudonymise("a", "s")) == 16
