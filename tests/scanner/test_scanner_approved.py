from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from aegisx9_scanner.approved import Registry, RegistryError, load_registry, parse_registry
from conftest import TODAY


def test_example_registry_loads(registry: Registry) -> None:
    sections = {e.section for e in registry.entries}
    assert sections == {"public", "sso_gated", "parked_redirects"}
    assert registry.prohibited == ("vault.example.com", "*.internal.example.com")
    assert [s.sg_id for s in registry.sg_exceptions] == ["sg-0123456789abcdef0"]
    assert registry.source == "approved_public.yml"


def test_approved_tuples_and_lookups(registry: Registry) -> None:
    tuples = registry.approved_tuples(TODAY)
    assert ("www.example.com", "203.0.113.10", 443, "tcp") in tuples
    assert ("mail.example.com", "203.0.113.12", 25, "tcp") in tuples
    assert ("example.net", None, 80, "tcp") in tuples
    assert registry.is_approved("www.example.com", None, 443, "tcp", TODAY)
    assert registry.is_approved(None, "203.0.113.12", 587, "tcp", TODAY)
    assert not registry.is_approved("www.example.com", None, 22, "tcp", TODAY)
    assert not registry.is_approved("www.example.com", None, 443, "udp", TODAY)
    assert registry.is_known("console.example.com", None, TODAY)
    assert not registry.is_known("nothing.example.com", "203.0.113.99", TODAY)
    assert "203.0.113.11" in registry.known_ips(TODAY)
    assert "example.org" in registry.known_hosts(TODAY)


def test_prohibited_globs(registry: Registry) -> None:
    assert registry.is_prohibited("vault.example.com")
    assert registry.is_prohibited("Vault.Example.Com.")
    assert registry.is_prohibited("db.internal.example.com")
    assert not registry.is_prohibited("www.example.com")


def test_expiry_is_honoured(registry: Registry) -> None:
    later = date(2027, 6, 1)
    assert registry.is_approved("gateway.example.com", None, 443, "tcp", TODAY)
    assert not registry.is_approved("gateway.example.com", None, 443, "tcp", later)
    assert [e.service for e in registry.expired(later)] == ["aegisx9-gateway"]
    assert "gateway.example.com" not in registry.known_hosts(later)
    entry = next(e for e in registry.entries if e.service == "marketing-site")
    assert entry.is_public and entry.expiry is None and not entry.is_expired(later)
    gated = next(e for e in registry.entries if e.service == "operator-console")
    assert "oauth2-proxy" in gated.gate and "security-headers" in gated.gate


def test_wildcard_domain_entry() -> None:
    reg = parse_registry(
        {
            "public": [
                {
                    "domain": "*.apps.example.com",
                    "service": "tenants",
                    "authorized_by": "x",
                    "authorized_date": "2026-01-01",
                    "reason": "r",
                    "expiry": "never",
                    "ports": [443],
                }
            ]
        }
    )
    assert reg.is_approved("a.apps.example.com", None, 443, "tcp", TODAY)
    assert not reg.is_approved("a.apps.example.com", None, 80, "tcp", TODAY)


@pytest.mark.parametrize(
    "doc, fragment",
    [
        ([], "top level"),
        ({"gated": []}, "'public' is required"),
        ({"public": {"a": 1}}, "expected a list"),
        ({"public": ["x"]}, "expected a mapping"),
        ({"public": [{"service": "s"}]}, "domain or domains is required"),
        ({"public": [{"domain": "a.example.com", "service": "s"}]}, "required for public entries"),
        (
            {
                "public": [
                    {
                        "domain": "a.example.com",
                        "service": "s",
                        "authorized_by": "x",
                        "authorized_date": "yesterday",
                        "reason": "r",
                        "expiry": "never",
                    }
                ]
            },
            "YYYY-MM-DD",
        ),
        ({"public": [], "gated": [{"domain": "a", "ports": [0]}]}, "ports"),
        ({"public": [], "gated": [{"domain": "a", "ports": "443"}]}, "ports"),
        ({"public": [], "gated": [{"domain": "a", "proto": "icmp"}]}, "proto"),
        ({"public": [], "gated": [{"domains": "a"}]}, "domains: expected a list"),
        ({"public": [], "gated": [{"domain": ["a"]}]}, "scalar"),
        ({"public": [], "prohibited": "x"}, "prohibited"),
        ({"public": [], "approved_aws_sg_exceptions": [{}]}, "sg_id"),
        ({"public": [], "approved_aws_sg_exceptions": {}}, "expected a list"),
        ({"public": [], 3: []}, "section names"),
    ],
)
def test_validation_errors(doc: object, fragment: str) -> None:
    with pytest.raises(RegistryError, match=fragment):
        parse_registry(doc)


def test_load_rejects_invalid_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "r.yml"
    bad.write_text("public: [\n")
    with pytest.raises(RegistryError, match="not valid YAML"):
        load_registry(bad)


def test_empty_sections_and_date_objects() -> None:
    reg = parse_registry(
        {
            "public": [
                {
                    "domain": "a.example.com",
                    "service": "s",
                    "authorized_by": "x",
                    "authorized_date": date(2026, 1, 1),
                    "reason": "r",
                    "expiry": date(2026, 2, 1),
                    "extra_note": "kept",
                }
            ],
            "unused": None,
            "prohibited": [None, "x.example.com"],
        }
    )
    assert reg.entries[0].authorized_date == date(2026, 1, 1)
    assert reg.entries[0].is_expired(TODAY)
    assert reg.entries[0].extra == {"extra_note": "kept"}
    assert reg.prohibited == ("x.example.com",)
