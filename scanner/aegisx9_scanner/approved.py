"""Approved-exposure registry.

The registry is a YAML document kept in the platform operations repository (this
package ships only ``approved_public.example.yml``). Its shape:

* ``public:`` a list of entries that are reachable from the internet with no gate.
  Each entry has ``domain`` (or ``domains``), ``ip``, ``service``, ``purpose``,
  ``authorized_by``, ``authorized_date``, ``reason`` and ``expiry`` (``never`` or a
  date). Optional ``ports`` (default 80 and 443) and ``proto`` (default ``tcp``).
* Any other ``<name>:`` list of the same entries describes a *gated* tier (public DNS,
  but a network or SSO gate in front). Optional ``middleware``, ``auth_gate``,
  ``backend`` and ``caveat`` fields are kept for the report.
* ``prohibited:`` names or glob patterns that must never be publicly reachable.
* ``approved_aws_sg_exceptions:`` security-group ids with the ports approved for
  ``0.0.0.0/0`` ingress.

Expired entries are not approved: the exposure they covered becomes an alert, and the
expiry itself is reported so the owner renews or removes it.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PORTS: tuple[int, ...] = (80, 443)
PUBLIC_SECTION = "public"
PROHIBITED_SECTION = "prohibited"
SG_SECTION = "approved_aws_sg_exceptions"
REQUIRED_PUBLIC_FIELDS = ("service", "authorized_by", "authorized_date", "reason", "expiry")
MAX_PORT = 65535


class RegistryError(ValueError):
    """The registry file is malformed. The message names the section and field only."""


@dataclass(frozen=True)
class ApprovedEntry:
    section: str
    domains: tuple[str, ...]
    ip: str | None
    service: str
    purpose: str
    authorized_by: str
    authorized_date: date | None
    reason: str
    expiry: date | None  # None means "never"
    ports: tuple[int, ...] = DEFAULT_PORTS
    proto: str = "tcp"
    gate: str = ""
    extra: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def is_public(self) -> bool:
        return self.section == PUBLIC_SECTION

    def is_expired(self, today: date) -> bool:
        return self.expiry is not None and self.expiry < today

    def matches_host(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(fnmatch.fnmatchcase(host, d) for d in self.domains)

    def covers(self, host: str | None, ip: str | None) -> bool:
        if host and self.matches_host(host):
            return True
        return bool(ip) and ip == self.ip


@dataclass(frozen=True)
class SgException:
    sg_id: str
    sg_name: str
    ports: tuple[int, ...]
    expiry: date | None


@dataclass
class Registry:
    entries: list[ApprovedEntry]
    prohibited: tuple[str, ...]
    sg_exceptions: list[SgException]
    source: str = ""

    def active(self, today: date) -> list[ApprovedEntry]:
        return [e for e in self.entries if not e.is_expired(today)]

    def expired(self, today: date) -> list[ApprovedEntry]:
        return [e for e in self.entries if e.is_expired(today)]

    def approved_tuples(self, today: date) -> frozenset[tuple[str, str | None, int, str]]:
        """Every approved ``(host, ip, port, proto)``; one tuple per domain and port."""
        out: set[tuple[str, str | None, int, str]] = set()
        for entry in self.active(today):
            for domain in entry.domains:
                for port in entry.ports:
                    out.add((domain, entry.ip, port, entry.proto))
        return frozenset(out)

    def known_hosts(self, today: date) -> frozenset[str]:
        return frozenset(d for e in self.active(today) for d in e.domains)

    def known_ips(self, today: date) -> frozenset[str]:
        return frozenset(e.ip for e in self.active(today) if e.ip)

    def entries_for(self, host: str | None, ip: str | None, today: date) -> list[ApprovedEntry]:
        return [e for e in self.active(today) if e.covers(host, ip)]

    def is_known(self, host: str | None, ip: str | None, today: date) -> bool:
        return bool(self.entries_for(host, ip, today))

    def is_approved(
        self, host: str | None, ip: str | None, port: int, proto: str, today: date
    ) -> bool:
        return any(port in e.ports and e.proto == proto for e in self.entries_for(host, ip, today))

    def is_prohibited(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(fnmatch.fnmatchcase(host, pattern.lower()) for pattern in self.prohibited)


def _as_str(value: Any, section: str, field_name: str, index: int) -> str:
    if value is None:
        return ""
    if isinstance(value, str | int | float | bool):
        return str(value).strip()
    raise RegistryError(f"{section}[{index}].{field_name}: expected a scalar")


def _as_date(value: Any, section: str, field_name: str, index: int) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if text.lower() == "never":
        return None
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise RegistryError(
            f"{section}[{index}].{field_name}: expected YYYY-MM-DD or never"
        ) from exc


def _as_ports(value: Any, section: str, index: int) -> tuple[int, ...]:
    if value is None:
        return DEFAULT_PORTS
    if not isinstance(value, list) or not value:
        raise RegistryError(f"{section}[{index}].ports: expected a non-empty list")
    ports: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 0 < item <= MAX_PORT:
            raise RegistryError(f"{section}[{index}].ports: expected integers 1-{MAX_PORT}")
        ports.append(item)
    return tuple(sorted(set(ports)))


def _domains(raw: dict[str, Any], section: str, index: int) -> tuple[str, ...]:
    names: list[str] = []
    if "domain" in raw:
        names.append(_as_str(raw["domain"], section, "domain", index))
    if "domains" in raw:
        if not isinstance(raw["domains"], list):
            raise RegistryError(f"{section}[{index}].domains: expected a list")
        names.extend(_as_str(d, section, "domains", index) for d in raw["domains"])
    cleaned = tuple(sorted({n.lower().rstrip(".") for n in names if n}))
    if not cleaned:
        raise RegistryError(f"{section}[{index}]: domain or domains is required")
    return cleaned


def _entry(raw: Any, section: str, index: int) -> ApprovedEntry:
    if not isinstance(raw, dict):
        raise RegistryError(f"{section}[{index}]: expected a mapping")
    domains = _domains(raw, section, index)
    if section == PUBLIC_SECTION:
        for name in REQUIRED_PUBLIC_FIELDS:
            if name not in raw or raw[name] in (None, ""):
                raise RegistryError(f"{section}[{index}].{name}: required for public entries")
    proto = _as_str(raw.get("proto", "tcp"), section, "proto", index).lower() or "tcp"
    if proto not in ("tcp", "udp"):
        raise RegistryError(f"{section}[{index}].proto: expected tcp or udp")
    gate_parts: list[str] = []
    for key in ("middleware", "auth_gate"):
        value = raw.get(key)
        if isinstance(value, list):
            gate_parts.append(",".join(str(v) for v in value))
        elif value:
            gate_parts.append(_as_str(value, section, key, index))
    known = {
        "domain",
        "domains",
        "ip",
        "service",
        "purpose",
        "authorized_by",
        "authorized_date",
        "reason",
        "expiry",
        "ports",
        "proto",
        "middleware",
        "auth_gate",
    }
    return ApprovedEntry(
        section=section,
        domains=domains,
        ip=_as_str(raw.get("ip"), section, "ip", index) or None,
        service=_as_str(raw.get("service"), section, "service", index),
        purpose=_as_str(raw.get("purpose"), section, "purpose", index),
        authorized_by=_as_str(raw.get("authorized_by"), section, "authorized_by", index),
        authorized_date=_as_date(raw.get("authorized_date"), section, "authorized_date", index),
        reason=_as_str(raw.get("reason"), section, "reason", index),
        expiry=_as_date(raw.get("expiry"), section, "expiry", index),
        ports=_as_ports(raw.get("ports"), section, index),
        proto=proto,
        gate="; ".join(p for p in gate_parts if p),
        extra={k: v for k, v in raw.items() if k not in known},
    )


def _sg_exception(raw: Any, index: int) -> SgException:
    if not isinstance(raw, dict) or not raw.get("sg_id"):
        raise RegistryError(f"{SG_SECTION}[{index}]: sg_id is required")
    return SgException(
        sg_id=_as_str(raw["sg_id"], SG_SECTION, "sg_id", index),
        sg_name=_as_str(raw.get("sg_name"), SG_SECTION, "sg_name", index),
        ports=_as_ports(raw.get("ports"), SG_SECTION, index),
        expiry=_as_date(raw.get("expiry"), SG_SECTION, "expiry", index),
    )


def parse_registry(doc: Any, source: str = "") -> Registry:
    if not isinstance(doc, dict):
        raise RegistryError("registry: expected a mapping at the top level")
    if PUBLIC_SECTION not in doc:
        raise RegistryError(f"registry: section '{PUBLIC_SECTION}' is required")
    entries: list[ApprovedEntry] = []
    prohibited: list[str] = []
    sg: list[SgException] = []
    for section, value in doc.items():
        if not isinstance(section, str):
            raise RegistryError("registry: section names must be strings")
        if value is None:
            continue
        if section == PROHIBITED_SECTION:
            if not isinstance(value, list):
                raise RegistryError(f"{section}: expected a list of names or patterns")
            prohibited.extend(_as_str(v, section, "pattern", i) for i, v in enumerate(value))
            continue
        if section == SG_SECTION:
            if not isinstance(value, list):
                raise RegistryError(f"{section}: expected a list")
            sg.extend(_sg_exception(v, i) for i, v in enumerate(value))
            continue
        if not isinstance(value, list):
            raise RegistryError(f"{section}: expected a list of exposure entries")
        entries.extend(_entry(v, section, i) for i, v in enumerate(value))
    return Registry(
        entries=entries,
        prohibited=tuple(p for p in prohibited if p),
        sg_exceptions=sg,
        source=source,
    )


def load_registry(path: Path) -> Registry:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RegistryError(f"registry: not valid YAML ({type(exc).__name__})") from exc
    return parse_registry(doc, source=path.name)
