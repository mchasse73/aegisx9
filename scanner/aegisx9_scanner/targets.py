"""Target list: what the scanner is allowed to look at, and what it must never touch.

``targets.yml`` lists hostnames and CIDRs (both WAN blocks, every cloud address) plus the
DNS expectations and uptime URLs. Registry entries are added automatically. Hostnames are
resolved at scan time.

``never_target.yml`` is a deny list checked BEFORE anything else: hostnames, CIDRs and
glob patterns. A target that matches is refused, logged and reported; it is never
resolved, scanned, probed or red-teamed. Live-trading endpoints live there.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from aegisx9_scanner.approved import Registry
from aegisx9_scanner.log import event, log_error

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], list[str]]


class TargetConfigError(ValueError):
    """``targets.yml`` or ``never_target.yml`` is malformed."""


@dataclass(frozen=True)
class DnsExpectation:
    name: str
    rtype: str
    expect: tuple[str, ...]


@dataclass(frozen=True)
class UptimeTarget:
    url: str
    expect_status: int = 200
    max_latency_ms: int = 3000
    addresses: tuple[str, ...] = ()  # validated answers, filled in by build_targets

    @property
    def host(self) -> str:
        return url_host(self.url)


@dataclass(frozen=True)
class Target:
    name: str
    kind: str  # host | ip | cidr
    source: str  # targets.yml | registry:<section>
    addresses: tuple[str, ...] = ()

    @property
    def is_network(self) -> bool:
        return self.kind == "cidr"


@dataclass(frozen=True)
class Refusal:
    """A target the never-target list kept out of the scan.

    ``intentional`` marks an approved-exposure registry entry that the never-target list
    also covers: the name is public on purpose (a live-trading endpoint) and is
    deliberately not scanned. Such a refusal is informational. Every other refusal comes
    from something an operator asked to scan (targets.yml) and is a configuration
    mistake."""

    name: str
    source: str
    rule: str
    intentional: bool = False


@dataclass
class Settings:
    alert_min_severity: str = "medium"
    cert_warn_days: int = 14
    nmap_tcp_top_ports: int = 1000
    nmap_udp_top_ports: int = 100
    http_timeout_s: int = 10
    nuclei_enabled: bool = True
    include_registry: bool = True


@dataclass
class TargetConfig:
    hosts: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    dns: list[DnsExpectation] = field(default_factory=list)
    uptime: list[UptimeTarget] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)


@dataclass
class NeverTargetList:
    hostnames: frozenset[str] = frozenset()
    networks: tuple[IPNetwork, ...] = ()
    patterns: tuple[str, ...] = ()
    reason: str = ""

    def match(self, name: str) -> str | None:
        """The rule that forbids ``name`` (a hostname, IP or CIDR), or ``None``."""
        name = name.strip().lower().rstrip(".")
        if not name:
            return None
        if name in self.hostnames:
            return f"hostname:{name}"
        for pattern in self.patterns:
            if fnmatch.fnmatchcase(name, pattern):
                return f"pattern:{pattern}"
        try:
            net = ipaddress.ip_network(name, strict=False)
        except ValueError:
            return None
        for forbidden in self.networks:
            # overlaps() covers "inside", "contains" and "partly overlapping": any of
            # them means a scan could touch a forbidden address.
            if net.version == forbidden.version and net.overlaps(forbidden):
                return f"cidr:{forbidden}"
        return None

    def match_any(self, names: Iterable[str]) -> str | None:
        for name in names:
            hit = self.match(name)
            if hit:
                return hit
        return None


@dataclass
class TargetSet:
    targets: list[Target]
    dns: list[DnsExpectation]
    uptime: list[UptimeTarget]
    refused: list[Refusal]
    settings: Settings

    @property
    def hosts(self) -> list[Target]:
        return [t for t in self.targets if t.kind == "host"]

    @property
    def scan_targets(self) -> list[str]:
        """What the port scanner gets: every validated address of every hostname (never
        the name itself, which nmap would resolve again and scan only the first answer
        of), plus address and network targets. Names stay on the Target for reports."""
        out: list[str] = []
        for t in self.targets:
            for item in [t.name] if t.is_network else t.addresses:
                if item not in out:
                    out.append(item)
        return out

    @property
    def addresses(self) -> frozenset[str]:
        return frozenset(a for t in self.targets if not t.is_network for a in t.addresses)


def url_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _str_list(value: Any, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise TargetConfigError(f"{name}: expected a list of strings")
    return [v.strip().lower().rstrip(".") for v in value if v.strip()]


def parse_never_target(doc: Any) -> NeverTargetList:
    if doc is None:
        doc = {}
    if not isinstance(doc, dict):
        raise TargetConfigError("never_target: expected a mapping")
    networks: list[IPNetwork] = []
    for cidr in _str_list(doc.get("cidrs"), "never_target.cidrs"):
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError as exc:
            raise TargetConfigError("never_target.cidrs: invalid network") from exc
    return NeverTargetList(
        hostnames=frozenset(_str_list(doc.get("hostnames"), "never_target.hostnames")),
        networks=tuple(networks),
        patterns=tuple(_str_list(doc.get("patterns"), "never_target.patterns")),
        reason=str(doc.get("reason") or ""),
    )


def load_never_target(path: Path) -> NeverTargetList:
    if not path.exists():
        raise TargetConfigError("never_target.yml is required (an empty file is accepted)")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise TargetConfigError(f"never_target: not valid YAML ({type(exc).__name__})") from exc
    return parse_never_target(doc)


def parse_targets(doc: Any) -> TargetConfig:
    if doc is None:
        doc = {}
    if not isinstance(doc, dict):
        raise TargetConfigError("targets: expected a mapping")
    cfg = TargetConfig(
        hosts=_str_list(doc.get("hosts"), "targets.hosts"),
        cidrs=_str_list(doc.get("cidrs"), "targets.cidrs"),
    )
    for cidr in cfg.cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise TargetConfigError("targets.cidrs: invalid network") from exc
    for i, raw in enumerate(doc.get("dns") or []):
        if not isinstance(raw, dict) or not raw.get("name"):
            raise TargetConfigError(f"targets.dns[{i}]: name is required")
        cfg.dns.append(
            DnsExpectation(
                name=str(raw["name"]).strip().lower().rstrip("."),
                rtype=str(raw.get("type", "A")).upper(),
                expect=tuple(sorted(_str_list(raw.get("expect"), f"targets.dns[{i}].expect"))),
            )
        )
    for i, raw in enumerate(doc.get("uptime") or []):
        if not isinstance(raw, dict) or not raw.get("url"):
            raise TargetConfigError(f"targets.uptime[{i}]: url is required")
        url = str(raw["url"]).strip()
        if not url.startswith(("http://", "https://")):
            raise TargetConfigError(f"targets.uptime[{i}].url: must be http(s)")
        cfg.uptime.append(
            UptimeTarget(
                url=url,
                expect_status=int(raw.get("expect_status", 200)),
                max_latency_ms=int(raw.get("max_latency_ms", 3000)),
            )
        )
    settings = doc.get("settings")
    if settings is None:
        settings = {}
    if not isinstance(settings, dict):
        raise TargetConfigError("targets.settings: expected a mapping")
    for key, value in settings.items():
        if not hasattr(cfg.settings, str(key)):
            raise TargetConfigError(f"targets.settings.{key}: unknown setting")
        current = getattr(cfg.settings, str(key))
        if not isinstance(value, type(current)) or isinstance(value, bool) != isinstance(
            current, bool
        ):
            raise TargetConfigError(f"targets.settings.{key}: expected {type(current).__name__}")
        setattr(cfg.settings, str(key), value)
    return cfg


def load_targets(path: Path) -> TargetConfig:
    if not path.exists():
        raise TargetConfigError("targets.yml is required")
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise TargetConfigError(f"targets: not valid YAML ({type(exc).__name__})") from exc
    return parse_targets(doc)


def resolve(name: str) -> list[str]:
    """A/AAAA answers for ``name`` through the system resolver (empty if unresolvable)."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        log_error("dns resolution failed", exc, name=name)
        return []
    return sorted({str(info[4][0]) for info in infos})


def _kind(name: str) -> str:
    try:
        net = ipaddress.ip_network(name, strict=False)
    except ValueError:
        return "host"
    return "ip" if net.num_addresses == 1 else "cidr"


def build_targets(
    cfg: TargetConfig,
    registry: Registry | None,
    never: NeverTargetList,
    *,
    today: Any,
    resolver: Resolver = resolve,
) -> TargetSet:
    """Merge targets.yml with the registry, refuse never-targets, resolve the rest.

    The deny list is applied to the configured name first, then again to every resolved
    address, so a hostname that quietly points into a forbidden block is refused too.
    """
    candidates: list[tuple[str, str]] = [(h, "targets.yml") for h in cfg.hosts]
    candidates += [(c, "targets.yml") for c in cfg.cidrs]
    if registry is not None and cfg.settings.include_registry:
        # Every registry entry stays in scope, expired ones included: an exposure whose
        # approval lapsed must still be looked at (and is then reported as unapproved).
        for entry in registry.entries:
            for domain in entry.domains:
                if "*" not in domain and "?" not in domain:
                    candidates.append((domain, f"registry:{entry.section}"))
            if entry.ip:
                candidates.append((entry.ip, f"registry:{entry.section}"))

    seen: set[str] = set()
    targets: list[Target] = []
    refused: list[Refusal] = []
    for name, source in candidates:
        if name in seen:
            continue
        seen.add(name)
        # Registry entries are approvals, not scan requests: one the never-target list
        # covers is intentionally not scanned.
        intentional = source.startswith("registry:")
        rule = never.match(name)
        if rule:
            refused.append(Refusal(name, source, rule, intentional))
            event("target refused by never_target", name=name, source=source, rule=rule)
            continue
        kind = _kind(name)
        addresses: tuple[str, ...] = ()
        if kind == "host":
            addresses = tuple(resolver(name))
            hit = never.match_any(addresses)
            if hit:
                refused.append(Refusal(name, source, hit, intentional))
                event("target refused by never_target", name=name, source=source, rule=hit)
                continue
        elif kind == "ip":
            addresses = (name,)
        targets.append(Target(name=name, kind=kind, source=source, addresses=addresses))

    dns = [d for d in cfg.dns if not _refuse(d.name, "targets.yml:dns", never, refused)]
    uptime: list[UptimeTarget] = []
    for u in cfg.uptime:
        if _refuse(u.host, "targets.yml:uptime", never, refused):
            continue
        # Resolve now, check every answer, and pin the check to those addresses.
        addresses = (u.host,) if _kind(u.host) == "ip" else tuple(resolver(u.host))
        hit = never.match_any(addresses)
        if hit:
            refused.append(Refusal(name=u.host, source="targets.yml:uptime", rule=hit))
            event("target refused by never_target", name=u.host, source="uptime", rule=hit)
            continue
        uptime.append(replace(u, addresses=addresses))
    return TargetSet(
        targets=targets, dns=dns, uptime=uptime, refused=refused, settings=cfg.settings
    )


def _refuse(name: str, source: str, never: NeverTargetList, refused: list[Refusal]) -> bool:
    rule = never.match(name)
    if not rule:
        return False
    refused.append(Refusal(name=name, source=source, rule=rule))
    event("target refused by never_target", name=name, source=source, rule=rule)
    return True


def check_url_allowed(url: str, never: NeverTargetList, resolver: Resolver = resolve) -> None:
    """Raise ``TargetConfigError`` if a URL's host (or what it resolves to) is forbidden."""
    host = url_host(url)
    if not host:
        raise TargetConfigError("target url: no host")
    rule = never.match(host) or never.match_any(resolver(host))
    if rule:
        event("target refused by never_target", name=host, source="target-url", rule=rule)
        raise TargetConfigError(f"target url refused by never_target ({rule})")
