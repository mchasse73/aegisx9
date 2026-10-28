"""Compare what was observed with the approved registry and the previous snapshot, and
turn the differences into classified, severity-rated alerts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from enum import StrEnum
from typing import Any

from aegisx9_scanner.approved import Registry
from aegisx9_scanner.checks.dns import DnsResult
from aegisx9_scanner.checks.http_exposure import ExposureFinding
from aegisx9_scanner.checks.nuclei import NucleiFinding
from aegisx9_scanner.checks.ports import OpenPort
from aegisx9_scanner.checks.tls import TlsResult
from aegisx9_scanner.checks.uptime import UptimeResult
from aegisx9_scanner.targets import Refusal, TargetSet


class Kind(StrEnum):
    NEW_OPEN_PORT = "NEW_OPEN_PORT"
    UNAPPROVED_HOST = "UNAPPROVED_HOST"
    PROHIBITED_HOST = "PROHIBITED_HOST"
    CERT_EXPIRING = "CERT_EXPIRING"
    CERT_INVALID = "CERT_INVALID"
    EXPOSURE_FINDING = "EXPOSURE_FINDING"
    DNS_DRIFT = "DNS_DRIFT"
    DOWN = "DOWN"
    DEGRADED = "DEGRADED"
    EXPIRED_APPROVAL = "EXPIRED_APPROVAL"
    REFUSED_TARGET = "REFUSED_TARGET"
    CHECK_INCOMPLETE = "CHECK_INCOMPLETE"
    REDTEAM_REGRESSION = "REDTEAM_REGRESSION"
    PORT_CLOSED = "PORT_CLOSED"
    APPROVED_PORT_OPENED = "APPROVED_PORT_OPENED"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls(text.strip().lower())
        except ValueError:
            return cls.MEDIUM


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Alert:
    kind: Kind
    severity: Severity
    target: str
    detail: str
    port: int | None = None
    proto: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = str(self.kind)
        d["severity"] = str(self.severity)
        return d


@dataclass
class Observation:
    """Everything one run saw. Field names are stable: they form the snapshot."""

    targets: TargetSet | None = None
    open_ports: list[OpenPort] = field(default_factory=list)
    tls: list[TlsResult] = field(default_factory=list)
    exposures: list[ExposureFinding] = field(default_factory=list)
    nuclei: list[NucleiFinding] = field(default_factory=list)
    dns: list[DnsResult] = field(default_factory=list)
    uptime: list[UptimeResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    ports_scanned: bool = False
    udp_scanned: bool = False
    nuclei_ran: bool = False
    nuclei_expected: bool = False  # nuclei is installed and enabled, so it must complete

    def hostnames_for(self, ip: str) -> list[str]:
        if self.targets is None:
            return []
        return sorted(t.name for t in self.targets.hosts if ip in t.addresses)


def snapshot_from(obs: Observation) -> dict[str, Any]:
    """The persisted view of a run: open ports only, so "new" has a stable meaning."""
    return {
        "open_ports": sorted(f"{p.ip}/{p.proto}/{p.port}" for p in obs.open_ports),
        "exposures": sorted(f"{e.url}" for e in obs.exposures),
        "nuclei": sorted(f"{n.host} {n.template_id}" for n in obs.nuclei),
        "ports_scanned": obs.ports_scanned,
    }


def classify(
    obs: Observation,
    registry: Registry,
    previous: dict[str, Any] | None,
    *,
    today: date,
    cert_warn_days: int = 14,
    expect_port_scan: bool = True,
) -> list[Alert]:
    alerts: list[Alert] = []
    prev_ports = set(previous.get("open_ports", [])) if previous else set()
    prev_scanned = bool(previous and previous.get("ports_scanned"))

    if obs.targets is not None:
        alerts.extend(refusal_alerts(obs.targets.refused))

    for entry in registry.expired(today):
        alerts.append(
            Alert(
                Kind.EXPIRED_APPROVAL,
                Severity.MEDIUM,
                ",".join(entry.domains),
                f"approval for {entry.service} expired {entry.expiry}; renew or remove it",
            )
        )

    seen_ports: set[str] = set()
    for port in obs.open_ports:
        key = f"{port.ip}/{port.proto}/{port.port}"
        seen_ports.add(key)
        hosts = obs.hostnames_for(port.ip) or ([port.hostname] if port.hostname else [])
        label = ",".join(hosts) if hosts else port.ip
        if any(registry.is_prohibited(h) for h in hosts):
            alerts.append(
                Alert(
                    Kind.PROHIBITED_HOST,
                    Severity.CRITICAL,
                    label,
                    "a prohibited name answers on the internet",
                    port.port,
                    port.proto,
                )
            )
            continue
        known = registry.is_known(None, port.ip, today) or any(
            registry.is_known(h, None, today) for h in hosts
        )
        approved = registry.is_approved(None, port.ip, port.port, port.proto, today) or any(
            registry.is_approved(h, None, port.port, port.proto, today) for h in hosts
        )
        is_new = key not in prev_ports
        if approved:
            # Approved, but a change against the last run is still a change: a run is
            # only "clean" when nothing moved.
            if prev_scanned and is_new:
                alerts.append(
                    Alert(
                        Kind.APPROVED_PORT_OPENED,
                        Severity.MEDIUM,
                        label,
                        f"{port.proto}/{port.port} ({port.service or 'unknown'}) is approved "
                        "but was not open last run",
                        port.port,
                        port.proto,
                    )
                )
            continue
        if not known:
            alerts.append(
                Alert(
                    Kind.UNAPPROVED_HOST,
                    Severity.HIGH if is_new else Severity.MEDIUM,
                    label,
                    f"{port.proto}/{port.port} ({port.service or 'unknown'}) open on an address "
                    "that is not in the approved registry",
                    port.port,
                    port.proto,
                )
            )
        else:
            alerts.append(
                Alert(
                    Kind.NEW_OPEN_PORT,
                    Severity.HIGH if is_new else Severity.MEDIUM,
                    label,
                    f"{port.proto}/{port.port} ({port.service or 'unknown'}) open but not approved"
                    + ("" if is_new else " (seen before, still unapproved)"),
                    port.port,
                    port.proto,
                )
            )

    if obs.ports_scanned and prev_scanned:
        for key in sorted(prev_ports - seen_ports):
            ip, proto, port_s = key.split("/")
            alerts.append(
                Alert(
                    Kind.PORT_CLOSED,
                    Severity.MEDIUM,
                    ip,
                    f"{proto}/{port_s} was open last run and is closed now",
                    int(port_s),
                    proto,
                )
            )

    for tls in obs.tls:
        alerts.extend(_tls_alerts(tls, cert_warn_days))

    for exp in obs.exposures:
        alerts.append(
            Alert(
                Kind.EXPOSURE_FINDING,
                Severity.parse(exp.severity),
                exp.host,
                f"{exp.description}: {exp.url}",
            )
        )
    for finding in obs.nuclei:
        alerts.append(
            Alert(
                Kind.EXPOSURE_FINDING,
                Severity.parse(finding.severity),
                finding.host or finding.matched_at,
                f"nuclei {finding.template_id}: {finding.name}",
            )
        )
    for dns in obs.dns:
        if dns.error or not dns.supported:
            # A configured check that did not happen is never "clean".
            why = f"dns lookup error ({dns.error})" if dns.error else "dns lookup unsupported"
            if dns.notes:
                why += ": " + "; ".join(dns.notes)
            alerts.append(Alert(Kind.CHECK_INCOMPLETE, Severity.MEDIUM, dns.name, why))
        elif dns.drifted:
            alerts.append(
                Alert(
                    Kind.DNS_DRIFT,
                    Severity.HIGH,
                    dns.name,
                    f"{dns.rtype} expected {list(dns.expected)} observed {list(dns.observed)}",
                )
            )
    alerts.extend(uptime_alerts(obs.uptime))

    if (
        expect_port_scan
        and obs.targets is not None
        and obs.targets.targets
        and not obs.ports_scanned
    ):
        alerts.append(
            Alert(
                Kind.CHECK_INCOMPLETE,
                Severity.MEDIUM,
                "port-scan",
                "the port scan did not complete",
            )
        )
    if obs.nuclei_expected and not obs.nuclei_ran:
        alerts.append(
            Alert(Kind.CHECK_INCOMPLETE, Severity.MEDIUM, "nuclei", "nuclei did not complete")
        )
    return alerts


def uptime_alerts(results: list[UptimeResult]) -> list[Alert]:
    alerts: list[Alert] = []
    for up in results:
        if not up.up:
            why = (
                f"error {up.error}"
                if up.error
                else f"status {up.status} (expected {up.expect_status})"
            )
            alerts.append(Alert(Kind.DOWN, Severity.HIGH, up.url, why))
        elif up.slow:
            alerts.append(
                Alert(
                    Kind.DEGRADED,
                    Severity.LOW,
                    up.url,
                    f"latency {up.latency_ms} ms > {up.max_latency_ms} ms",
                )
            )
    return alerts


def refusal_alerts(refused: list[Refusal]) -> list[Alert]:
    """A never-target named in targets.yml (or its dns/uptime lists) is an operator
    mistake and alerts HIGH. An approved-exposure registry entry that the never-target
    list also covers is public on purpose and intentionally not scanned: it is reported
    as INFO so it never turns every run into an ALERT."""
    return [
        Alert(
            Kind.REFUSED_TARGET,
            Severity.INFO,
            r.name,
            f"{r.source} entry is on the never-target list ({r.rule}): intentionally not scanned",
        )
        if r.intentional
        else Alert(
            Kind.REFUSED_TARGET,
            Severity.HIGH,
            r.name,
            f"{r.source} names a never-target ({r.rule}); it was not scanned. Fix the config.",
        )
        for r in refused
    ]


def _tls_alerts(tls: TlsResult, cert_warn_days: int) -> list[Alert]:
    alerts: list[Alert] = []
    target = f"{tls.host}:{tls.port}"
    if tls.error and not tls.chain_ok:
        if tls.error == "SSLCertVerificationError":
            alerts.append(
                Alert(Kind.CERT_INVALID, Severity.HIGH, target, "certificate failed verification")
            )
        else:
            alerts.append(
                Alert(Kind.CHECK_INCOMPLETE, Severity.LOW, target, f"tls check error ({tls.error})")
            )
        return alerts
    if tls.days_left is not None and tls.days_left < cert_warn_days:
        sev = Severity.HIGH if tls.days_left < cert_warn_days // 2 else Severity.MEDIUM
        alerts.append(
            Alert(Kind.CERT_EXPIRING, sev, target, f"certificate expires in {tls.days_left} days")
        )
    if tls.legacy_versions:
        alerts.append(
            Alert(
                Kind.EXPOSURE_FINDING,
                Severity.MEDIUM,
                target,
                "legacy protocol accepted: " + ", ".join(tls.legacy_versions),
            )
        )
    if tls.headers_fetched and not tls.hsts:
        alerts.append(
            Alert(
                Kind.EXPOSURE_FINDING, Severity.LOW, target, "no Strict-Transport-Security header"
            )
        )
    missing = [h for h in tls.missing_headers if h != "strict-transport-security"]
    if missing:
        alerts.append(
            Alert(
                Kind.EXPOSURE_FINDING,
                Severity.LOW,
                target,
                "missing security headers: " + ", ".join(missing),
            )
        )
    return alerts
