"""Web endpoints to probe: every configured hostname on each of its validated addresses,
every address target, and every web listener the port scan discovered (a new web
server inside a scanned block must get the content probes too). HTTP and HTTPS both."""

from __future__ import annotations

from dataclasses import dataclass

from aegisx9_scanner.checks.http_exposure import base_url
from aegisx9_scanner.checks.ports import OpenPort
from aegisx9_scanner.targets import TargetSet

WEB_PORTS: dict[int, str] = {
    80: "http",
    443: "https",
    8000: "http",
    8080: "http",
    8443: "https",
    8888: "http",
}


@dataclass(frozen=True)
class WebEndpoint:
    host: str  # name for SNI and the Host header; the address itself when there is no name
    address: str
    port: int
    scheme: str

    @property
    def url(self) -> str:
        return base_url(self.scheme, self.host, self.port)

    @property
    def named(self) -> bool:
        return self.host != self.address


def scheme_for(port: OpenPort) -> str | None:
    if port.proto != "tcp":
        return None
    if port.port in WEB_PORTS:
        return WEB_PORTS[port.port]
    service = port.service.lower()
    if "https" in service or "ssl" in service:
        return "https"
    if "http" in service:
        return "http"
    return None


def web_endpoints(targets: TargetSet, open_ports: list[OpenPort]) -> list[WebEndpoint]:
    found: dict[tuple[str, str, int, str], WebEndpoint] = {}

    def add(host: str, address: str, port: int, scheme: str) -> None:
        found.setdefault((host, address, port, scheme), WebEndpoint(host, address, port, scheme))

    for t in targets.targets:
        if t.is_network:
            continue
        for a in t.addresses:
            add(t.name, a, 443, "https")
            add(t.name, a, 80, "http")

    names: dict[str, list[str]] = {}
    for t in targets.hosts:
        for a in t.addresses:
            names.setdefault(a, []).append(t.name)
    for p in open_ports:
        scheme = scheme_for(p)
        if scheme is None:
            continue
        for host in names.get(p.ip) or [p.hostname or p.ip]:
            add(host, p.ip, p.port, scheme)
    return sorted(found.values(), key=lambda e: (e.host, e.address, e.port, e.scheme))
