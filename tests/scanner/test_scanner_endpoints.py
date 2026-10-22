from __future__ import annotations

from aegisx9_scanner.approved import Registry
from aegisx9_scanner.checks.ports import OpenPort
from aegisx9_scanner.endpoints import scheme_for, web_endpoints
from aegisx9_scanner.targets import NeverTargetList, TargetConfig, build_targets
from conftest import TODAY, fake_resolver

RESOLVE = fake_resolver(
    {
        "www.example.com": ["203.0.113.10"],
        "gateway.example.com": ["203.0.113.11"],
        "mail.example.com": ["203.0.113.12"],
        "console.example.com": ["203.0.113.10"],
    }
)


def test_scheme_for() -> None:
    assert scheme_for(OpenPort("a", 443, "tcp")) == "https"
    assert scheme_for(OpenPort("a", 8080, "tcp")) == "http"
    assert scheme_for(OpenPort("a", 9443, "tcp", "ssl/http")) == "https"
    assert scheme_for(OpenPort("a", 3000, "tcp", "http-proxy")) == "http"
    assert scheme_for(OpenPort("a", 22, "tcp", "ssh")) is None
    assert scheme_for(OpenPort("a", 80, "udp")) is None


def test_web_endpoints_cover_names_addresses_and_discovered_listeners(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> None:
    ts = build_targets(targets_cfg, registry, never, today=TODAY, resolver=RESOLVE)
    open_ports = [
        OpenPort("203.0.113.10", 443, "tcp", "https"),
        OpenPort("203.0.113.10", 8443, "tcp"),  # extra listener on a named address
        OpenPort("203.0.113.20", 8080, "tcp", "http-proxy"),  # web server found in the block
        OpenPort("203.0.113.20", 22, "tcp", "ssh"),
    ]
    eps = web_endpoints(ts, open_ports)
    urls = {(e.url, e.address) for e in eps}
    # Every configured name on each of its addresses, HTTP and HTTPS.
    assert ("https://www.example.com", "203.0.113.10") in urls
    assert ("http://www.example.com", "203.0.113.10") in urls
    assert ("https://console.example.com", "203.0.113.10") in urls
    # Address-only registry targets get probed by address.
    assert ("https://203.0.113.12", "203.0.113.12") in urls
    assert ("http://203.0.113.12", "203.0.113.12") in urls
    # Discovered listeners: with every name that maps to the address, or by address.
    assert ("https://www.example.com:8443", "203.0.113.10") in urls
    assert ("https://console.example.com:8443", "203.0.113.10") in urls
    assert ("http://203.0.113.20:8080", "203.0.113.20") in urls
    assert not any(e.port == 22 for e in eps)
    anon = next(e for e in eps if e.address == "203.0.113.20")
    assert not anon.named and anon.host == "203.0.113.20"
    assert next(e for e in eps if e.host == "www.example.com").named
    assert len(eps) == len(set(eps))  # no duplicates
