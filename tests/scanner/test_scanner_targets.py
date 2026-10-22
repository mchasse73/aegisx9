from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from aegisx9_scanner.approved import Registry
from aegisx9_scanner.targets import (
    NeverTargetList,
    TargetConfig,
    TargetConfigError,
    UptimeTarget,
    build_targets,
    check_url_allowed,
    load_never_target,
    load_targets,
    parse_never_target,
    parse_targets,
    resolve,
    url_host,
)
from conftest import TODAY, fake_resolver

RESOLVE = fake_resolver(
    {
        "www.example.com": ["203.0.113.10"],
        "gateway.example.com": ["203.0.113.11"],
        "mail.example.com": ["203.0.113.12"],
        "console.example.com": ["203.0.113.10"],
        "sneaky.example.com": ["192.0.2.7"],
        "dual.example.com": ["203.0.113.13", "2001:db8::13"],
    }
)


def test_never_target_matching(never: NeverTargetList) -> None:
    assert never.match("trading.example.com") == "hostname:trading.example.com"
    assert never.match("TRADING.example.com.") == "hostname:trading.example.com"
    assert never.match("x.trading.example.com") == "pattern:*.trading.example.com"
    assert never.match("my-broker-host") == "pattern:*broker*"
    assert never.match("192.0.2.9") == "cidr:192.0.2.0/24"
    assert never.match("192.0.2.0/25") == "cidr:192.0.2.0/24"
    assert never.match("192.0.0.0/16") == "cidr:192.0.2.0/24"  # a block that contains it
    assert never.match("203.0.113.5") is None
    assert never.match("www.example.com") is None
    assert never.match("") is None
    assert never.match_any(["203.0.113.5", "192.0.2.1"]) == "cidr:192.0.2.0/24"
    assert never.reason.startswith("live-trading")


def test_build_targets_merges_registry_and_refuses(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> None:
    targets_cfg.hosts += ["trading.example.com", "sneaky.example.com", "dual.example.com"]
    targets_cfg.cidrs.append("192.0.2.0/28")
    ts = build_targets(targets_cfg, registry, never, today=TODAY, resolver=RESOLVE)
    names = {t.name for t in ts.targets}
    assert {"www.example.com", "gateway.example.com", "203.0.113.0/27"} <= names
    assert {"mail.example.com", "203.0.113.12", "example.net", "console.example.com"} <= names
    assert "trading.example.com" not in names
    assert "sneaky.example.com" not in names  # resolves into a never CIDR
    assert "192.0.2.0/28" not in names
    refused = {(r.name, r.rule) for r in ts.refused}
    assert ("trading.example.com", "hostname:trading.example.com") in refused
    assert ("sneaky.example.com", "cidr:192.0.2.0/24") in refused
    assert ("192.0.2.0/28", "cidr:192.0.2.0/24") in refused
    www = next(t for t in ts.targets if t.name == "www.example.com")
    assert www.kind == "host" and www.addresses == ("203.0.113.10",)
    assert www.source == "targets.yml"
    ip = next(t for t in ts.targets if t.name == "203.0.113.12")
    assert ip.kind == "ip" and ip.source == "registry:public"
    assert "203.0.113.10" in ts.addresses
    # The port scanner gets validated addresses and networks only, every answer included.
    scan = ts.scan_targets
    assert "203.0.113.0/27" in scan and "203.0.113.13" in scan and "2001:db8::13" in scan
    assert not any(s.endswith("example.com") or s.endswith("example.net") for s in scan)
    assert scan.count("203.0.113.10") == 1
    assert len(ts.dns) == 3 and len(ts.uptime) == 2
    assert all(t.kind == "host" for t in ts.hosts)
    assert ts.uptime[0].addresses == ("203.0.113.10",)


def test_dns_and_uptime_entries_are_also_refused(
    targets_cfg: TargetConfig, never: NeverTargetList
) -> None:
    targets_cfg.dns.append(
        type(targets_cfg.dns[0])(name="trading.example.com", rtype="A", expect=())
    )
    targets_cfg.uptime.append(UptimeTarget(url="https://broker-api.example.com/"))
    targets_cfg.uptime.append(UptimeTarget(url="https://sneaky.example.com/"))  # answer forbidden
    targets_cfg.uptime.append(UptimeTarget(url="http://203.0.113.9:8080/health"))
    ts = build_targets(targets_cfg, None, never, today=TODAY, resolver=RESOLVE)
    assert all(d.name != "trading.example.com" for d in ts.dns)
    assert all("broker" not in u.url and "sneaky" not in u.url for u in ts.uptime)
    assert {r.source for r in ts.refused} == {"targets.yml:dns", "targets.yml:uptime"}
    assert {r.name for r in ts.refused} == {
        "trading.example.com",
        "broker-api.example.com",
        "sneaky.example.com",
    }
    literal = next(u for u in ts.uptime if u.url.startswith("http://203"))
    assert literal.addresses == ("203.0.113.9",)


def test_include_registry_can_be_disabled(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> None:
    targets_cfg.settings.include_registry = False
    ts = build_targets(targets_cfg, registry, never, today=TODAY, resolver=RESOLVE)
    assert {t.source for t in ts.targets} == {"targets.yml"}


def test_expired_registry_entries_stay_in_scope(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> None:
    targets_cfg.hosts.clear()
    later = date(2027, 6, 1)
    assert registry.expired(later)  # the gateway approval lapsed...
    ts = build_targets(targets_cfg, registry, never, today=later, resolver=RESOLVE)
    assert "gateway.example.com" in {t.name for t in ts.targets}  # ...but it is still scanned
    assert "203.0.113.11" in ts.scan_targets


def test_check_url_allowed(never: NeverTargetList) -> None:
    check_url_allowed("https://gateway.example.com/v1", never, resolver=RESOLVE)
    with pytest.raises(TargetConfigError, match="refused"):
        check_url_allowed("https://trading.example.com/", never, resolver=RESOLVE)
    with pytest.raises(TargetConfigError, match="refused"):
        check_url_allowed("https://sneaky.example.com/", never, resolver=RESOLVE)
    with pytest.raises(TargetConfigError, match="no host"):
        check_url_allowed("not a url", never, resolver=RESOLVE)
    assert url_host("https://A.Example.com:8443/x") == "a.example.com"


def test_parse_targets_validation() -> None:
    assert parse_targets(None).hosts == []
    with pytest.raises(TargetConfigError, match="mapping"):
        parse_targets([])
    with pytest.raises(TargetConfigError, match="list of strings"):
        parse_targets({"hosts": "a"})
    with pytest.raises(TargetConfigError, match="invalid network"):
        parse_targets({"cidrs": ["300.1.1.1/8"]})
    with pytest.raises(TargetConfigError, match="name is required"):
        parse_targets({"dns": [{"type": "A"}]})
    with pytest.raises(TargetConfigError, match="url is required"):
        parse_targets({"uptime": [{}]})
    with pytest.raises(TargetConfigError, match="url is required"):
        parse_targets({"uptime": ["https://www.example.com/"]})  # a bare string is not an entry
    with pytest.raises(TargetConfigError, match="http"):
        parse_targets({"uptime": [{"url": "ftp://x"}]})
    with pytest.raises(TargetConfigError, match="unknown setting"):
        parse_targets({"settings": {"nope": 1}})
    with pytest.raises(TargetConfigError, match="expected int"):
        parse_targets({"settings": {"cert_warn_days": "14"}})
    with pytest.raises(TargetConfigError, match="expected bool"):
        parse_targets({"settings": {"nuclei_enabled": 1}})
    with pytest.raises(TargetConfigError, match="settings: expected a mapping"):
        parse_targets({"settings": []})
    cfg = parse_targets({"settings": {"cert_warn_days": 30}, "dns": [{"name": "A.example.com."}]})
    assert cfg.settings.cert_warn_days == 30
    assert cfg.dns[0].name == "a.example.com" and cfg.dns[0].rtype == "A"


def test_parse_never_target_validation() -> None:
    assert parse_never_target(None).hostnames == frozenset()
    with pytest.raises(TargetConfigError, match="mapping"):
        parse_never_target("x")
    with pytest.raises(TargetConfigError, match="invalid network"):
        parse_never_target({"cidrs": ["nope"]})


def test_loaders_require_files_and_valid_yaml(tmp_path: Path) -> None:
    with pytest.raises(TargetConfigError, match="required"):
        load_targets(tmp_path / "missing.yml")
    with pytest.raises(TargetConfigError, match="required"):
        load_never_target(tmp_path / "missing.yml")
    bad = tmp_path / "bad.yml"
    bad.write_text("hosts: [\n")
    with pytest.raises(TargetConfigError, match="not valid YAML"):
        load_targets(bad)
    with pytest.raises(TargetConfigError, match="not valid YAML"):
        load_never_target(bad)
    empty = tmp_path / "empty.yml"
    empty.write_text("")
    assert load_never_target(empty).patterns == ()


def test_resolve_handles_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def boom(*_a: object, **_k: object) -> list[object]:
        raise socket.gaierror("x")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert resolve("nothing.invalid") == []
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_a, **_k: [(2, 1, 6, "", ("203.0.113.10", 0)), (2, 1, 6, "", ("203.0.113.10", 0))],
    )
    assert resolve("www.example.com") == ["203.0.113.10"]
