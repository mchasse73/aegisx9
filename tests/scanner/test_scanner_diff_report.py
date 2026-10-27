from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path

from aegisx9_scanner.approved import Registry
from aegisx9_scanner.checks.dns import DnsResult
from aegisx9_scanner.checks.http_exposure import ExposureFinding
from aegisx9_scanner.checks.nuclei import NucleiFinding
from aegisx9_scanner.checks.ports import OpenPort
from aegisx9_scanner.checks.tls import TlsResult
from aegisx9_scanner.checks.uptime import UptimeResult
from aegisx9_scanner.diff import Alert, Kind, Observation, Severity, classify, snapshot_from
from aegisx9_scanner.report import (
    Report,
    load_snapshot,
    render_markdown,
    save_snapshot,
    write_report,
)
from aegisx9_scanner.targets import NeverTargetList, TargetConfig, build_targets
from conftest import TODAY, fake_resolver

RESOLVE = fake_resolver(
    {
        "www.example.com": ["203.0.113.10"],
        "gateway.example.com": ["203.0.113.11"],
        "mail.example.com": ["203.0.113.12"],
        "console.example.com": ["203.0.113.10"],
        "vault.example.com": ["203.0.113.20"],
    }
)
WWW = "console.example.com,www.example.com"  # both names share the address


def _observation(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> Observation:
    targets_cfg.hosts.append("vault.example.com")
    ts = build_targets(targets_cfg, registry, never, today=TODAY, resolver=RESOLVE)
    return Observation(targets=ts, ports_scanned=True)


def test_classify_ports(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> None:
    obs = _observation(targets_cfg, registry, never)
    obs.open_ports = [
        OpenPort("203.0.113.10", 443, "tcp", "https"),  # approved, but not open last run
        OpenPort("203.0.113.12", 25, "tcp", "smtp"),  # approved by ip + ports list, seen before
        OpenPort("203.0.113.10", 22, "tcp", "ssh"),  # known host, unapproved port
        OpenPort("203.0.113.11", 8443, "tcp"),  # known via gateway host, seen before
        OpenPort("203.0.113.30", 3389, "tcp", "ms-wbt-server"),  # unknown address
        OpenPort("203.0.113.20", 8200, "tcp"),  # prohibited name
    ]
    previous = {
        "open_ports": ["203.0.113.11/tcp/8443", "203.0.113.10/tcp/8080", "203.0.113.12/tcp/25"],
        "ports_scanned": True,
    }
    alerts = classify(obs, registry, previous, today=TODAY)
    by_kind = {(a.kind, a.target, a.port): a for a in alerts}
    assert by_kind[(Kind.NEW_OPEN_PORT, WWW, 22)].severity == Severity.HIGH
    stale = by_kind[(Kind.NEW_OPEN_PORT, "gateway.example.com", 8443)]
    assert stale.severity == Severity.MEDIUM and "seen before" in stale.detail
    assert by_kind[(Kind.UNAPPROVED_HOST, "203.0.113.30", 3389)].severity == Severity.HIGH
    assert by_kind[(Kind.PROHIBITED_HOST, "vault.example.com", 8200)].severity == Severity.CRITICAL
    # Approved exposure that changed since the last run is still reported (never "clean").
    opened = by_kind[(Kind.APPROVED_PORT_OPENED, WWW, 443)]
    assert opened.severity == Severity.MEDIUM and "approved" in opened.detail
    assert (Kind.APPROVED_PORT_OPENED, "mail.example.com", 25) not in by_kind  # unchanged
    closed = by_kind[(Kind.PORT_CLOSED, "203.0.113.10", 8080)]
    assert closed.severity == Severity.MEDIUM
    assert (Kind.NEW_OPEN_PORT, WWW, 443) not in by_kind
    assert (Kind.NEW_OPEN_PORT, "mail.example.com", 25) not in by_kind
    assert by_kind[(Kind.NEW_OPEN_PORT, WWW, 22)].to_dict()["kind"] == "NEW_OPEN_PORT"


def test_first_run_has_no_baseline_to_diff(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> None:
    obs = _observation(targets_cfg, registry, never)
    obs.open_ports = [OpenPort("203.0.113.10", 443, "tcp", "https")]
    assert classify(obs, registry, None, today=TODAY) == []


def test_classify_other_checks(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> None:
    targets_cfg.hosts.append("trading.example.com")
    obs = _observation(targets_cfg, registry, never)
    obs.tls = [
        TlsResult("www.example.com", chain_ok=True, days_left=3, headers_fetched=True, headers={}),
        TlsResult(
            "gateway.example.com",
            chain_ok=True,
            days_left=10,
            legacy_versions=["TLSv1"],
            headers_fetched=True,
            headers={"strict-transport-security": "x"},
        ),
        TlsResult("console.example.com", error="SSLCertVerificationError"),
        TlsResult("mail.example.com", error="ConnectionRefusedError"),
        TlsResult("example.net", chain_ok=True, days_left=300, headers_fetched=False),
    ]
    obs.exposures = [
        ExposureFinding(
            "www.example.com", "https://www.example.com/.git/HEAD", "vcs", "critical", "git", 200
        )
    ]
    obs.nuclei = [NucleiFinding("tpl", "Thing", "low", "https://www.example.com", "")]
    obs.dns = [
        DnsResult("www.example.com", "A", ("203.0.113.10",), ("203.0.113.99",)),
        DnsResult("x.example.com", "A", ("1.2.3.4",), error="OSError"),
        DnsResult("txt.example.com", "TXT", ("v=spf1",), supported=False, notes=["dig missing"]),
    ]
    obs.uptime = [
        UptimeResult("https://www.example.com/", 503, 20, 200, 1000),
        UptimeResult("https://gateway.example.com/", 200, 5000, 200, 1000),
        UptimeResult("https://down.example.com/", 0, 0, 200, 1000, error="URLError"),
    ]
    later = date(2027, 6, 1)
    alerts = classify(obs, registry, None, today=later, cert_warn_days=14)
    kinds = [(a.kind, a.severity, a.target) for a in alerts]
    assert (Kind.REFUSED_TARGET, Severity.INFO, "trading.example.com") in kinds
    assert (Kind.EXPIRED_APPROVAL, Severity.MEDIUM, "gateway.example.com") in kinds
    assert (Kind.CERT_EXPIRING, Severity.HIGH, "www.example.com:443") in kinds
    assert (Kind.CERT_EXPIRING, Severity.MEDIUM, "gateway.example.com:443") in kinds
    assert (Kind.EXPOSURE_FINDING, Severity.MEDIUM, "gateway.example.com:443") in kinds
    assert (Kind.EXPOSURE_FINDING, Severity.LOW, "www.example.com:443") in kinds  # missing hsts
    assert (Kind.CERT_INVALID, Severity.HIGH, "console.example.com:443") in kinds
    assert (Kind.CHECK_INCOMPLETE, Severity.LOW, "mail.example.com:443") in kinds
    assert (Kind.EXPOSURE_FINDING, Severity.CRITICAL, "www.example.com") in kinds
    assert (Kind.EXPOSURE_FINDING, Severity.LOW, "https://www.example.com") in kinds
    assert (Kind.DNS_DRIFT, Severity.HIGH, "www.example.com") in kinds
    assert (Kind.CHECK_INCOMPLETE, Severity.MEDIUM, "x.example.com") in kinds
    unsupported = next(a for a in alerts if a.target == "txt.example.com")
    assert unsupported.kind == Kind.CHECK_INCOMPLETE and unsupported.severity == Severity.MEDIUM
    assert "unsupported" in unsupported.detail and "dig missing" in unsupported.detail
    assert (Kind.DOWN, Severity.HIGH, "https://www.example.com/") in kinds
    assert (Kind.DEGRADED, Severity.LOW, "https://gateway.example.com/") in kinds
    assert (Kind.DOWN, Severity.HIGH, "https://down.example.com/") in kinds
    assert all(k != Kind.PORT_CLOSED for k, _, _ in kinds)


def test_incomplete_checks_are_alerts(
    targets_cfg: TargetConfig, registry: Registry, never: NeverTargetList
) -> None:
    obs = _observation(targets_cfg, registry, never)
    obs.ports_scanned = False
    obs.nuclei_expected = True
    alerts = classify(
        obs, registry, {"open_ports": ["203.0.113.10/tcp/22"], "ports_scanned": True}, today=TODAY
    )
    assert [(a.kind, a.target) for a in alerts] == [
        (Kind.CHECK_INCOMPLETE, "port-scan"),
        (Kind.CHECK_INCOMPLETE, "nuclei"),
    ]
    assert all(a.severity == Severity.MEDIUM for a in alerts)
    obs.nuclei_ran = True
    obs.ports_scanned = True
    assert [a.kind for a in classify(obs, registry, None, today=TODAY)] == []
    assert classify(Observation(), registry, None, today=TODAY) == []


def test_snapshot_roundtrip(state_dir: Path) -> None:
    obs = Observation(open_ports=[OpenPort("203.0.113.10", 443, "tcp")], ports_scanned=True)
    snap = snapshot_from(obs)
    assert snap == {
        "open_ports": ["203.0.113.10/tcp/443"],
        "exposures": [],
        "nuclei": [],
        "ports_scanned": True,
    }
    assert load_snapshot(state_dir) is None
    path = save_snapshot(snap, state_dir, now=datetime(2026, 10, 21, tzinfo=UTC))
    assert (path.stat().st_mode & 0o777) == 0o600
    loaded = load_snapshot(state_dir)
    assert loaded is not None and loaded["open_ports"] == snap["open_ports"]
    assert "saved_at" in loaded
    path.write_text("[]")
    assert load_snapshot(state_dir) is None
    path.write_text("{bad")
    assert load_snapshot(state_dir) is None


def _report(alerts: list[Alert], mode: str = "daily", **kw: object) -> Report:
    t0 = datetime(2026, 10, 21, 8, 0, tzinfo=UTC)
    return Report(mode=mode, started_at=t0, finished_at=t0, alerts=alerts, **kw)  # type: ignore[arg-type]


def test_report_clean_and_alerting(state_dir: Path) -> None:
    info = Alert(Kind.PORT_CLOSED, Severity.INFO, "203.0.113.10", "closed", 22, "tcp")
    clean = _report([info], target_count=3)
    assert clean.clean and clean.event_type == "clean" and "clean" in clean.summary
    md = render_markdown(clean)
    assert "CLEAN" in md and "Nothing changed" in md and "Informational" in md
    json_path, md_path = write_report(clean, state_dir)
    doc = json.loads(json_path.read_text())
    assert doc["clean"] and doc["event"] == "clean"
    assert doc["informational"][0]["kind"] == "PORT_CLOSED"
    assert json_path.parent.name == "2026-10-21" and md_path.read_text() == md
    assert (state_dir / "last_report.json").exists()

    bad = _report(
        [
            Alert(Kind.NEW_OPEN_PORT, Severity.HIGH, "www.example.com", "tcp/22 | open", 22, "tcp"),
            Alert(Kind.EXPOSURE_FINDING, Severity.LOW, "www.example.com:443", "no hsts"),
        ],
        notes=["nmap udp skipped"],
    )
    assert not bad.clean and bad.event_type == "exposure_change"
    assert bad.summary == "daily: 1 alerts (1 NEW_OPEN_PORT)"
    md = render_markdown(bad)
    assert "1 ALERT(S)" in md and "tcp/22 \\| open" in md and "## Notes" in md
    assert "www.example.com:22" in md
    assert bad.to_dict()["alerts"][0]["port"] == 22

    down = _report(
        [Alert(Kind.DOWN, Severity.HIGH, "https://www.example.com/", "status 503")], mode="uptime"
    )
    assert down.event_type == "down"
    rt = _report([Alert(Kind.REDTEAM_REGRESSION, Severity.HIGH, "https://g", "x")], mode="redteam")
    assert rt.event_type == "redteam_regression"
    dry = _report([], dry_run=True)
    write_report(dry, state_dir / "dry")
    assert not (state_dir / "dry" / "last_report.json").exists()
    assert "Dry run" in render_markdown(dry)


def test_last_report_is_replaced_atomically(state_dir: Path) -> None:
    """The three units run as different users: an existing 0600 file from another user
    cannot be truncated, but its directory entry can be replaced."""
    last = state_dir / "last_report.json"
    last.write_text('{"stale": true}')
    last.chmod(0o400)  # simulates "owned by someone else": not writable in place
    write_report(_report([], mode="uptime"), state_dir)
    doc = json.loads(last.read_text())
    assert doc["mode"] == "uptime" and "stale" not in doc
    assert (last.stat().st_mode & 0o777) == 0o600
    assert not list(state_dir.glob(".last_report.json.*"))  # no temporary file left behind


def test_severity_threshold_and_parse() -> None:
    r = _report(
        [Alert(Kind.EXPOSURE_FINDING, Severity.LOW, "a", "x")], alert_min_severity=Severity.LOW
    )
    assert not r.clean
    assert Severity.parse("CRITICAL") is Severity.CRITICAL
    assert Severity.parse("bogus") is Severity.MEDIUM
    assert Severity.HIGH.rank > Severity.MEDIUM.rank
