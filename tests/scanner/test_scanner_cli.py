from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisx9_scanner import cli
from aegisx9_scanner.checks import CommandResult, ports
from aegisx9_scanner.checks.http_exposure import HttpResponse
from aegisx9_scanner.checks.tls import TlsResult
from aegisx9_scanner.diff import Alert, Kind, Severity
from aegisx9_scanner.redteam_external import RedteamOutcome
from aegisx9_scanner.report import Report
from conftest import fake_resolver

RESOLVE = fake_resolver(
    {
        "www.example.com": ["203.0.113.10"],
        "gateway.example.com": ["203.0.113.11"],
        "mail.example.com": ["203.0.113.12"],
        "console.example.com": ["203.0.113.10"],
    }
)
WWW = "console.example.com,www.example.com"


def _args(config_dir: Path, state_dir: Path, *rest: str) -> list[str]:
    return ["--config", str(config_dir), "--state", str(state_dir), *rest]


def test_validate_config(config_dir: Path, state_dir: Path) -> None:
    assert cli.main(_args(config_dir, state_dir, "validate-config"), env={}) == cli.EXIT_CLEAN
    targets = config_dir / "targets.yml"
    targets.write_text("hosts:\n  - trading.example.com\n")
    assert cli.main(_args(config_dir, state_dir, "validate-config"), env={}) == cli.EXIT_CONFIG
    (config_dir / "approved_public.yml").write_text("gated: []\n")
    assert cli.main(_args(config_dir, state_dir, "validate-config"), env={}) == cli.EXIT_CONFIG
    (config_dir / "never_target.yml").unlink()
    assert cli.main(_args(config_dir, state_dir, "validate-config"), env={}) == cli.EXIT_CONFIG


def test_global_options_must_precede_the_subcommand(config_dir: Path, state_dir: Path) -> None:
    """The systemd units and the deploy role pass --config/--state first; the reverse
    order is rejected by argparse, so guard the contract."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["validate-config", "--config", str(config_dir), "--state", str(state_dir)])
    assert exc.value.code == 2
    assert cli.main(_args(config_dir, state_dir, "validate-config"), env={}) == cli.EXIT_CLEAN


def test_unreadable_config_dir(tmp_path: Path, state_dir: Path) -> None:
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "never_target.yml").write_text("")
    (cfg / "targets.yml").mkdir()  # a directory where a file is expected -> OSError
    assert cli.main(_args(cfg, state_dir, "daily"), env={}) == cli.EXIT_CONFIG


def test_daily_dry_run_touches_no_network(
    config_dir: Path, state_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = cli.main(_args(config_dir, state_dir, "--dry-run", "daily"), env={})
    assert rc == cli.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "CLEAN" in out and "Dry run" in out
    assert not (state_dir / "snapshot.json").exists()
    assert not (state_dir / "last_report.json").exists()
    assert list((state_dir / "reports").rglob("daily-*.json"))


def test_daily_full_run_with_fakes(
    config_dir: Path, state_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "resolve", RESOLVE)
    monkeypatch.setattr(ports, "is_privileged", lambda: False)
    monkeypatch.setattr(ports, "find_tool", lambda n: "/x/nmap")
    nmap_xml = (
        '<nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
        '<port protocol="tcp" portid="443"><state state="open"/></port></ports></host>'
        '<host><address addr="203.0.113.20" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port>'
        "</ports></host></nmaprun>"
    )
    nmap_calls: list[list[str]] = []

    def run_nmap(argv: list[str], timeout: int) -> CommandResult:
        nmap_calls.append(argv)
        return CommandResult(0, nmap_xml)

    monkeypatch.setattr(ports, "run_command", run_nmap)
    tls_seen: list[tuple[str, int, str]] = []

    def fake_tls(host: str, port: int = 443, *, address: str = "", timeout: int = 10) -> TlsResult:
        tls_seen.append((host, port, address))
        return TlsResult(host, port, address, chain_ok=True, days_left=90)

    monkeypatch.setattr(cli.tls, "check_tls", fake_tls)
    fetched: list[tuple[str, str]] = []

    def fetch(url: str, timeout: int, address: str = "") -> HttpResponse:
        fetched.append((url, address))
        if url == "http://203.0.113.20:8080/.git/HEAD":  # found only by address, on plain HTTP
            return HttpResponse(200, {"content-type": "text/plain"}, b"ref: refs/heads/main\n")
        return HttpResponse(404, {}, b"")

    monkeypatch.setattr(cli.http_exposure, "fetch", fetch)
    monkeypatch.setattr(cli.nuclei, "find_tool", lambda n: None)
    monkeypatch.setattr(
        cli.dns_check,
        "system_lookup",
        lambda name, rtype: ["203.0.113.10"] if name == "www.example.com" else [],
    )
    sent: list[dict[str, object]] = []

    def fake_notify(
        report: object, md: str, cfg: object, env: dict[str, str], reason: str = ""
    ) -> dict[str, bool]:
        sent.append({"event": getattr(report, "event_type"), "reason": reason})  # noqa: B009
        return {"webhook": True, "email": False}

    monkeypatch.setattr(cli, "notify", fake_notify)

    rc = cli.main(
        _args(config_dir, state_dir, "daily"), env={"AEGISX9_SCANNER_ALERT_MIN_SEVERITY": "medium"}
    )
    assert rc == cli.EXIT_ALERTS
    assert sent == [{"event": "exposure_change", "reason": "summary"}]
    # nmap got validated addresses and networks, never a hostname.
    scanned = nmap_calls[0]
    assert "203.0.113.10" in scanned and "203.0.113.0/27" in scanned
    assert not any(a.endswith("example.com") for a in scanned)
    # Web checks ran for names (pinned to their address), for address targets, on both
    # schemes, and for the listener nmap discovered inside the block.
    assert ("www.example.com", 443, "203.0.113.10") in tls_seen
    assert ("https://www.example.com/.git/HEAD", "203.0.113.10") in fetched
    assert ("http://www.example.com/.git/HEAD", "203.0.113.10") in fetched
    assert ("https://203.0.113.12/.git/HEAD", "203.0.113.12") in fetched
    assert ("http://203.0.113.20:8080/.git/HEAD", "203.0.113.20") in fetched
    last = json.loads((state_dir / "last_report.json").read_text())
    kinds = {(a["kind"], a["target"]) for a in last["alerts"]}
    assert ("NEW_OPEN_PORT", WWW) in kinds
    assert ("UNAPPROVED_HOST", "203.0.113.20") in kinds
    assert ("EXPOSURE_FINDING", "203.0.113.20") in kinds
    assert ("DNS_DRIFT", "gateway.example.com") in kinds and ("DNS_DRIFT", "example.com") in kinds
    assert any("nuclei not installed" in n for n in last["notes"])
    snap = json.loads((state_dir / "snapshot.json").read_text())
    assert snap["open_ports"] == [
        "203.0.113.10/tcp/22",
        "203.0.113.10/tcp/443",
        "203.0.113.20/tcp/8080",
    ]

    # Second run: the same unapproved port persists at MEDIUM, nothing is "new".
    rc = cli.main(_args(config_dir, state_dir, "daily"), env={})
    last = json.loads((state_dir / "last_report.json").read_text())
    port = next(a for a in last["alerts"] if a["kind"] == "NEW_OPEN_PORT")
    assert rc == cli.EXIT_ALERTS and port["severity"] == "medium"
    # The daily scan is the heartbeat: it sends a summary every run, even unchanged.
    assert [s["reason"] for s in sent] == ["summary", "summary"]
    assert last["run_id"] != snap.get("run_id")


def test_uptime_run(config_dir: Path, state_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "resolve", RESOLVE)
    pinned: list[str] = []

    def fetch(url: str, timeout: int, address: str = "") -> HttpResponse:
        pinned.append(address)
        return HttpResponse(200 if "www" in url else 503, {}, b"")

    monkeypatch.setattr(cli.uptime, "fetch", fetch)
    sent: list[tuple[str, str]] = []

    def fake_notify(
        report: Report, md: str, cfg: object, env: dict[str, str], reason: str = ""
    ) -> dict[str, bool]:
        sent.append((report.event_type, reason))
        return {"webhook": True, "email": False}

    monkeypatch.setattr(cli, "notify", fake_notify)
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_ALERTS
    assert sent == [("down", "alert")] and pinned == ["203.0.113.10", "203.0.113.11"]
    assert not (state_dir / "snapshot.json").exists()
    # The same failure five minutes later is not sent again (the alert flood, #96).
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_ALERTS
    assert sent == [("down", "alert")]
    monkeypatch.setattr(
        cli.uptime, "fetch", lambda url, timeout, address="": HttpResponse(200, {}, b"")
    )
    # Recovery is announced once; a clean run after a clean run is silent.
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_CLEAN
    assert sent[-1] == ("clean", "recovered")
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_CLEAN
    assert len(sent) == 2


def test_undelivered_notice_is_retried(
    config_dir: Path, state_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A notice no channel accepted is not remembered as sent."""
    monkeypatch.setattr(cli, "resolve", RESOLVE)
    monkeypatch.setattr(
        cli.uptime, "fetch", lambda url, timeout, address="": HttpResponse(503, {}, b"")
    )
    sent: list[str] = []

    def failing(
        report: Report, md: str, cfg: object, env: dict[str, str], reason: str = ""
    ) -> dict[str, bool]:
        sent.append(reason)
        return {"webhook": False, "email": False}

    monkeypatch.setattr(cli, "notify", failing)
    cli.main(_args(config_dir, state_dir, "uptime"), env={})
    cli.main(_args(config_dir, state_dir, "uptime"), env={})
    assert sent == ["alert", "alert"]
    assert not (state_dir / "notify" / "uptime.json").exists()


def test_uptime_refusals_alone_do_not_alert(
    config_dir: Path, state_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A never-target named in the configuration is reported, not alerted: with the
    real registry some names are on the never-target list by design (#96)."""
    (config_dir / "targets.yml").write_text(
        "uptime:\n  - url: https://www.example.com/\n  - url: https://trading.example.com/\n"
    )
    monkeypatch.setattr(cli, "resolve", RESOLVE)
    monkeypatch.setattr(
        cli.uptime, "fetch", lambda url, timeout, address="": HttpResponse(200, {}, b"")
    )
    sent: list[str] = []
    monkeypatch.setattr(
        cli, "notify", lambda report, md, cfg, env, reason="": sent.append(reason) or {}
    )
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_CLEAN
    last = json.loads((state_dir / "last_report.json").read_text())
    assert last["clean"] and last["refused_count"] >= 1 and last["alerts"] == []
    refused = {a["target"] for a in last["informational"] if a["kind"] == "REFUSED_TARGET"}
    assert "trading.example.com" in refused
    assert sent == []


def test_redteam_run(
    config_dir: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "resolve", RESOLVE)
    monkeypatch.setattr(cli, "notify", lambda report, md, cfg, env, reason="": {})
    # No target: nothing to do, exit clean (the timer must not page anyone).
    assert cli.main(_args(config_dir, state_dir, "redteam"), env={}) == cli.EXIT_CLEAN
    # A never-target is refused before anything runs.
    rc = cli.main(
        _args(config_dir, state_dir, "redteam", "--target-url", "https://trading.example.com/"),
        env={},
    )
    assert rc == cli.EXIT_CONFIG
    # Dry run: never executes the suites.
    rc = cli.main(
        _args(
            config_dir,
            state_dir,
            "--dry-run",
            "redteam",
            "--target-url",
            "https://gateway.example.com/",
        ),
        env={},
    )
    assert rc == cli.EXIT_CLEAN and "suites not executed" in capsys.readouterr().out
    seen: dict[str, object] = {}

    def fake_run(cfg: object, work: Path) -> RedteamOutcome:
        seen["cfg"] = cfg
        seen["work"] = work
        return RedteamOutcome(
            alerts=[Alert(Kind.REDTEAM_REGRESSION, Severity.HIGH, "g", "x")], notes=["n"]
        )

    monkeypatch.setattr(cli, "run_redteam", fake_run)
    env = {
        "AEGISX9_SCANNER_REDTEAM_TARGET_URL": "https://gateway.example.com",
        "AEGISX9_SCANNER_REDTEAM_MODEL": "m",
    }
    rc = cli.main(_args(config_dir, state_dir, "redteam", "--suite-dir", str(config_dir)), env=env)
    assert rc == cli.EXIT_ALERTS
    cfg = seen["cfg"]
    assert getattr(cfg, "suite_dir") == config_dir and getattr(cfg, "model") == "m"  # noqa: B009
    last = json.loads((state_dir / "last_report.json").read_text())
    assert last["event"] == "redteam_regression" and last["mode"] == "redteam"
    work = seen["work"]
    assert isinstance(work, Path) and work == state_dir / "work" / "redteam" / last["run_id"]


def test_parser_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0 and "aegisx9-scan" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])
