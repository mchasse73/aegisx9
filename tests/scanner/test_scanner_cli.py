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
from conftest import fake_resolver

RESOLVE = fake_resolver(
    {
        "www.example.com": ["203.0.113.10"],
        "gateway.example.com": ["203.0.113.11"],
        "mail.example.com": ["203.0.113.12"],
        "console.example.com": ["203.0.113.10"],
    }
)


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
    assert (
        not (state_dir / "snapshot.json").exists() and not (state_dir / "last_report.json").exists()
    )
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
        '<port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>'
    )
    monkeypatch.setattr(ports, "run_command", lambda argv, timeout: CommandResult(0, nmap_xml))
    monkeypatch.setattr(
        cli.tls, "check_tls", lambda host, timeout: TlsResult(host, chain_ok=True, days_left=90)
    )

    def fetch(url: str, timeout: int) -> HttpResponse:
        if url == "https://www.example.com/.git/HEAD":
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
    monkeypatch.setattr(
        cli,
        "notify",
        lambda report, md, cfg, env: sent.append({"event": report.event_type})
        or {"webhook": True, "email": False},
    )

    rc = cli.main(
        _args(config_dir, state_dir, "daily"), env={"AEGISX9_SCANNER_ALERT_MIN_SEVERITY": "medium"}
    )
    assert rc == cli.EXIT_ALERTS
    assert sent == [{"event": "exposure_change"}]
    last = json.loads((state_dir / "last_report.json").read_text())
    kinds = {(a["kind"], a["target"]) for a in last["alerts"]}
    assert ("NEW_OPEN_PORT", "console.example.com,www.example.com") in kinds
    assert ("EXPOSURE_FINDING", "www.example.com") in kinds
    assert ("DNS_DRIFT", "gateway.example.com") in kinds and ("DNS_DRIFT", "example.com") in kinds
    assert any("nuclei not installed" in n for n in last["notes"])
    snap = json.loads((state_dir / "snapshot.json").read_text())
    assert snap["open_ports"] == ["203.0.113.10/tcp/22", "203.0.113.10/tcp/443"]

    # Second run: the same unapproved port persists at MEDIUM, nothing is "new".
    rc = cli.main(_args(config_dir, state_dir, "daily"), env={})
    last = json.loads((state_dir / "last_report.json").read_text())
    port = next(a for a in last["alerts"] if a["kind"] == "NEW_OPEN_PORT")
    assert rc == cli.EXIT_ALERTS and port["severity"] == "medium"


def test_uptime_run(config_dir: Path, state_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "resolve", RESOLVE)
    monkeypatch.setattr(
        cli.uptime,
        "fetch",
        lambda url, timeout: HttpResponse(200 if "www" in url else 503, {}, b""),
    )
    sent: list[str] = []
    monkeypatch.setattr(
        cli, "notify", lambda report, md, cfg, env: sent.append(report.event_type) or {}
    )
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_ALERTS
    assert sent == ["down"]
    assert not (state_dir / "snapshot.json").exists()
    monkeypatch.setattr(cli.uptime, "fetch", lambda url, timeout: HttpResponse(200, {}, b""))
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_CLEAN
    assert sent[-1] == "clean"


def test_redteam_run(
    config_dir: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "resolve", RESOLVE)
    monkeypatch.setattr(cli, "notify", lambda report, md, cfg, env: {})
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
    assert getattr(seen["cfg"], "suite_dir") == config_dir and getattr(seen["cfg"], "model") == "m"  # noqa: B009
    last = json.loads((state_dir / "last_report.json").read_text())
    assert last["event"] == "redteam_regression" and last["mode"] == "redteam"


def test_parser_and_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0 and "aegisx9-scan" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])
