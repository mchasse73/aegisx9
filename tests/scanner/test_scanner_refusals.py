"""Two kinds of never-target refusal (#96).

* A registry (approved-exposure) entry that never_target also covers is public on
  purpose and intentionally not scanned: informational, never an ALERT, and
  ``validate-config`` accepts it.
* A never-target an operator asked to scan in targets.yml is a mistake: HIGH, it alerts
  (and notifies), and ``validate-config`` rejects it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisx9_scanner import cli
from aegisx9_scanner.checks.http_exposure import HttpResponse
from aegisx9_scanner.report import Report
from conftest import fake_resolver

RESOLVE = fake_resolver(
    {"www.example.com": ["203.0.113.10"], "gateway.example.com": ["203.0.113.11"]}
)
TRADING = "trading.example.com"
REGISTRY_ENTRY = f"""
trading_public:
  - domain: {TRADING}
    service: live-trading
    purpose: Live-trading endpoint, public by design and never scanned
    authorized_by: <security-owner>
    authorized_date: "2026-01-15"
    reason: Brokers connect from the internet.
    expiry: never
"""


def _args(config_dir: Path, state_dir: Path, *rest: str) -> list[str]:
    return ["--config", str(config_dir), "--state", str(state_dir), *rest]


def _registry_never_target(config_dir: Path) -> None:
    with (config_dir / "approved_public.yml").open("a") as fh:
        fh.write(REGISTRY_ENTRY)


def _operator_never_target(config_dir: Path) -> None:
    (config_dir / "targets.yml").write_text(
        "hosts:\n  - www.example.com\nuptime:\n  - url: https://www.example.com/\n"
        f"  - url: https://{TRADING}/\n"
    )


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    out: list[str] = []

    def fake_notify(
        report: Report, md: str, cfg: object, env: dict[str, str], reason: str = ""
    ) -> dict[str, bool]:
        out.append(reason)
        return {"webhook": True, "email": False}

    monkeypatch.setattr(cli, "notify", fake_notify)
    monkeypatch.setattr(cli, "resolve", RESOLVE)
    monkeypatch.setattr(
        cli.uptime, "fetch", lambda url, timeout, address="": HttpResponse(200, {}, b"")
    )
    return out


def _refusals(doc: dict[str, list[dict[str, str]]]) -> tuple[list[dict[str, str]], ...]:
    alerting = [a for a in doc["alerts"] if a["kind"] == "REFUSED_TARGET"]
    info = [a for a in doc["informational"] if a["kind"] == "REFUSED_TARGET"]
    return alerting, info


def _last(state_dir: Path) -> dict[str, list[dict[str, str]]]:
    doc: dict[str, list[dict[str, str]]] = json.loads((state_dir / "last_report.json").read_text())
    return doc


def test_validate_config_accepts_registry_never_targets_only(
    config_dir: Path, state_dir: Path
) -> None:
    _registry_never_target(config_dir)
    assert cli.main(_args(config_dir, state_dir, "validate-config"), env={}) == cli.EXIT_CLEAN
    _operator_never_target(config_dir)
    assert cli.main(_args(config_dir, state_dir, "validate-config"), env={}) == cli.EXIT_CONFIG


def test_uptime_registry_refusal_is_informational(
    config_dir: Path, state_dir: Path, sent: list[str]
) -> None:
    _registry_never_target(config_dir)
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_CLEAN
    alerting, info = _refusals(_last(state_dir))
    assert alerting == [] and [a["target"] for a in info] == [TRADING]
    assert info[0]["severity"] == "info" and "intentionally not scanned" in info[0]["detail"]
    assert sent == []


def test_uptime_operator_refusal_alerts_and_notifies(
    config_dir: Path, state_dir: Path, sent: list[str]
) -> None:
    _operator_never_target(config_dir)
    assert cli.main(_args(config_dir, state_dir, "uptime"), env={}) == cli.EXIT_ALERTS
    alerting, _info = _refusals(_last(state_dir))
    assert [(a["target"], a["severity"]) for a in alerting] == [(TRADING, "high")]
    assert sent == ["alert"]


def test_daily_both_kinds(config_dir: Path, state_dir: Path) -> None:
    _registry_never_target(config_dir)
    assert cli.main(_args(config_dir, state_dir, "--dry-run", "daily"), env={}) == cli.EXIT_CLEAN
    doc = json.loads(sorted((state_dir / "reports").rglob("daily-*.json"))[-1].read_text())
    alerting, info = _refusals(doc)
    assert alerting == [] and [a["target"] for a in info] == [TRADING]
    # The same name listed in targets.yml comes from the operator first: it alerts.
    (config_dir / "targets.yml").write_text(f"hosts:\n  - {TRADING}\n")
    rc = cli.main(_args(config_dir, state_dir, "--dry-run", "daily"), env={})
    assert rc == cli.EXIT_ALERTS


def test_redteam_both_kinds(config_dir: Path, state_dir: Path, sent: list[str]) -> None:
    _registry_never_target(config_dir)
    # A registry never-target does not affect a red-team run against an allowed URL.
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
    assert rc == cli.EXIT_CLEAN
    # Asking to red-team a never-target is always refused, registry entry or not.
    rc = cli.main(
        _args(config_dir, state_dir, "redteam", "--target-url", f"https://{TRADING}/"), env={}
    )
    assert rc == cli.EXIT_CONFIG and sent == []
