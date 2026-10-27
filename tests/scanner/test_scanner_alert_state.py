"""Notify on a change of state, not on every run (#96)."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegisx9_scanner import alert_state, notify
from aegisx9_scanner.alert_state import Decision, NotifyState, decide
from aegisx9_scanner.diff import Alert, Kind, Severity
from aegisx9_scanner.fsutil import ensure_group_dir
from aegisx9_scanner.report import Report, write_report

T0 = datetime(2026, 10, 27, 8, tzinfo=UTC)
DOWN = Alert(Kind.DOWN, Severity.HIGH, "https://www.example.com/", "status 503")
DOWN_2 = Alert(Kind.DOWN, Severity.HIGH, "https://gateway.example.com/", "status 503")


def _report(mode: str, alerts: list[Alert], at: datetime = T0) -> Report:
    return Report(mode=mode, started_at=at, finished_at=at, alerts=alerts)


def _state(alerts: list[Alert], at: datetime = T0, mode: str = "uptime") -> NotifyState:
    r = _report(mode, alerts, at)
    return NotifyState(clean=r.clean, fingerprint=alert_state.fingerprint(r), sent_at=at)


def test_uptime_first_failure_alerts_and_first_clean_is_quiet() -> None:
    assert decide(_report("uptime", [DOWN]), None, now=T0) == Decision(True, "alert")
    assert decide(_report("uptime", []), None, now=T0) == Decision(False, "quiet")
    assert decide(_report("uptime", []), _state([]), now=T0) == Decision(False, "quiet")


def test_unchanged_failure_is_suppressed_then_reminded_after_the_interval() -> None:
    prev = _state([DOWN])
    soon = T0 + timedelta(minutes=5)
    assert decide(_report("uptime", [DOWN], soon), prev, now=soon) == Decision(False, "unchanged")
    # Details such as latency or status text do not make a new state.
    other_detail = Alert(Kind.DOWN, Severity.HIGH, DOWN.target, "URLError")
    assert not decide(_report("uptime", [other_detail], soon), prev, now=soon).send
    later = T0 + alert_state.REALERT_AFTER
    assert decide(_report("uptime", [DOWN], later), prev, now=later) == Decision(True, "reminder")


def test_a_different_failure_set_is_a_change() -> None:
    prev = _state([DOWN])
    soon = T0 + timedelta(minutes=5)
    assert decide(_report("uptime", [DOWN, DOWN_2], soon), prev, now=soon) == Decision(
        True, "changed"
    )
    assert decide(_report("uptime", [DOWN], soon), _state([]), now=soon) == Decision(True, "alert")


def test_recovery_is_sent_once() -> None:
    assert decide(_report("uptime", []), _state([DOWN]), now=T0) == Decision(True, "recovered")
    assert decide(_report("redteam", []), _state([DOWN]), now=T0) == Decision(True, "recovered")


def test_daily_always_sends_a_summary() -> None:
    clean = _report("daily", [])
    assert decide(clean, None, now=T0) == Decision(True, "summary")
    assert decide(clean, _state([], mode="daily"), now=T0) == Decision(True, "summary")
    assert decide(_report("daily", [DOWN]), _state([DOWN]), now=T0) == Decision(True, "summary")
    assert decide(clean, _state([DOWN], mode="daily"), now=T0) == Decision(True, "recovered")


def test_informational_findings_do_not_change_the_fingerprint() -> None:
    refused = Alert(Kind.REFUSED_TARGET, Severity.INFO, "trading.example.com", "never-target")
    r = _report("uptime", [refused])
    assert r.clean and alert_state.fingerprint(r) == ""
    assert decide(r, None, now=T0) == Decision(False, "quiet")


def test_state_round_trip_is_group_readable(state_dir: Path) -> None:
    r = _report("uptime", [DOWN])
    alert_state.record(r, state_dir, now=T0)
    path = alert_state.state_path(state_dir, "uptime")
    assert stat.S_IMODE(path.stat().st_mode) == alert_state.STATE_FILE_MODE
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o770
    doc = json.loads(path.read_text())
    assert doc["mode"] == "uptime" and doc["clean"] is False
    loaded = alert_state.load_state(state_dir, "uptime")
    assert loaded == NotifyState(False, alert_state.fingerprint(r), T0)
    assert alert_state.load_state(state_dir, "redteam") is None


def test_corrupt_state_errs_towards_notifying(state_dir: Path) -> None:
    path = alert_state.state_path(state_dir, "uptime")
    path.parent.mkdir()
    path.write_text("{not json")
    assert alert_state.load_state(state_dir, "uptime") is None
    path.write_text(json.dumps({"clean": True}))
    assert alert_state.load_state(state_dir, "uptime") is None
    assert alert_state.gate(_report("uptime", [DOWN]), state_dir, now=T0).send


def test_unsaved_state_is_logged_not_raised(
    state_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*a: object, **k: object) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(alert_state, "write_atomic", boom)
    alert_state.record(_report("uptime", [DOWN]), state_dir, now=T0)
    assert not alert_state.state_path(state_dir, "uptime").exists()


def test_gate_logs_suppression(state_dir: Path) -> None:
    alert_state.record(_report("uptime", [DOWN]), state_dir, now=T0)
    soon = T0 + timedelta(minutes=5)
    assert alert_state.gate(_report("uptime", [DOWN], soon), state_dir, now=soon) == Decision(
        False, "unchanged"
    )


def test_subject_names_the_reason() -> None:
    assert "] ALERT:" in notify.subject_for(_report("uptime", [DOWN]), "alert")
    assert "ALERT (still failing)" in notify.subject_for(_report("uptime", [DOWN]), "reminder")
    assert "] RECOVERED:" in notify.subject_for(_report("uptime", []), "recovered")
    assert "] CLEAN:" in notify.subject_for(_report("daily", []), "summary")
    assert notify.build_event(_report("uptime", []), "recovered")["notify_reason"] == "recovered"


def test_report_directories_are_group_writable_whatever_the_umask(state_dir: Path) -> None:
    old = os.umask(0o022)
    try:
        write_report(_report("uptime", [DOWN]), state_dir)
        ensure_group_dir(state_dir / "work" / "daily" / "run")
    finally:
        os.umask(old)
    reports = state_dir / "reports"
    for d in (reports, *reports.iterdir(), state_dir / "work", state_dir / "work" / "daily"):
        assert stat.S_IMODE(d.stat().st_mode) == 0o770, d
    # An existing directory is left alone: its mode belongs to whoever created it.
    state_dir.chmod(0o750)
    ensure_group_dir(state_dir)
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o750
