"""Run reports: a JSON document and a Markdown summary per run, a dated "clean" report
when nothing is wrong, and the snapshot the next run diffs against."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisx9_scanner import __version__
from aegisx9_scanner.diff import Alert, Severity

SNAPSHOT_FILE = "snapshot.json"
LAST_REPORT_FILE = "last_report.json"
REPORTS_DIR = "reports"


@dataclass
class Report:
    mode: str
    started_at: datetime
    finished_at: datetime
    alerts: list[Alert]
    notes: list[str] = field(default_factory=list)
    alert_min_severity: Severity = Severity.MEDIUM
    target_count: int = 0
    refused_count: int = 0
    run_id: str = field(default_factory=lambda: secrets.token_hex(6))
    version: str = __version__
    dry_run: bool = False
    paths: dict[str, str] = field(default_factory=dict)

    @property
    def alerting(self) -> list[Alert]:
        return [a for a in self.alerts if a.severity.rank >= self.alert_min_severity.rank]

    @property
    def informational(self) -> list[Alert]:
        return [a for a in self.alerts if a.severity.rank < self.alert_min_severity.rank]

    @property
    def clean(self) -> bool:
        return not self.alerting

    @property
    def event_type(self) -> str:
        if self.clean:
            return "clean"
        kinds = {str(a.kind) for a in self.alerting}
        if self.mode == "uptime" or kinds <= {"DOWN", "DEGRADED"}:
            return "down"
        if self.mode == "redteam":
            return "redteam_regression"
        return "exposure_change"

    @property
    def summary(self) -> str:
        if self.clean:
            return f"{self.mode}: clean, {self.target_count} targets, nothing changed"
        counts: dict[str, int] = {}
        for a in self.alerting:
            counts[str(a.kind)] = counts.get(str(a.kind), 0) + 1
        parts = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
        return f"{self.mode}: {len(self.alerting)} alerts ({parts})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "aegisx9-scanner-report/1",
            "version": self.version,
            "run_id": self.run_id,
            "mode": self.mode,
            "dry_run": self.dry_run,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": self.finished_at.isoformat(timespec="seconds"),
            "clean": self.clean,
            "event": self.event_type,
            "summary": self.summary,
            "target_count": self.target_count,
            "refused_count": self.refused_count,
            "alert_min_severity": str(self.alert_min_severity),
            "alerts": [a.to_dict() for a in self.alerting],
            "informational": [a.to_dict() for a in self.informational],
            "notes": list(self.notes),
            "paths": dict(self.paths),
        }


def render_markdown(report: Report) -> str:
    day = report.finished_at.date().isoformat()
    status = "CLEAN" if report.clean else f"{len(report.alerting)} ALERT(S)"
    lines = [
        f"# AegisX9 external vantage: {report.mode} run {day} - {status}",
        "",
        f"- Run id: `{report.run_id}`",
        f"- Scanner version: {report.version}",
        f"- Started: {report.started_at.isoformat(timespec='seconds')}",
        f"- Finished: {report.finished_at.isoformat(timespec='seconds')}",
        f"- Targets: {report.target_count} (refused by never-target list: {report.refused_count})",
        f"- Alert threshold: {report.alert_min_severity}",
    ]
    if report.dry_run:
        lines.append("- Dry run: no network activity, no notifications")
    lines.append("")
    if report.clean:
        lines += ["## Result", "", "Nothing changed. No unapproved exposure was observed.", ""]
    else:
        lines += ["## Alerts", "", "| Severity | Kind | Target | Detail |", "|---|---|---|---|"]
        for a in sorted(report.alerting, key=lambda x: (-x.severity.rank, str(x.kind), x.target)):
            port = f":{a.port}" if a.port else ""
            lines.append(f"| {a.severity} | {a.kind} | {a.target}{port} | {_cell(a.detail)} |")
        lines.append("")
    if report.informational:
        lines += ["## Informational", ""]
        lines += [
            f"- {a.severity} {a.kind} {a.target}: {_cell(a.detail)}" for a in report.informational
        ]
        lines.append("")
    if report.notes:
        lines += ["## Notes", ""]
        lines += [f"- {n}" for n in report.notes]
        lines.append("")
    return "\n".join(lines)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _write_private(path: Path, text: str) -> None:
    """Write a 0600 file atomically: a private temporary file in the same directory,
    then ``os.replace``. The three units run as different users and share
    ``last_report.json``; replacing the directory entry needs only a writable
    directory, whereas truncating another user's 0600 file would fail."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_report(report: Report, state_dir: Path) -> tuple[Path, Path]:
    day = report.finished_at.date().isoformat()
    base = state_dir / REPORTS_DIR / day
    stem = f"{report.mode}-{report.finished_at.strftime('%H%M%S')}-{report.run_id}"
    json_path = base / f"{stem}.json"
    md_path = base / f"{stem}.md"
    report.paths = {"json": str(json_path), "markdown": str(md_path)}
    _write_private(json_path, json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    _write_private(md_path, render_markdown(report))
    if not report.dry_run:
        _write_private(
            state_dir / LAST_REPORT_FILE, json.dumps(report.to_dict(), sort_keys=True) + "\n"
        )
    return json_path, md_path


def load_snapshot(state_dir: Path) -> dict[str, Any] | None:
    path = state_dir / SNAPSHOT_FILE
    if not path.exists():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def save_snapshot(
    snapshot: dict[str, Any], state_dir: Path, *, now: datetime | None = None
) -> Path:
    path = state_dir / SNAPSHOT_FILE
    doc = dict(snapshot)
    doc["saved_at"] = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    _write_private(path, json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return path
