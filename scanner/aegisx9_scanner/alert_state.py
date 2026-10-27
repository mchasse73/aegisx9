"""When to notify: on a change of state, not on every run.

The uptime probe runs every five minutes. Sending its outcome every time turned one
unchanged condition into hundreds of emails a day, which trains people to ignore the
channel. So each job (``uptime``, ``daily``, ``redteam``) keeps the state it last
NOTIFIED in ``<state>/notify/<job>.json`` and a run notifies only when:

* the set of alerting findings differs from the one last notified (``alert`` /
  ``changed``);
* the same failing set is still there and the last notice is at least
  ``REALERT_AFTER`` old (``reminder``);
* the job is clean again after a notified failure (``recovered``).

The daily scan is the exception: it sends one summary per run, CLEAN or ALERT, because
it is the heartbeat (silence from it means the scanner is broken). Its state is still
recorded so the summary can say when a failure recovered.

The state is written only after at least one channel accepted the notice, so a failed
delivery is retried on the next run instead of being remembered as sent. The file holds
alert kinds, targets and timestamps, never a secret; it is group-readable (``0660``)
because the uptime and red-team units run as throwaway ``DynamicUser`` ids that differ
between runs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from aegisx9_scanner.log import event, log_error
from aegisx9_scanner.report import Report, write_atomic

NOTIFY_DIR = "notify"
STATE_FILE_MODE = 0o660
# A still-failing, unchanged state is re-sent at most this often.
REALERT_AFTER = timedelta(hours=24)
# Jobs that send every run as a summary (see the module docstring).
SUMMARY_JOBS = frozenset({"daily"})
SCHEMA = "aegisx9-scanner-notify-state/1"


@dataclass(frozen=True)
class NotifyState:
    """What was last notified for one job."""

    clean: bool
    fingerprint: str
    sent_at: datetime

    def to_dict(self, mode: str) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "mode": mode,
            "clean": self.clean,
            "fingerprint": self.fingerprint,
            "sent_at": self.sent_at.isoformat(timespec="seconds"),
        }


@dataclass(frozen=True)
class Decision:
    send: bool
    reason: str  # summary | alert | changed | reminder | recovered | quiet | unchanged


def fingerprint(report: Report) -> str:
    """A stable identity for the set of alerting findings. Details such as a latency
    figure or a day count change every run and are left out on purpose."""
    keys = sorted({f"{a.kind}|{a.target}|{a.port or ''}|{a.proto}" for a in report.alerting})
    return hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest() if keys else ""


def state_path(state_dir: Path, mode: str) -> Path:
    return state_dir / NOTIFY_DIR / f"{mode}.json"


def load_state(state_dir: Path, mode: str) -> NotifyState | None:
    """The last notified state, or None when there is none or it cannot be read (an
    unreadable state errs on the side of notifying)."""
    path = state_path(state_dir, mode)
    if not path.exists():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        return NotifyState(
            clean=bool(doc["clean"]),
            fingerprint=str(doc["fingerprint"]),
            sent_at=datetime.fromisoformat(str(doc["sent_at"])),
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        log_error("notify state unreadable; treating as first run", exc, mode=mode)
        return None


def save_state(state_dir: Path, mode: str, state: NotifyState) -> None:
    try:
        write_atomic(
            state_path(state_dir, mode),
            json.dumps(state.to_dict(mode), sort_keys=True) + "\n",
            mode=STATE_FILE_MODE,
        )
    except OSError as exc:
        # Not fatal: the next run may repeat a notice, which is better than losing one.
        log_error("notify state not saved", exc, mode=mode)


def decide(report: Report, previous: NotifyState | None, *, now: datetime) -> Decision:
    current = fingerprint(report)
    recovered = previous is not None and not previous.clean and report.clean
    if report.mode in SUMMARY_JOBS:
        return Decision(True, "recovered" if recovered else "summary")
    if report.clean:
        return Decision(True, "recovered") if recovered else Decision(False, "quiet")
    if previous is None or previous.clean:
        return Decision(True, "alert")
    if previous.fingerprint != current:
        return Decision(True, "changed")
    if now - previous.sent_at >= REALERT_AFTER:
        return Decision(True, "reminder")
    return Decision(False, "unchanged")


def record(report: Report, state_dir: Path, *, now: datetime) -> None:
    save_state(
        state_dir,
        report.mode,
        NotifyState(clean=report.clean, fingerprint=fingerprint(report), sent_at=now),
    )


def gate(report: Report, state_dir: Path, *, now: datetime) -> Decision:
    decision = decide(report, load_state(state_dir, report.mode), now=now)
    if not decision.send:
        event("notification suppressed", mode=report.mode, reason=decision.reason)
    return decision
