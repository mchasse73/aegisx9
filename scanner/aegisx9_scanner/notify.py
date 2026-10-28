"""Alert delivery: an HMAC-signed webhook to the Event-Driven Ansible event stream and an
email through SES. Both are optional and configured from the environment.

Environment:

* ``AEGISX9_SCANNER_WEBHOOK_URL``: where to POST the event (https).
* ``AEGISX9_SCANNER_WEBHOOK_SECRET_FILE``: 0600 file holding the HMAC key (preferred).
* ``AEGISX9_SCANNER_WEBHOOK_SECRET``: the key itself, when a file is not possible.
* ``AEGISX9_SCANNER_SES_FROM`` / ``AEGISX9_SCANNER_SES_TO`` (comma separated).
* ``AEGISX9_SCANNER_AWS_REGION``.

The key never appears on a command line, in a log line or in a report. Signature header:
``X-AegisX9-Signature: sha256=<hex>`` over the exact request body.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import importlib.util
import json
import os
import stat
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegisx9_scanner import __version__
from aegisx9_scanner.checks import CommandResult, find_tool, run_command
from aegisx9_scanner.log import error_name, event, log_error
from aegisx9_scanner.report import Report

SIGNATURE_HEADER = "X-AegisX9-Signature"
WEBHOOK_TIMEOUT_S = 20
SES_TIMEOUT_S = 60
ENV_PREFIX = "AEGISX9_SCANNER_"

Poster = Callable[[str, bytes, Mapping[str, str], int], int]
EmailRunner = Callable[[list[str], str, int], CommandResult]


class SecretError(RuntimeError):
    """The HMAC key could not be read safely. No detail beyond the type is reported."""


@dataclass
class NotifyConfig:
    webhook_url: str = ""
    webhook_secret_file: str = ""
    webhook_secret_env: str = ENV_PREFIX + "WEBHOOK_SECRET"
    ses_from: str = ""
    ses_to: list[str] = field(default_factory=list)
    region: str = ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> NotifyConfig:
        env = os.environ if env is None else env
        to = env.get(ENV_PREFIX + "SES_TO", "")
        return cls(
            webhook_url=env.get(ENV_PREFIX + "WEBHOOK_URL", "").strip(),
            webhook_secret_file=env.get(ENV_PREFIX + "WEBHOOK_SECRET_FILE", "").strip(),
            webhook_secret_env=ENV_PREFIX + "WEBHOOK_SECRET",
            ses_from=env.get(ENV_PREFIX + "SES_FROM", "").strip(),
            ses_to=[a.strip() for a in to.split(",") if a.strip()],
            region=env.get(ENV_PREFIX + "AWS_REGION", "").strip(),
        )

    @property
    def webhook_enabled(self) -> bool:
        return bool(self.webhook_url)

    @property
    def email_enabled(self) -> bool:
        return bool(self.ses_from and self.ses_to)


def load_webhook_secret(cfg: NotifyConfig, env: Mapping[str, str] | None = None) -> bytes:
    """The HMAC key from the 0600 file named in the environment, else from the variable."""
    env = os.environ if env is None else env
    if cfg.webhook_secret_file:
        path = Path(cfg.webhook_secret_file)
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                raise SecretError("secret file is readable by others")
            data = path.read_bytes().strip()
        except OSError as exc:
            raise SecretError(error_name(exc)) from exc
        if not data:
            raise SecretError("secret file is empty")
        return data
    value = env.get(cfg.webhook_secret_env, "")
    if not value:
        raise SecretError("no webhook secret configured")
    return value.encode("utf-8")


def sign(secret: bytes, body: bytes) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify(secret: bytes, body: bytes, header_value: str) -> bool:
    return hmac.compare_digest(sign(secret, body), header_value.strip())


def build_event(report: Report, reason: str = "") -> dict[str, Any]:
    return {
        "event": report.event_type,
        "source": "aegisx9-scanner",
        "version": __version__,
        "run_id": report.run_id,
        "mode": report.mode,
        "timestamp": report.finished_at.isoformat(timespec="seconds"),
        "summary": report.summary,
        "alert_count": len(report.alerting),
        "alerts": [a.to_dict() for a in report.alerting],
        "report_path": report.paths.get("json", ""),
        "notify_reason": reason,
    }


def http_post(url: str, body: bytes, headers: Mapping[str, str], timeout: int) -> int:
    req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - https enforced by caller
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def post_webhook(
    payload: dict[str, Any],
    cfg: NotifyConfig,
    *,
    env: Mapping[str, str] | None = None,
    poster: Poster = http_post,
) -> bool:
    if not cfg.webhook_enabled:
        return False
    if not cfg.webhook_url.startswith("https://"):
        event("webhook url must be https", level=40)
        return False
    try:
        secret = load_webhook_secret(cfg, env)
    except SecretError as exc:
        log_error("webhook secret unavailable", exc)
        return False
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "aegisx9-scanner",
        SIGNATURE_HEADER: sign(secret, body),
    }
    try:
        status = poster(cfg.webhook_url, body, headers, WEBHOOK_TIMEOUT_S)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log_error("webhook delivery failed", exc, event=payload.get("event"))
        return False
    ok = 200 <= status < 300
    event("webhook delivered" if ok else "webhook rejected", level=20 if ok else 40, status=status)
    return ok


def _boto3_client(region: str) -> Any | None:
    if importlib.util.find_spec("boto3") is None:
        return None
    boto3 = importlib.import_module("boto3")
    return boto3.client("ses", region_name=region or None)


def _cli_runner(argv: list[str], stdin: str, timeout: int) -> CommandResult:
    return run_command(argv, timeout, stdin=stdin)


def send_email(
    subject: str,
    body: str,
    cfg: NotifyConfig,
    *,
    client: Any | None = None,
    runner: EmailRunner = _cli_runner,
    aws_cli: str | None = None,
) -> bool:
    """SES through boto3 when it is importable, else the AWS CLI with the request on stdin."""
    if not cfg.email_enabled:
        return False
    message = {
        "Source": cfg.ses_from,
        "Destination": {"ToAddresses": list(cfg.ses_to)},
        "Message": {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
        },
    }
    client = client if client is not None else _boto3_client(cfg.region)
    if client is not None:
        try:
            client.send_email(**message)
        except Exception as exc:
            log_error("ses send failed", exc, transport="boto3")
            return False
        event("email sent", transport="boto3", recipients=len(cfg.ses_to))
        return True
    aws_cli = aws_cli or find_tool("aws")
    if aws_cli is None:
        event("neither boto3 nor the aws cli is available: email skipped", level=30)
        return False
    argv = [
        aws_cli,
        "ses",
        "send-email",
        "--cli-input-json",
        "file:///dev/stdin",
        "--output",
        "json",
    ]
    if cfg.region:
        argv += ["--region", cfg.region]
    res = runner(argv, json.dumps(message), SES_TIMEOUT_S)
    ok = res.returncode == 0
    event("email sent" if ok else "ses cli failed", level=20 if ok else 40, transport="cli")
    return ok


def subject_for(report: Report, reason: str = "") -> str:
    if reason == "recovered":
        label = "RECOVERED"
    elif report.clean:
        label = "CLEAN"
    elif reason == "reminder":
        label = "ALERT (still failing)"
    else:
        label = "ALERT"
    return f"[aegisx9-scanner] {label}: {report.summary}"


def notify(
    report: Report,
    markdown: str,
    cfg: NotifyConfig,
    *,
    env: Mapping[str, str] | None = None,
    reason: str = "",
) -> dict[str, bool]:
    """Deliver the run outcome. Whether a run notifies at all is decided by
    ``alert_state`` (state changes, a daily reminder, the daily summary); ``reason``
    says which and is carried in the event and the subject."""
    payload = build_event(report, reason)
    outcome = {"webhook": post_webhook(payload, cfg, env=env)}
    if cfg.email_enabled:
        outcome["email"] = send_email(subject_for(report, reason), markdown, cfg)
    else:
        outcome["email"] = False
    return outcome
