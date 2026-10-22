from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pytest

from aegisx9_scanner import notify
from aegisx9_scanner.checks import CommandResult
from aegisx9_scanner.diff import Alert, Kind, Severity
from aegisx9_scanner.report import Report


def _report(alerts: list[Alert]) -> Report:
    t0 = datetime(2026, 10, 21, 8, tzinfo=UTC)
    r = Report(mode="daily", started_at=t0, finished_at=t0, alerts=alerts)
    r.paths = {"json": "/var/lib/aegisx9-scanner/reports/x.json"}
    return r


def test_config_from_env() -> None:
    cfg = notify.NotifyConfig.from_env(
        {
            "AEGISX9_SCANNER_WEBHOOK_URL": "https://eda.example.com/hook ",
            "AEGISX9_SCANNER_SES_FROM": "scanner@example.com",
            "AEGISX9_SCANNER_SES_TO": "a@example.com, b@example.com,",
            "AEGISX9_SCANNER_AWS_REGION": "us-east-1",
        }
    )
    assert (
        cfg.webhook_enabled
        and cfg.email_enabled
        and cfg.ses_to == ["a@example.com", "b@example.com"]
    )
    assert not notify.NotifyConfig.from_env({}).webhook_enabled


def test_secret_loading_prefers_file_and_checks_mode(tmp_path: Path) -> None:
    value = secrets.token_urlsafe(24)
    f = tmp_path / "hook"
    f.write_text(value + "\n")
    f.chmod(0o600)
    cfg = notify.NotifyConfig(webhook_secret_file=str(f))
    assert notify.load_webhook_secret(cfg, {}) == value.encode()
    f.chmod(0o644)
    with pytest.raises(notify.SecretError):
        notify.load_webhook_secret(cfg, {})
    f.chmod(0o600)
    f.write_text("")
    with pytest.raises(notify.SecretError):
        notify.load_webhook_secret(cfg, {})
    cfg = notify.NotifyConfig(webhook_secret_file=str(tmp_path / "missing"))
    with pytest.raises(notify.SecretError):
        notify.load_webhook_secret(cfg, {})
    cfg = notify.NotifyConfig()
    assert (
        notify.load_webhook_secret(cfg, {"AEGISX9_SCANNER_WEBHOOK_SECRET": value}) == value.encode()
    )
    with pytest.raises(notify.SecretError):
        notify.load_webhook_secret(cfg, {})


def test_signature_matches_independent_hmac() -> None:
    key = secrets.token_bytes(32)
    body = b'{"event":"clean"}'
    sig = notify.sign(key, body)
    assert sig == "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()
    assert notify.verify(key, body, sig) and not notify.verify(key, body + b" ", sig)


def test_post_webhook_signs_body(tmp_path: Path) -> None:
    key = secrets.token_urlsafe(32)
    f = tmp_path / "hook"
    f.write_text(key)
    f.chmod(0o600)
    cfg = notify.NotifyConfig(
        webhook_url="https://eda.example.com/hook", webhook_secret_file=str(f)
    )
    seen: dict[str, object] = {}

    def poster(url: str, body: bytes, headers: dict[str, str], timeout: int) -> int:
        seen.update(url=url, body=body, headers=dict(headers))
        return 202

    report = _report(
        [Alert(Kind.NEW_OPEN_PORT, Severity.HIGH, "www.example.com", "tcp/22", 22, "tcp")]
    )
    payload = notify.build_event(report)
    assert payload["event"] == "exposure_change" and payload["alert_count"] == 1
    assert (
        payload["alerts"][0]["kind"] == "NEW_OPEN_PORT" and payload["source"] == "aegisx9-scanner"
    )
    assert notify.post_webhook(payload, cfg, env={}, poster=poster)
    body = seen["body"]
    assert isinstance(body, bytes) and json.loads(body)["run_id"] == report.run_id
    headers = seen["headers"]
    assert isinstance(headers, dict)
    assert notify.verify(key.encode(), body, headers["X-AegisX9-Signature"])
    assert headers["Content-Type"] == "application/json"
    assert key not in json.dumps(headers) and key not in body.decode()

    assert not notify.post_webhook(payload, cfg, env={}, poster=lambda *a: 500)

    def boom(*a: object) -> int:
        raise urllib.error.URLError("x")

    assert not notify.post_webhook(payload, cfg, env={}, poster=boom)
    assert not notify.post_webhook(payload, notify.NotifyConfig(), env={}, poster=poster)
    assert not notify.post_webhook(
        payload, notify.NotifyConfig(webhook_url="http://x"), env={}, poster=poster
    )
    nosecret = notify.NotifyConfig(webhook_url="https://eda.example.com/hook")
    assert not notify.post_webhook(payload, nosecret, env={}, poster=poster)


def test_http_post(monkeypatch: pytest.MonkeyPatch) -> None:
    class Resp:
        status = 204

        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            pass

    monkeypatch.setattr(notify.urllib.request, "urlopen", lambda req, timeout: Resp())
    assert notify.http_post("https://x.example.com/", b"{}", {}, 1) == 204

    def http_err(req: object, timeout: int) -> None:
        raise urllib.error.HTTPError("https://x", 401, "no", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(notify.urllib.request, "urlopen", http_err)
    assert notify.http_post("https://x.example.com/", b"{}", {}, 1) == 401


def test_send_email_boto3_and_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = notify.NotifyConfig(
        ses_from="scanner@example.com", ses_to=["ops@example.com"], region="us-east-1"
    )

    class Client:
        calls: ClassVar[list[dict[str, object]]] = []

        def send_email(self, **kw: object) -> None:
            self.calls.append(kw)

    assert notify.send_email("s", "b", cfg, client=Client())
    assert Client.calls[0]["Source"] == "scanner@example.com"

    class Broken:
        def send_email(self, **kw: object) -> None:
            raise RuntimeError("x")

    assert not notify.send_email("s", "b", cfg, client=Broken())

    monkeypatch.setattr(notify, "_boto3_client", lambda region: None)
    seen: dict[str, object] = {}

    def runner(argv: list[str], stdin: str, timeout: int) -> CommandResult:
        seen.update(argv=argv, stdin=stdin)
        return CommandResult(0, "{}")

    assert notify.send_email("subj", "body", cfg, runner=runner, aws_cli="/usr/bin/aws")
    argv = seen["argv"]
    assert isinstance(argv, list) and "file:///dev/stdin" in argv and "--region" in argv
    assert "subj" not in " ".join(argv)  # the message travels on stdin, not argv
    assert json.loads(str(seen["stdin"]))["Message"]["Subject"]["Data"] == "subj"
    assert not notify.send_email(
        "s", "b", cfg, runner=lambda a, s, t: CommandResult(1, ""), aws_cli="/usr/bin/aws"
    )
    monkeypatch.setattr(notify, "find_tool", lambda n: None)
    assert not notify.send_email("s", "b", cfg)
    assert not notify.send_email("s", "b", notify.NotifyConfig())


def test_boto3_client_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notify.importlib.util, "find_spec", lambda name: None)
    assert notify._boto3_client("us-east-1") is None


def test_cli_runner_uses_stdin() -> None:
    res = notify._cli_runner(["/bin/sh", "-c", "cat"], "payload", 5)
    assert res.stdout == "payload"


def test_notify_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notify, "post_webhook", lambda payload, cfg, env=None: True)
    monkeypatch.setattr(
        notify,
        "send_email",
        lambda subject, body, cfg: subject.startswith("[aegisx9-scanner] CLEAN"),
    )
    cfg = notify.NotifyConfig(
        webhook_url="https://x", ses_from="a@example.com", ses_to=["b@example.com"]
    )
    assert notify.notify(_report([]), "md", cfg, env={}) == {"webhook": True, "email": True}
    assert notify.notify(_report([]), "md", notify.NotifyConfig(), env={}) == {
        "webhook": True,
        "email": False,
    }
