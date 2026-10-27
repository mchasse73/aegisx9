"""``aegisx9-scan``: the external vantage command line.

Subcommands: ``daily`` (ports, TLS, exposure probes, nuclei, DNS), ``uptime`` (HTTP
reachability), ``redteam --target-url`` (promptfoo + garak), ``validate-config``.
Global options (``--config``, ``--state``, ``--dry-run``) come BEFORE the subcommand.
Exit codes: 0 clean, 1 alerts (systemd marks the unit failed), 2 configuration error.
"""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegisx9_scanner import __version__, alert_state
from aegisx9_scanner.approved import Registry, RegistryError, load_registry
from aegisx9_scanner.checks import dns as dns_check
from aegisx9_scanner.checks import http_exposure, nuclei, ports, tls, uptime
from aegisx9_scanner.diff import (
    Alert,
    Observation,
    Severity,
    classify,
    refusal_alerts,
    snapshot_from,
    uptime_alerts,
)
from aegisx9_scanner.endpoints import web_endpoints
from aegisx9_scanner.log import configure, event, log_error
from aegisx9_scanner.notify import NotifyConfig, notify
from aegisx9_scanner.redteam_external import RedteamConfig, run_redteam
from aegisx9_scanner.report import (
    Report,
    load_snapshot,
    render_markdown,
    save_snapshot,
    write_report,
)
from aegisx9_scanner.targets import (
    NeverTargetList,
    Resolver,
    TargetConfig,
    TargetConfigError,
    TargetSet,
    build_targets,
    check_url_allowed,
    load_never_target,
    load_targets,
    resolve,
)

EXIT_CLEAN = 0
EXIT_ALERTS = 1
EXIT_CONFIG = 2

DEFAULT_CONFIG_DIR = Path("/etc/aegisx9-scanner")
DEFAULT_STATE_DIR = Path("/var/lib/aegisx9-scanner")
REGISTRY_FILE = "approved_public.yml"
TARGETS_FILE = "targets.yml"
NEVER_TARGET_FILE = "never_target.yml"


class Config:
    """Loaded configuration. The never-target list is loaded first, always."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir = config_dir
        self.never: NeverTargetList = load_never_target(config_dir / NEVER_TARGET_FILE)
        self.targets_cfg: TargetConfig = load_targets(config_dir / TARGETS_FILE)
        self.registry: Registry = load_registry(config_dir / REGISTRY_FILE)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisx9-scan", description=__doc__)
    parser.add_argument("--version", action="version", version=f"aegisx9-scan {__version__}")
    parser.add_argument(
        "--config", type=Path, default=DEFAULT_CONFIG_DIR, help="configuration directory"
    )
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE_DIR, help="state directory")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="load config, build targets, no network, no alerts sent",
    )
    parser.add_argument("--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("daily", help="full external exposure check")
    sub.add_parser("uptime", help="HTTP reachability and latency")
    rt = sub.add_parser("redteam", help="promptfoo + garak against a public gateway endpoint")
    rt.add_argument(
        "--target-url", default="", help="public gateway base URL (default: from the environment)"
    )
    rt.add_argument(
        "--suite-dir",
        type=Path,
        default=None,
        help="directory holding redteam/promptfoo and redteam/garak",
    )
    sub.add_parser("validate-config", help="validate the three configuration files and exit")
    return parser


def main(argv: Sequence[str] | None = None, env: dict[str, str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure(logging.DEBUG if args.verbose else logging.INFO)
    env = dict(os.environ) if env is None else env
    args.run_id = secrets.token_hex(6)
    event(
        "aegisx9-scan starting",
        version=__version__,
        command=args.command,
        dry_run=args.dry_run,
        run_id=args.run_id,
    )
    try:
        cfg = Config(args.config)
    except (RegistryError, TargetConfigError) as exc:
        event(
            "configuration invalid", level=logging.ERROR, error=type(exc).__name__, detail=str(exc)
        )
        return EXIT_CONFIG
    except OSError as exc:
        log_error("configuration unreadable", exc)
        return EXIT_CONFIG

    today = datetime.now(UTC).date()
    if args.command == "validate-config":
        return _validate(cfg, today)
    if args.command == "daily":
        return _run(args, cfg, env, "daily", lambda obs, ts: _daily(obs, ts, args, cfg))
    if args.command == "uptime":
        return _run(args, cfg, env, "uptime", lambda obs, ts: _uptime(obs, ts))
    return _redteam(args, cfg, env)


def _validate(cfg: Config, today: Any) -> int:
    targets = build_targets(
        cfg.targets_cfg, cfg.registry, cfg.never, today=today, resolver=lambda _n: []
    )
    expired = cfg.registry.expired(today)
    event(
        "configuration valid",
        targets=len(targets.targets),
        refused=len(targets.refused),
        registry_entries=len(cfg.registry.entries),
        expired_approvals=len(expired),
        dns=len(targets.dns),
        uptime=len(targets.uptime),
    )
    for r in targets.refused:
        event(
            "never-target hit in configuration",
            level=logging.WARNING,
            name=r.name,
            source=r.source,
            rule=r.rule,
        )
    return EXIT_CONFIG if targets.refused else EXIT_CLEAN


def _work_dir(args: argparse.Namespace, mode: str) -> Path:
    """A directory used by this run only; stale files from an earlier run never count."""
    state: Path = Path(args.state)
    return state / "work" / mode / str(args.run_id)


def _run(
    args: argparse.Namespace,
    cfg: Config,
    env: dict[str, str],
    mode: str,
    collect: Any,
) -> int:
    started = datetime.now(UTC)
    today = started.date()
    targets = build_targets(
        cfg.targets_cfg, cfg.registry, cfg.never, today=today, resolver=_resolver(args)
    )
    obs = Observation(targets=targets)
    if args.dry_run:
        obs.notes.append("dry run: no checks executed")
        for t in targets.targets:
            event("would scan", target=t.name, kind=t.kind, source=t.source)
    else:
        collect(obs, targets)

    previous = load_snapshot(args.state) if mode == "daily" else None
    alerts = (
        classify(
            obs,
            cfg.registry,
            previous,
            today=today,
            cert_warn_days=targets.settings.cert_warn_days,
            expect_port_scan=not args.dry_run,
        )
        if mode == "daily"
        else [*uptime_alerts(obs.uptime), *refusal_alerts(targets.refused)]
    )
    report = Report(
        mode=mode,
        started_at=started,
        finished_at=datetime.now(UTC),
        alerts=alerts,
        notes=obs.notes,
        alert_min_severity=Severity.parse(
            env.get("AEGISX9_SCANNER_ALERT_MIN_SEVERITY", targets.settings.alert_min_severity)
        ),
        target_count=len(targets.targets) if mode == "daily" else len(targets.uptime),
        refused_count=len(targets.refused),
        run_id=args.run_id,
        dry_run=args.dry_run,
    )
    return _finish(report, obs, args, env, save=(mode == "daily" and not args.dry_run))


def _daily(obs: Observation, targets: TargetSet, args: argparse.Namespace, cfg: Config) -> None:
    s = targets.settings
    # Only validated addresses and networks reach nmap; hostnames were resolved and
    # checked by build_targets and stay in the target set for the report.
    scan = ports.scan_ports(
        targets.scan_targets,
        exclude=[str(n) for n in cfg.never.networks],
        tcp_top_ports=s.nmap_tcp_top_ports,
        udp_top_ports=s.nmap_udp_top_ports,
    )
    obs.open_ports = scan.open_ports
    obs.ports_scanned = scan.tcp_ran
    obs.udp_scanned = scan.udp_ran
    obs.notes.extend(scan.notes)

    endpoints = web_endpoints(targets, scan.open_ports)
    for ep in endpoints:
        if ep.scheme == "https":
            obs.tls.append(
                tls.check_tls(ep.host, ep.port, address=ep.address, timeout=s.http_timeout_s)
            )
        obs.exposures.extend(
            http_exposure.probe_host(
                ep.host,
                scheme=ep.scheme,
                port=ep.port,
                address=ep.address,
                timeout=s.http_timeout_s,
            )
        )
    if s.nuclei_enabled:
        obs.nuclei_expected = nuclei.installed()
        result = nuclei.run_nuclei([ep.url for ep in endpoints], _work_dir(args, "daily"))
        obs.nuclei = result.findings
        obs.nuclei_ran = result.ran
        obs.notes.extend(result.notes)
    obs.dns = dns_check.check_dns(targets.dns)


def _uptime(obs: Observation, targets: TargetSet) -> None:
    obs.uptime = uptime.check_uptime(targets.uptime, timeout=targets.settings.http_timeout_s)


def _redteam(args: argparse.Namespace, cfg: Config, env: dict[str, str]) -> int:
    started = datetime.now(UTC)
    rt = RedteamConfig.from_env(env)
    if args.target_url:
        rt.target_url = args.target_url
    if args.suite_dir is not None:
        rt.suite_dir = args.suite_dir
    notes: list[str] = []
    alerts: list[Alert] = []
    if not rt.target_url:
        notes.append("no red-team target url configured: nothing to do")
    else:
        try:
            check_url_allowed(rt.target_url, cfg.never, resolver=_resolver(args))
        except TargetConfigError as exc:
            event("red-team target refused", level=logging.ERROR, detail=str(exc))
            return EXIT_CONFIG
        if args.dry_run:
            notes.append("dry run: suites not executed")
        else:
            outcome = run_redteam(rt, _work_dir(args, "redteam"))
            alerts = outcome.alerts
            notes.extend(outcome.notes)
    report = Report(
        mode="redteam",
        started_at=started,
        finished_at=datetime.now(UTC),
        alerts=alerts,
        notes=notes,
        alert_min_severity=Severity.parse(env.get("AEGISX9_SCANNER_ALERT_MIN_SEVERITY", "medium")),
        target_count=1 if rt.target_url else 0,
        run_id=args.run_id,
        dry_run=args.dry_run,
    )
    return _finish(report, Observation(), args, env, save=False)


def _resolver(args: argparse.Namespace) -> Resolver:
    """No DNS traffic at all on a dry run; the real resolver otherwise."""
    return (lambda _name: []) if args.dry_run else resolve


def _finish(
    report: Report, obs: Observation, args: argparse.Namespace, env: dict[str, str], *, save: bool
) -> int:
    json_path, md_path = write_report(report, args.state)
    markdown = render_markdown(report)
    if save:
        save_snapshot(snapshot_from(obs), args.state, now=report.finished_at)
    if args.dry_run:
        sys.stdout.write(markdown)
    else:
        decision = alert_state.gate(report, args.state, now=report.finished_at)
        if decision.send:
            delivered = notify(
                report, markdown, NotifyConfig.from_env(env), env=env, reason=decision.reason
            )
            event("notifications", reason=decision.reason, **delivered)
            if any(delivered.values()):
                alert_state.record(report, args.state, now=report.finished_at)
    event(
        "run finished",
        mode=report.mode,
        run_id=report.run_id,
        clean=report.clean,
        alerts=len(report.alerting),
        informational=len(report.informational),
        report=str(json_path),
        summary_path=str(md_path),
    )
    return EXIT_CLEAN if report.clean else EXIT_ALERTS
