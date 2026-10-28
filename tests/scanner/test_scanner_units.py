"""Lint the scanner's systemd units against what each one runs (#96).

Two defects reached a real host because nothing checked the unit files:

* ``ProcSubset=pid`` hides ``/proc/net``. nmap needs it, so the daily port scan died
  with ``route_dst_netlink: can't find interface``. The CI job ``scanner-sandbox`` runs
  nmap under the daily unit's parsed sandbox; this file is the fast, local guard.
* ``StateDirectory=`` resets the state directory to ``0755`` on every start unless
  ``StateDirectoryMode=`` says otherwise, which took group write away from the
  ``DynamicUser`` units that share it through the scanner group.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from conftest import ROOT

UNITS = ROOT / "scanner" / "systemd"
SCAN_UNITS = ["aegisx9-scan-daily", "aegisx9-scan-uptime", "aegisx9-scan-redteam"]
STATE_DIR = "/var/lib/aegisx9-scanner"
LOG_DIR = "/var/log/aegisx9-scanner"

_spec = importlib.util.spec_from_file_location(
    "scanner_unit_sandbox", ROOT / "scripts" / "ci" / "scanner_unit_sandbox.py"
)
assert _spec and _spec.loader
sandbox = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sandbox)

# Units whose payload reads system-wide /proc files and so must NOT set ProcSubset=pid:
# daily runs nmap (/proc/net); redteam runs Node.js and torch (/proc/stat, cpuinfo,
# meminfo). The uptime unit is the scanner's own HTTP client and keeps it.
NEEDS_FULL_PROC = {"aegisx9-scan-daily", "aegisx9-scan-redteam"}


def _service(name: str) -> dict[str, str]:
    result: dict[str, str] = sandbox.service_settings(UNITS / f"{name}.service")
    return result


def _tmpfiles() -> dict[str, tuple[str, str, str]]:
    """path -> (mode, user, group) from the tmpfiles definition."""
    out: dict[str, tuple[str, str, str]] = {}
    for line in (UNITS / "aegisx9-scanner.tmpfiles.conf").read_text().splitlines():
        if line.startswith("d "):
            _t, path, mode, user, group, *_rest = line.split()
            out[path] = (mode, user, group)
    return out


@pytest.mark.parametrize("name", SCAN_UNITS)
def test_proc_subset_only_where_harmless(name: str) -> None:
    svc = _service(name)
    assert svc.get("ProtectProc") == "invisible", "keep hiding other users' processes"
    if name in NEEDS_FULL_PROC:
        assert "ProcSubset" not in svc, f"{name}: ProcSubset=pid hides /proc/net and /proc/stat"
    else:
        assert svc.get("ProcSubset") == "pid"


@pytest.mark.parametrize("name", SCAN_UNITS)
def test_state_and_log_directories_agree_with_tmpfiles(name: str) -> None:
    tmp = _tmpfiles()
    svc = _service(name)
    state_mode, owner, group = tmp[STATE_DIR]
    assert tmp[LOG_DIR] == (state_mode, owner, group)
    assert int(state_mode, 8) & 0o070 == 0o070, "the units share the state dir by group"
    assert svc.get("Group") == group, f"{name}: Group= must be the scanner group"
    umask = int(svc.get("UMask", "0022"), 8)
    assert umask & 0o060 == 0, f"{name}: UMask= must leave group read/write"
    if svc.get("StateDirectory") == Path(STATE_DIR).name:
        # systemd re-applies StateDirectoryMode= (default 0755) and User=/Group= on
        # every start, so they must say exactly what tmpfiles says.
        assert svc.get("StateDirectoryMode") == state_mode, f"{name}: StateDirectoryMode"
        assert svc.get("User") == owner
    if svc.get("LogsDirectory") == Path(LOG_DIR).name:
        assert svc.get("LogsDirectoryMode") == tmp[LOG_DIR][0], f"{name}: LogsDirectoryMode"
    if svc.get("DynamicUser") == "yes":
        rw = svc.get("ReadWritePaths", "").split()
        assert STATE_DIR in rw and LOG_DIR in rw and "StateDirectory" not in svc


def test_daily_unit_keeps_nmap_capabilities() -> None:
    svc = _service("aegisx9-scan-daily")
    assert set(svc["AmbientCapabilities"].split()) == {"CAP_NET_RAW", "CAP_NET_ADMIN"}
    families = set(svc["RestrictAddressFamilies"].split())
    assert {"AF_NETLINK", "AF_PACKET"} <= families


def test_sandbox_properties_leave_out_host_only_settings() -> None:
    props = sandbox.sandbox_properties(UNITS / "aegisx9-scan-daily.service")
    keys = [p.split("=", 1)[0] for p in props]
    assert "User=aegisx9-scanner" in props and "ProtectProc=invisible" in props
    assert not set(keys) & sandbox.SKIPPED
    # Repeated keys are kept in order (systemd merges SystemCallFilter= lines).
    assert keys.count("SystemCallFilter") == 2
    argv = sandbox.systemd_run_argv(
        UNITS / "aegisx9-scan-daily.service", ["nmap", "-V"], ["ProcSubset=pid"]
    )
    assert argv[:2] == ["systemd-run", "--wait"] and argv[-3:] == ["--", "nmap", "-V"]
    assert argv[-5:-3] == ["-p", "ProcSubset=pid"]


def test_sandbox_cli_print(capsys: pytest.CaptureFixture[str]) -> None:
    unit = str(UNITS / "aegisx9-scan-uptime.service")
    assert sandbox.main([unit, "--print", "--", "true"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("systemd-run ") and "-p ProcSubset=pid" in out
    assert sandbox.main([unit]) == 2
    with pytest.raises(SystemExit):
        sandbox.main([unit, "--print", "--"])
