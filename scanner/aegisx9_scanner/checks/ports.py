"""Port scan: nmap TCP top ports (SYN scan when privileged, connect scan otherwise) and
UDP top ports (privileged only), run per address family. The XML report is parsed
with defusedxml.

The scanner receives *validated addresses and networks* only, never hostnames: the
target builder has already resolved every name, checked every answer against the
never-target list, and keeps the name-to-address mapping for the report.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree

from aegisx9_scanner.checks import CommandResult, CommandRunner, find_tool, run_command
from aegisx9_scanner.log import event

NMAP_TIMEOUT_S = 3 * 60 * 60
CAP_NET_RAW_BIT = 13
PROC_STATUS = Path("/proc/self/status")


@dataclass(frozen=True)
class OpenPort:
    ip: str
    port: int
    proto: str
    service: str = ""
    hostname: str = ""

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.ip, self.port, self.proto)


@dataclass
class PortScanResult:
    open_ports: list[OpenPort]
    tcp_ran: bool
    udp_ran: bool
    privileged: bool
    notes: list[str]


def has_cap_net_raw(status_text: str) -> bool:
    """True when the ``CapEff`` line of a ``/proc/<pid>/status`` text includes CAP_NET_RAW."""
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            try:
                caps = int(line.split(":", 1)[1].strip(), 16)
            except ValueError:
                return False
            return bool(caps & (1 << CAP_NET_RAW_BIT))
    return False


def is_privileged(status_path: Path = PROC_STATUS) -> bool:
    """Root, or a non-root process that holds CAP_NET_RAW in its effective set (the daily
    unit runs as a static user with ambient capabilities, so euid alone is not enough)."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        return True
    try:
        text = status_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return has_cap_net_raw(text)


def family_of(target: str) -> str:
    """``"4"`` or ``"6"`` for an address or network; anything unparsable counts as IPv4."""
    try:
        return str(ipaddress.ip_network(target, strict=False).version)
    except ValueError:
        return "4"


def split_by_family(targets: Iterable[str]) -> tuple[list[str], list[str]]:
    v4: list[str] = []
    v6: list[str] = []
    for t in targets:
        (v6 if family_of(t) == "6" else v4).append(t)
    return v4, v6


def nmap_argv(
    nmap: str,
    targets: Iterable[str],
    *,
    proto: str,
    top_ports: int,
    privileged: bool,
    family: str = "4",
    exclude: Iterable[str] = (),
) -> list[str]:
    scan_type = "-sU" if proto == "udp" else ("-sS" if privileged else "-sT")
    argv = [
        nmap,
        scan_type,
        "-Pn",
        "-n",
        "--open",
        "--top-ports",
        str(top_ports),
        "-T3",
        "--host-timeout",
        "20m",
        "-oX",
        "-",
    ]
    if family == "6":
        argv.append("-6")
    if privileged:
        # nmap decides raw-socket use from euid; with capabilities it must be told.
        argv.append("--privileged")
    excluded = [e for e in exclude if e and family_of(e) == family]
    if excluded:
        argv += ["--exclude", ",".join(excluded)]
    return [*argv, *targets]


def parse_nmap_xml(xml_text: str) -> list[OpenPort]:
    """Open ports from an nmap XML report. Anything that is not ``state="open"`` is
    ignored; ``open|filtered`` UDP answers are too noisy to alert on."""
    if not xml_text.strip():
        return []
    root = ElementTree.fromstring(xml_text)
    found: list[OpenPort] = []
    for host in root.iter("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""
        for port_el in host.iter("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port_el.find("service")
            found.append(
                OpenPort(
                    ip=ip,
                    port=int(port_el.get("portid", "0")),
                    proto=port_el.get("protocol", "tcp"),
                    service=service.get("name", "") if service is not None else "",
                    hostname=hostname,
                )
            )
    return sorted(found, key=lambda p: (p.ip, p.proto, p.port))


def scan_ports(
    targets: list[str],
    *,
    exclude: Iterable[str] = (),
    tcp_top_ports: int = 1000,
    udp_top_ports: int = 100,
    privileged: bool | None = None,
    runner: CommandRunner | None = None,
    nmap: str | None = None,
) -> PortScanResult:
    """Scan validated addresses/networks, IPv4 and IPv6 separately. ``tcp_ran`` (and
    ``udp_ran``) are true only when every family that had targets completed."""
    privileged = is_privileged() if privileged is None else privileged
    runner = runner or (lambda argv, timeout: run_command(argv, timeout))
    nmap = nmap or find_tool("nmap")
    result = PortScanResult(
        open_ports=[], tcp_ran=False, udp_ran=False, privileged=privileged, notes=[]
    )
    if not targets:
        result.notes.append("no targets to port-scan")
        return result
    if nmap is None:
        result.notes.append("nmap not installed: port scan skipped")
        event("nmap not found", level=30)
        return result

    exclude = list(exclude)
    v4, v6 = split_by_family(targets)
    families = [(fam, items) for fam, items in (("4", v4), ("6", v6)) if items]
    tcp_ok = True
    udp_ok = True
    for family, items in families:
        tcp = runner(
            nmap_argv(
                nmap,
                items,
                proto="tcp",
                top_ports=tcp_top_ports,
                privileged=privileged,
                family=family,
                exclude=exclude,
            ),
            NMAP_TIMEOUT_S,
        )
        tcp_ok = _collect(tcp, f"tcp/v{family}", result) and tcp_ok
        if not privileged:
            continue
        udp = runner(
            nmap_argv(
                nmap,
                items,
                proto="udp",
                top_ports=udp_top_ports,
                privileged=True,
                family=family,
                exclude=exclude,
            ),
            NMAP_TIMEOUT_S,
        )
        udp_ok = _collect(udp, f"udp/v{family}", result) and udp_ok
    result.tcp_ran = tcp_ok
    if not privileged:
        result.notes.append("not privileged: UDP scan skipped (needs CAP_NET_RAW)")
    else:
        result.udp_ran = udp_ok
    result.open_ports.sort(key=lambda p: (p.ip, p.proto, p.port))
    return result


def _collect(res: CommandResult, label: str, result: PortScanResult) -> bool:
    if res.returncode != 0:
        result.notes.append(f"nmap {label} scan exited {res.returncode}")
        event("nmap failed", level=40, scan=label, returncode=res.returncode)
        return False
    try:
        result.open_ports.extend(parse_nmap_xml(res.stdout))
    except ElementTree.ParseError as exc:
        result.notes.append(f"nmap {label} output unparseable ({type(exc).__name__})")
        return False
    return True
