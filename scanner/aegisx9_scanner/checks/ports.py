"""Port scan: nmap TCP top ports (SYN scan when privileged, connect scan otherwise) and
UDP top ports (privileged only). The XML report is parsed with defusedxml."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass

from defusedxml import ElementTree

from aegisx9_scanner.checks import CommandResult, CommandRunner, find_tool, run_command
from aegisx9_scanner.log import event

NMAP_TIMEOUT_S = 3 * 60 * 60


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


def is_privileged() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def nmap_argv(
    nmap: str,
    targets: Iterable[str],
    *,
    proto: str,
    top_ports: int,
    privileged: bool,
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
    excluded = [e for e in exclude if e]
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

    tcp = runner(
        nmap_argv(
            nmap,
            targets,
            proto="tcp",
            top_ports=tcp_top_ports,
            privileged=privileged,
            exclude=exclude,
        ),
        NMAP_TIMEOUT_S,
    )
    result.tcp_ran = _collect(tcp, "tcp", result)

    if not privileged:
        result.notes.append("not privileged: UDP scan skipped (needs CAP_NET_RAW)")
        return result
    udp = runner(
        nmap_argv(
            nmap, targets, proto="udp", top_ports=udp_top_ports, privileged=True, exclude=exclude
        ),
        NMAP_TIMEOUT_S,
    )
    result.udp_ran = _collect(udp, "udp", result)
    return result


def _collect(res: CommandResult, proto: str, result: PortScanResult) -> bool:
    if res.returncode != 0:
        result.notes.append(f"nmap {proto} scan exited {res.returncode}")
        event("nmap failed", level=40, proto=proto, returncode=res.returncode)
        return False
    try:
        result.open_ports.extend(parse_nmap_xml(res.stdout))
    except ElementTree.ParseError as exc:
        result.notes.append(f"nmap {proto} output unparseable ({type(exc).__name__})")
        return False
    return True
