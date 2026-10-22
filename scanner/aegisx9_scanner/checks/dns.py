"""DNS expectations: every named record must answer exactly what the registry says.

A and AAAA go through the system resolver; other types use ``dig +short`` when it is
installed (dnsutils) and are reported as unsupported otherwise.
"""

from __future__ import annotations

import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field

from aegisx9_scanner.checks import CommandRunner, find_tool, run_command
from aegisx9_scanner.targets import DnsExpectation

DIG_TIMEOUT_S = 30
NAME_RE = re.compile(r"^[a-z0-9.-]+$")
RTYPE_RE = re.compile(r"^[A-Z]{1,10}$")

Lookup = Callable[[str, str], list[str]]


@dataclass
class DnsResult:
    name: str
    rtype: str
    expected: tuple[str, ...]
    observed: tuple[str, ...] = ()
    supported: bool = True
    error: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def drifted(self) -> bool:
        return self.supported and not self.error and set(self.observed) != set(self.expected)


def _normalise(rtype: str, values: list[str]) -> tuple[str, ...]:
    out = {v.strip().lower().rstrip(".").strip('"') for v in values if v.strip()}
    if rtype == "MX":
        out = {" ".join(v.split()) for v in out}
    return tuple(sorted(out))


def system_lookup(name: str, rtype: str, runner: CommandRunner | None = None) -> list[str]:
    if rtype in ("A", "AAAA"):
        family = socket.AF_INET if rtype == "A" else socket.AF_INET6
        infos = socket.getaddrinfo(name, None, family=family, proto=socket.IPPROTO_TCP)
        return sorted({str(i[4][0]) for i in infos})
    dig = find_tool("dig")
    if dig is None:
        raise LookupError("dig not installed")
    if not NAME_RE.match(name) or not RTYPE_RE.match(rtype):
        raise ValueError("unsafe dns query")
    runner = runner or (lambda argv, timeout: run_command(argv, timeout))
    res = runner([dig, "+short", "+time=5", "+tries=2", name, rtype], DIG_TIMEOUT_S)
    if res.returncode != 0:
        raise LookupError("dig failed")
    return [ln for ln in res.stdout.splitlines() if ln.strip()]


def check_dns(
    expectations: list[DnsExpectation], *, lookup: Lookup | None = None
) -> list[DnsResult]:
    lookup = lookup or system_lookup
    results: list[DnsResult] = []
    for exp in expectations:
        result = DnsResult(
            name=exp.name, rtype=exp.rtype, expected=_normalise(exp.rtype, list(exp.expect))
        )
        try:
            result.observed = _normalise(exp.rtype, lookup(exp.name, exp.rtype))
        except socket.gaierror:
            result.observed = ()  # NXDOMAIN / no answer: compared against expectations as empty
        except LookupError as exc:
            result.supported = False
            result.notes.append(f"lookup unsupported ({type(exc).__name__})")
        except (OSError, ValueError) as exc:
            result.error = type(exc).__name__
        results.append(result)
    return results
