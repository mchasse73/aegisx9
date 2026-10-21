"""nuclei wrapper: exposure, config, backup and misconfiguration templates only, JSONL
output parsed into findings. nuclei is optional; when it is missing the run says so."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from aegisx9_scanner.checks import CommandRunner, find_tool, run_command

NUCLEI_TAGS = "exposure,config,backup,misconfig,exposures"
NUCLEI_SEVERITIES = "low,medium,high,critical"
NUCLEI_TIMEOUT_S = 2 * 60 * 60


@dataclass(frozen=True)
class NucleiFinding:
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str


@dataclass
class NucleiResult:
    findings: list[NucleiFinding]
    ran: bool
    notes: list[str]


def nuclei_argv(nuclei: str, targets_file: Path, output: Path) -> list[str]:
    return [
        nuclei,
        "-list",
        str(targets_file),
        "-tags",
        NUCLEI_TAGS,
        "-severity",
        NUCLEI_SEVERITIES,
        "-jsonl",
        "-output",
        str(output),
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-rate-limit",
        "50",
        "-timeout",
        "10",
    ]


def parse_jsonl(text: str) -> list[NucleiFinding]:
    findings: list[NucleiFinding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        info = row.get("info") or {}
        findings.append(
            NucleiFinding(
                template_id=str(row.get("template-id") or row.get("templateID") or ""),
                name=str(info.get("name") or ""),
                severity=str(info.get("severity") or "unknown").lower(),
                host=str(row.get("host") or ""),
                matched_at=str(row.get("matched-at") or row.get("matched") or ""),
            )
        )
    return findings


def run_nuclei(
    hosts: list[str],
    work_dir: Path,
    *,
    runner: CommandRunner | None = None,
    nuclei: str | None = None,
) -> NucleiResult:
    runner = runner or (lambda argv, timeout: run_command(argv, timeout))
    nuclei = nuclei or find_tool("nuclei")
    result = NucleiResult(findings=[], ran=False, notes=[])
    if not hosts:
        result.notes.append("no hosts for nuclei")
        return result
    if nuclei is None:
        result.notes.append("nuclei not installed: template scan skipped")
        return result
    work_dir.mkdir(parents=True, exist_ok=True)
    targets_file = work_dir / "nuclei-targets.txt"
    output = work_dir / "nuclei.jsonl"
    targets_file.write_text("".join(f"https://{h}\n" for h in hosts), encoding="utf-8")
    if output.exists():
        output.unlink()
    res = runner(nuclei_argv(nuclei, targets_file, output), NUCLEI_TIMEOUT_S)
    if res.returncode != 0:
        result.notes.append(f"nuclei exited {res.returncode}")
    if output.exists():
        result.findings = parse_jsonl(output.read_text(encoding="utf-8"))
        result.ran = True
    elif res.returncode == 0:
        result.ran = True  # no output file means no matches
    return result
