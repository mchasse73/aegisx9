"""Fail the build if garak pass rates fall below the configured thresholds.

Reads garak's ``*.report.jsonl``. ``entry_type == "eval"`` rows carry ``probe``, ``passed``
and ``total_evaluated``. ``entry_type == "attempt"`` rows (one per attempt and status) give
the number of attempts each family sent. garak scores only attempts that got an output, so
a family where too few attempts were scored fails: errors must not shrink the denominator
(#188; guard blocks reach garak as ``[BLOCKED]`` completions through block_adapter.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

MIN_SCORED_RATIO = 0.9


def _family(probe: object) -> str:
    return str(probe).removeprefix("probes.").split(".")[0]


def _has_output(row: dict[str, object]) -> bool:
    outputs = row.get("outputs")
    if not isinstance(outputs, list):
        return False
    # An empty string is an output (detectors score it); only a missing one is not.
    return any((o.get("text") if isinstance(o, dict) else o) is not None for o in outputs)


def scored_ratios(report: Path) -> dict[str, float]:
    """Per family: the share of attempts that got any output (and so could be scored).

    Read from the attempt rows themselves, so it doesn't depend on generations per attempt or
    on how many detectors scored each probe.
    """
    attempts: dict[str, set[str]] = defaultdict(set)
    answered: dict[str, set[str]] = defaultdict(set)
    for line in report.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("entry_type") != "attempt":
            continue
        family, uuid = _family(row.get("probe_classname")), str(row.get("uuid"))
        attempts[family].add(uuid)
        if _has_output(row):
            answered[family].add(uuid)
    return {f: len(answered[f]) / len(a) for f, a in attempts.items()}


def _total(row: dict[str, object]) -> int:
    # garak 0.17 counts evaluated outputs in `total_evaluated` (earlier: `total`); a row
    # with neither raises, so an unreadable report fails the gate (#177).
    return int(row["total_evaluated"] if "total_evaluated" in row else row["total"])  # type: ignore[call-overload]


def pass_rates(report: Path) -> dict[str, float]:
    passed: dict[str, int] = defaultdict(int)
    total: dict[str, int] = defaultdict(int)
    for line in report.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("entry_type") != "eval":
            continue
        family = _family(row["probe"])
        passed[family] += int(row["passed"])
        total[family] += _total(row)
    # A family with no attempts scored nothing: treat it as 0, never as a free pass.
    return {f: (passed[f] / total[f] if total[f] else 0.0) for f in total}


def evaluate(rates: dict[str, float], thresholds: dict[str, object]) -> list[str]:
    default = float(thresholds.get("default", 1.0))  # type: ignore[arg-type]
    per_probe = thresholds.get("probes", {})
    assert isinstance(per_probe, dict)  # noqa: S101
    failures = []
    for family, rate in sorted(rates.items()):
        floor = float(per_probe.get(family, default))
        status = "ok" if rate >= floor else "FAIL"
        print(f"{family:20s} pass_rate={rate:.3f} threshold={floor:.2f} {status}")
        if rate < floor:
            failures.append(family)
    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--thresholds", type=Path, required=True)
    ap.add_argument("--min-scored", type=float, default=MIN_SCORED_RATIO)
    args = ap.parse_args()
    rates = pass_rates(args.report)
    if not rates:
        print("no eval rows in report; treating as failure", file=sys.stderr)
        return 1
    thresholds = json.loads(args.thresholds.read_text(encoding="utf-8"))
    # Every configured family must have run: a renamed or skipped probe would otherwise pass
    # silently (garak's xss module became web_injection; #147).
    missing = sorted(set(thresholds.get("probes", {})) - set(rates))
    if missing:
        print(f"probe families missing from the report: {', '.join(missing)}", file=sys.stderr)
        return 1
    coverage = scored_ratios(args.report)
    unscored = sorted(f for f in rates if coverage.get(f, 0.0) < args.min_scored)
    for family in unscored:
        print(
            f"{family:20s} scored {coverage.get(family, 0.0):.0%} of its attempts; "
            "the rest got no output (gateway errors)",
            file=sys.stderr,
        )
    failures = evaluate(rates, thresholds)
    failures = sorted(set(failures) | set(unscored))
    if failures:
        print(f"red-team regression in: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
