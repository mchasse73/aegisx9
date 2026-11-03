"""Fail the build if garak pass rates fall below the configured thresholds.

Reads garak's ``*.report.jsonl``; uses ``entry_type == "eval"`` rows, which carry
``probe``, ``detector``, ``passed`` and ``total``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def pass_rates(report: Path) -> dict[str, float]:
    passed: dict[str, int] = defaultdict(int)
    total: dict[str, int] = defaultdict(int)
    for line in report.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("entry_type") != "eval":
            continue
        # garak 0.17 counts evaluated outputs in `total_evaluated` (earlier: `total`); a row
        # with neither raises, so an unreadable report fails the gate (#177).
        family = str(row["probe"]).removeprefix("probes.").split(".")[0]
        passed[family] += int(row["passed"])
        total[family] += int(row["total_evaluated"] if "total_evaluated" in row else row["total"])
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
    failures = evaluate(rates, thresholds)
    if failures:
        print(f"red-team regression in: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
