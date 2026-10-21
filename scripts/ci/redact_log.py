"""Filter stdin to stdout, masking internal identifiers and the values of named env vars.

Usage: cmd 2>&1 | python3 scripts/ci/redact_log.py [--mask-env VAR ...] [--terraform-summary]

--terraform-summary keeps only the lines an operator needs from a remote Terraform run
(run identifier, apply summary, errors) so plan bodies stay in Terraform Enterprise.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from identifiers import load_patterns, redact

_TF_KEEP = re.compile(
    r"^(Apply complete|Plan:|No changes|Error|Running apply in|Preparing the remote|"
    r"Waiting for the plan|Terraform v|Initializing)|/runs/run-[A-Za-z0-9]+"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mask-env", action="append", default=[])
    ap.add_argument("--terraform-summary", action="store_true")
    args = ap.parse_args()
    values = [os.environ.get(name, "") for name in args.mask_env]
    patterns = load_patterns()
    for line in sys.stdin:
        if args.terraform_summary and not _TF_KEEP.search(line):
            continue
        sys.stdout.write(redact(line, patterns, values))
    return 0


if __name__ == "__main__":
    sys.exit(main())
