"""``python -m aegisx9_scanner`` entry point."""

from __future__ import annotations

import sys

from aegisx9_scanner.cli import main

if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
