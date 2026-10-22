"""AegisX9 external vantage scanner.

Looks at the organisation's public surface from the real internet every day, compares
what it sees with the approved-exposure registry and the previous run, and raises an
alert on any change. See ``scanner/README.md``.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aegisx9")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0"

__all__ = ["__version__"]
