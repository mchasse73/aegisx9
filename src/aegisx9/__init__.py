"""aegisx9: a secure AI gateway with governance."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aegisx9")
except PackageNotFoundError:  # pragma: no cover - only when running from a source tree
    __version__ = "0.0.0+local"

__all__ = ["__version__"]
