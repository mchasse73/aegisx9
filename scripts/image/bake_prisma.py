"""Build-time step of the gateway image: pin the Prisma query engine for this platform.

Runs in the image build stage after ``prisma generate``. LiteLLM's schema lists several
``binaryTargets``, so the generated client knows several query engines; left alone it
probes them at runtime and would execute builds for a different libc. This selects the
engine for the build platform once and links it to ``/opt/prisma/query-engine``
(``PRISMA_QUERY_ENGINE_BINARY`` in the runtime stage), then checks that the CLI is cached
and that no private Node.js was installed.

prisma-client-py names the platform after the exact OpenSSL minor (``debian-openssl-3.5.x``)
while the Prisma CLI publishes one engine per major (``debian-openssl-3.0.x``), so a missing
exact match falls back to the same distro and OpenSSL major.

prisma-client-py's platform name also ignores the CPU: on arm64 it still reports
``debian-openssl-3.5.x``, which names the x86-64 engine. The Prisma CLI publishes the arm64
glibc engine as ``linux-arm64-openssl-*`` (musl: ``linux-musl-arm64-openssl-*``), so on arm64
the target is renamed to those before the lookup.
"""

from __future__ import annotations

import os
import platform as host_platform
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

PRISMA_ROOT = Path("/opt/prisma")
_PLATFORM = re.compile(r"(?P<distro>.+)-openssl-(?P<version>(?P<major>\d+)\.\d+\.x)")
_ARM64 = frozenset({"aarch64", "arm64"})


def engine_target(target: str, machine: str) -> str | None:
    """``target`` named the way the Prisma CLI names its engine for ``machine``."""
    if machine not in _ARM64:
        return target
    match = _PLATFORM.fullmatch(target)
    if match is None:
        return None
    libc = "linux-musl-arm64" if match["distro"] == "linux-musl" else "linux-arm64"
    return f"{libc}-openssl-{match['version']}"


def select_engine(target: str, paths: Mapping[str, str], machine: str = "x86_64") -> str | None:
    """The engine for ``target`` on ``machine``, or for the same distro and OpenSSL major."""
    renamed = engine_target(target, machine)
    if renamed is None:
        return None
    target = renamed
    if target in paths:
        return paths[target]
    match = _PLATFORM.fullmatch(target)
    if match is None:
        return None
    return paths.get(f"{match['distro']}-openssl-{match['major']}.0.x")


def main() -> int:
    from prisma.binaries import platform  # type: ignore[import-not-found]
    from prisma.client import BINARY_PATHS  # type: ignore[import-not-found]

    target = platform.binary_platform()
    selected = select_engine(target, BINARY_PATHS.query_engine, host_platform.machine())
    if selected is None:
        print(f"no query engine for {target}: {sorted(BINARY_PATHS.query_engine)}", file=sys.stderr)
        return 1
    engine = Path(selected)
    if PRISMA_ROOT not in engine.parents:
        print(f"query engine outside {PRISMA_ROOT}: {engine}", file=sys.stderr)
        return 1
    # The path comes from the client generated in this build.
    subprocess.run([str(engine), "--version"], check=True, stdout=subprocess.DEVNULL)  # noqa: S603
    (PRISMA_ROOT / "query-engine").symlink_to(engine)
    cli = Path(os.environ["PRISMA_BINARY_CACHE_DIR"]) / "node_modules/prisma/build/index.js"
    if not cli.is_file():
        print(f"Prisma CLI not cached at {cli}", file=sys.stderr)
        return 1
    if Path(os.environ["PRISMA_NODEENV_CACHE_DIR"]).exists():
        print("a private Node.js was installed; node must come from PATH", file=sys.stderr)
        return 1
    print(f"prisma query engine for {target} baked: {engine.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
