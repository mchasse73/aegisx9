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
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

PRISMA_ROOT = Path("/opt/prisma")
_PLATFORM = re.compile(r"(?P<distro>.+)-openssl-(?P<major>\d+)\.\d+\.x")


def select_engine(target: str, paths: Mapping[str, str]) -> str | None:
    """The engine built for ``target``, or for the same distro and OpenSSL major."""
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
    selected = select_engine(target, BINARY_PATHS.query_engine)
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
