"""Filesystem helpers shared by every module that writes under the state directory."""

from __future__ import annotations

import os
from pathlib import Path

# Subdirectories of the shared state directory are group-writable, like the directory
# itself (scanner/systemd/aegisx9-scanner.tmpfiles.conf).
GROUP_DIR_MODE = 0o770


def ensure_group_dir(path: Path) -> None:
    """Create ``path`` and any missing parents as ``0770``, whatever the process umask.

    The daily unit (static user) and the uptime and red-team units (``DynamicUser``)
    share the state directory through the scanner group. A subdirectory one of them
    creates (``reports/<date>``, ``notify``) must stay writable by the others, so the
    mode is set explicitly instead of trusting each unit's ``UMask=``. Existing
    directories are left alone: their mode belongs to whoever created them."""
    missing: list[Path] = []
    p = path
    while not p.exists():
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        try:
            d.mkdir(mode=GROUP_DIR_MODE)
        except FileExistsError:
            continue  # another unit created it first
        # Group rwx is the point (units share the directory); nothing for others.
        os.chmod(d, GROUP_DIR_MODE)  # nosemgrep
