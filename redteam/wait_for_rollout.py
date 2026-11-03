"""Wait until a namespace's AegisX9 Deployments run a given image digest and are available.

The digest comes from a file (one ``sha256:...`` line) or from the ``digest:`` pin in a
kustomize overlay, which is what Argo CD deploys. The red-team gate therefore tests the
image the overlay on ``main`` says staging runs, not whatever ``main`` last built.

Runs on the in-cluster ARC runner. It talks to the Kubernetes API directly with the
pod's mounted service-account token (no kubectl on the runner image), and only reads
Deployments. Errors are reported by type, never with a response body or the token.
Exits 0 once rolled out, 1 on timeout, 2 on bad input or a refused request.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
OVERLAY_DIGEST_RE = re.compile(r"^\s*digest:\s*(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
NAMESPACES = ("aegisx9-staging", "aegisx9-prod")
SELECTOR = "app.kubernetes.io/part-of=aegisx9"

Fetch = Callable[[str], dict[str, Any]]


class RolloutError(Exception):
    """A refused or malformed API answer; the message never holds the token."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


# A missing grant or a bad token won't fix itself: stop at once. Anything else (5xx, 429,
# a reset connection, a timeout while pods roll) is retried until the deadline.
FATAL_STATUSES = frozenset({401, 403, 404})


def rollout_complete(deploy: dict, digest: str) -> bool:  # type: ignore[type-arg]
    spec = deploy.get("spec", {})
    status = deploy.get("status", {})
    images = [c.get("image", "") for c in spec["template"]["spec"]["containers"]]
    want = spec.get("replicas", 1)
    return (
        all(img.endswith("@" + digest) for img in images)
        and status.get("observedGeneration", 0) >= deploy["metadata"].get("generation", 0)
        and status.get("updatedReplicas", 0) == want
        and status.get("availableReplicas", 0) == want
    )


def digest_from_file(path: Path) -> str:
    digest = path.read_text(encoding="utf-8").strip()
    if not DIGEST_RE.match(digest):
        raise RolloutError("digest file does not contain a sha256 digest")
    return digest


def digest_from_overlay(path: Path) -> str:
    """The single ``digest:`` pin of a kustomization file."""
    found = OVERLAY_DIGEST_RE.findall(path.read_text(encoding="utf-8"))
    if len(found) != 1:
        raise RolloutError(f"expected exactly one digest pin in the overlay, found {len(found)}")
    return str(found[0])


def in_cluster_fetch(sa_dir: Path = SA_DIR, env: dict[str, str] | None = None) -> Fetch:
    """GETs against the API server with the pod's service-account token."""
    env = dict(os.environ) if env is None else env
    host, port = env.get("KUBERNETES_SERVICE_HOST"), env.get("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        raise RolloutError("not running in a cluster (KUBERNETES_SERVICE_HOST unset)")
    token = (sa_dir / "token").read_text(encoding="ascii").strip()
    ctx = ssl.create_default_context(cafile=str(sa_dir / "ca.crt"))
    base = f"https://{host}:{port}"

    def fetch(path: str) -> dict[str, Any]:
        req = urllib.request.Request(  # noqa: S310 - https to the in-cluster API only
            base + path, headers={"Authorization": "Bearer " + token, "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:  # noqa: S310
                data = json.load(resp)
        except urllib.error.HTTPError as e:
            raise RolloutError(f"API answered {e.code}", e.code) from None
        if not isinstance(data, dict):
            raise RolloutError("API answer is not an object")
        return data

    return fetch


def deployments_path(namespace: str) -> str:
    if namespace not in NAMESPACES:
        raise RolloutError("namespace must be aegisx9-staging or aegisx9-prod")
    query = urllib.parse.urlencode({"labelSelector": SELECTOR})
    return f"/apis/apps/v1/namespaces/{namespace}/deployments?{query}"


def wait(
    fetch: Fetch,
    namespace: str,
    digest: str,
    timeout_s: float,
    interval_s: float = 15,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """True once every AegisX9 Deployment runs ``digest`` and is available."""
    path = deployments_path(namespace)
    deadline = clock() + timeout_s
    while True:
        try:
            items = fetch(path).get("items", [])
        except RolloutError as e:
            if e.status in FATAL_STATUSES:
                raise
            items = []
        except (OSError, ValueError):
            items = []
        if items and all(rollout_complete(d, digest) for d in items):
            return True
        if clock() >= deadline:
            return False
        sleep(interval_s)


def main(argv: list[str] | None = None, fetch: Fetch | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", required=True)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--digest-file", type=Path)
    src.add_argument("--overlay", type=Path, help="kustomization.yaml holding the digest pin")
    ap.add_argument("--timeout", type=float, default=900)
    args = ap.parse_args(argv)
    try:
        digest = (
            digest_from_overlay(args.overlay)
            if args.overlay
            else digest_from_file(args.digest_file)
        )
        done = wait(fetch or in_cluster_fetch(), args.namespace, digest, args.timeout)
    except (RolloutError, OSError, ValueError) as e:
        detail = str(e) if isinstance(e, RolloutError) else type(e).__name__
        print(f"wait_for_rollout: {detail}", file=sys.stderr)
        return 2
    if done:
        print(f"{args.namespace} is running {digest[:19]}")
        return 0
    print(f"timed out waiting for {args.namespace} to run {digest[:19]}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
