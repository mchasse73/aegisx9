"""Wait until a namespace's AegisX9 Deployment runs a given image digest and is available.

Runs on the in-cluster ARC runner, whose service account has read-only access to
Deployments in the AegisX9 namespaces. Exits non-zero on timeout.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--namespace", required=True)
    ap.add_argument("--digest-file", required=True)
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    # The namespace passed to kubectl is one of two literals, chosen by comparison, so no
    # user-controlled string reaches the argv (and SAST taint tracking agrees).
    if args.namespace == "aegisx9-staging":
        namespace = "aegisx9-staging"
    elif args.namespace == "aegisx9-prod":
        namespace = "aegisx9-prod"
    else:
        print("namespace must be aegisx9-staging or aegisx9-prod", file=sys.stderr)
        return 2

    with open(args.digest_file, encoding="utf-8") as fh:
        digest = fh.read().strip()
    if not DIGEST_RE.match(digest):
        print("digest file does not contain a sha256 digest", file=sys.stderr)
        return 2

    kubectl = shutil.which("kubectl")
    if kubectl is None:
        print("kubectl not found on PATH", file=sys.stderr)
        return 2

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        # Fixed argv, no shell; namespace is a literal selected above.
        out = subprocess.run(  # noqa: S603
            [
                kubectl,
                "-n",
                namespace,
                "get",
                "deploy",
                "-l",
                "app.kubernetes.io/part-of=aegisx9",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode == 0:
            items = json.loads(out.stdout).get("items", [])
            if items and all(rollout_complete(d, digest) for d in items):
                print(f"{namespace} is running {digest[:19]}")
                return 0
        time.sleep(15)
    print(f"timed out waiting for {args.namespace} to run {digest[:19]}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
