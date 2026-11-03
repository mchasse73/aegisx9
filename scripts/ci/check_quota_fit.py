"""Fail when a rendered overlay can't roll out inside its namespace quota.

A rolling update runs ``replicas + maxSurge`` pods of each Deployment at once, and the
budget Job and CronJobs may run at the same time. Kubernetes refuses any pod that would
push the namespace past its ResourceQuota, so an oversized change merges cleanly and then
never starts (#162). This sums the worst case from the rendered manifests: every
Deployment at full surge plus the ``--concurrent-jobs`` largest Job or CronJob pods
(counting a Job's parallel pods, and taking the largest separately for CPU and memory).

Usage: check_quota_fit.py RENDERED.yaml --limits-cpu 3 --limits-memory 3Gi --pods 5
Exits 0 when it fits, 1 when it doesn't, 2 on bad input.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

_MEM = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "k": 10**3, "M": 10**6, "G": 10**9}


def cpu_millis(value: object) -> int:
    s = str(value).strip()
    if s.endswith("m"):
        return int(s[:-1])
    return round(float(s) * 1000)


def mem_bytes(value: object) -> int:
    s = str(value).strip()
    for suffix in sorted(_MEM, key=len, reverse=True):
        if s.endswith(suffix):
            return int(float(s[: -len(suffix)]) * _MEM[suffix])
    return int(s)


def _surge(spec: dict[str, Any], replicas: int) -> int:
    rolling = (spec.get("strategy") or {}).get("rollingUpdate") or {}
    surge = rolling.get("maxSurge", "25%")
    if isinstance(surge, str) and surge.endswith("%"):
        return -(-replicas * int(surge[:-1]) // 100)  # Kubernetes rounds surge up
    return int(surge)


def pod_limits(pod: dict[str, Any]) -> tuple[int, int]:
    """CPU millis and memory bytes the quota charges for one pod.

    Init containers run before the others, so a pod is charged the larger of its biggest
    init container and the sum of its regular containers.
    """

    def lim(c: dict[str, Any]) -> tuple[int, int]:
        limits = (c.get("resources") or {}).get("limits") or {}
        if "cpu" not in limits or "memory" not in limits:
            raise ValueError(f"container {c.get('name')} has no cpu/memory limit")
        return cpu_millis(limits["cpu"]), mem_bytes(limits["memory"])

    main = [lim(c) for c in pod.get("containers", [])]
    init = [lim(c) for c in pod.get("initContainers", [])]
    cpu = max([sum(c for c, _ in main), *(c for c, _ in init)])
    mem = max([sum(m for _, m in main), *(m for _, m in init)])
    return cpu, mem


def worst_case(docs: list[dict[str, Any]], concurrent_jobs: int) -> tuple[int, int, int]:
    """(cpu millis, memory bytes, pods) at the peak of a rollout."""
    cpu = mem = pods = 0
    jobs: list[tuple[int, int]] = []
    for d in docs:
        kind = d.get("kind")
        if kind == "Deployment":
            spec = d["spec"]
            replicas = int(spec.get("replicas", 1))
            n = replicas + _surge(spec, replicas)
            c, m = pod_limits(spec["template"]["spec"])
            cpu, mem, pods = cpu + n * c, mem + n * m, pods + n
        elif kind in ("Job", "CronJob"):
            spec = d["spec"]["jobTemplate"]["spec"] if kind == "CronJob" else d["spec"]
            # A Job runs up to `parallelism` pods at once (default 1), never more than
            # `completions` when that is set.
            copies = int(spec.get("parallelism", 1))
            if spec.get("completions") is not None:
                copies = min(copies, int(spec["completions"]))
            jobs.extend([pod_limits(spec["template"]["spec"])] * max(copies, 0))
    # CPU and memory are each charged their own worst case: the jobs that peak on CPU need
    # not be the ones that peak on memory.
    cpu += sum(sorted((c for c, _ in jobs), reverse=True)[:concurrent_jobs])
    mem += sum(sorted((m for _, m in jobs), reverse=True)[:concurrent_jobs])
    pods += min(len(jobs), concurrent_jobs)
    return cpu, mem, pods


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rendered", type=Path)
    ap.add_argument("--limits-cpu", required=True)
    ap.add_argument("--limits-memory", required=True)
    ap.add_argument("--pods", type=int, required=True)
    ap.add_argument("--concurrent-jobs", type=int, default=2)
    args = ap.parse_args(argv)
    try:
        docs = [d for d in yaml.safe_load_all(args.rendered.read_text(encoding="utf-8")) if d]
        cpu, mem, pods = worst_case(docs, args.concurrent_jobs)
        cap_cpu, cap_mem = cpu_millis(args.limits_cpu), mem_bytes(args.limits_memory)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as e:
        print(f"quota-fit: cannot evaluate {args.rendered} ({type(e).__name__})", file=sys.stderr)
        return 2
    report = (
        f"cpu {cpu}m/{cap_cpu}m, memory {mem // 2**20}Mi/{cap_mem // 2**20}Mi, "
        f"pods {pods}/{args.pods}"
    )
    if cpu > cap_cpu or mem > cap_mem or pods > args.pods:
        print(f"quota-fit: {args.rendered} does NOT fit at rollout peak: {report}", file=sys.stderr)
        return 1
    print(f"quota-fit: {args.rendered} fits at rollout peak: {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
