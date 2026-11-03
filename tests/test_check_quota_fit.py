"""Tests for scripts/ci/check_quota_fit.py (#162)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "check_quota_fit.py"
_spec = importlib.util.spec_from_file_location("check_quota_fit", _PATH)
assert _spec and _spec.loader
qf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qf)


def _c(name: str, cpu: str, mem: str) -> dict:
    return {"name": name, "resources": {"limits": {"cpu": cpu, "memory": mem}}}


def _deploy(containers: list[dict], surge: object = 1, replicas: int = 1) -> dict:
    return {
        "kind": "Deployment",
        "spec": {
            "replicas": replicas,
            "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": surge}},
            "template": {"spec": {"containers": containers}},
        },
    }


def _cron(cpu: str, mem: str = "128Mi") -> dict:
    pod = {"containers": [_c("job", cpu, mem)]}
    return {"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": {"spec": pod}}}}}


def _job(cpu: str, parallelism: int, completions: int | None = None) -> dict:
    spec: dict = {
        "parallelism": parallelism,
        "template": {"spec": {"containers": [_c("j", cpu, "64Mi")]}},
    }
    if completions is not None:
        spec["completions"] = completions
    return {"kind": "Job", "spec": spec}


def test_units() -> None:
    assert qf.cpu_millis("1") == 1000
    assert qf.cpu_millis("1.5") == 1500
    assert qf.cpu_millis("400m") == 400
    assert qf.mem_bytes("1Gi") == 2**30
    assert qf.mem_bytes("128Mi") == 128 * 2**20
    assert qf.mem_bytes("1000") == 1000


def test_old_staging_limits_do_not_fit() -> None:
    # The #162 incident: 1.6 CPU per pod, surge 1, quota 3 CPU.
    docs = [
        _deploy(
            [_c("gateway", "1", "1Gi"), _c("auth", "500m", "128Mi"), _c("wif", "100m", "128Mi")]
        )
    ]
    cpu, _, pods = qf.worst_case(docs, 0)
    assert (cpu, pods) == (3200, 2)


def test_jobs_count_largest_first() -> None:
    docs = [_deploy([_c("g", "800m", "1Gi")]), _cron("200m"), _cron("100m"), _cron("300m")]
    cpu, _, pods = qf.worst_case(docs, 2)
    assert cpu == 1600 + 300 + 200
    assert pods == 4


def test_percent_surge_rounds_up() -> None:
    docs = [_deploy([_c("g", "100m", "64Mi")], surge="25%", replicas=3)]
    _, _, pods = qf.worst_case(docs, 0)
    assert pods == 4


def test_init_container_charged_when_larger() -> None:
    pod = {"containers": [_c("a", "100m", "64Mi")], "initContainers": [_c("i", "500m", "32Mi")]}
    assert qf.pod_limits(pod) == (500, 64 * 2**20)


def test_missing_limit_is_an_error() -> None:
    with pytest.raises(ValueError):
        qf.pod_limits({"containers": [{"name": "x", "resources": {}}]})


@pytest.mark.parametrize(("cpu", "code"), [("650m", 0), ("700m", 1)])
def test_main_exit_codes(tmp_path: Path, cpu: str, code: int) -> None:
    f = tmp_path / "r.yaml"
    f.write_text(yaml.safe_dump_all([_deploy([_c("g", cpu, "256Mi")])]), encoding="utf-8")
    assert (
        qf.main([str(f), "--limits-cpu", "1300m", "--limits-memory", "1Gi", "--pods", "5"]) == code
    )


def test_main_bad_input(tmp_path: Path) -> None:
    f = tmp_path / "r.yaml"
    f.write_text("kind: Deployment\nspec: {}\n", encoding="utf-8")
    assert qf.main([str(f), "--limits-cpu", "1", "--limits-memory", "1Gi", "--pods", "1"]) == 2


def test_memory_worst_case_is_independent_of_cpu() -> None:
    # Copilot's example on #163: the CPU-largest jobs are not the memory-largest ones.
    docs = [_cron("200m"), _cron("200m"), _cron("100m", "512Mi")]
    cpu, mem, pods = qf.worst_case(docs, 2)
    assert cpu == 400
    assert mem == (512 + 128) * 2**20
    assert pods == 2


@pytest.mark.parametrize(("parallelism", "completions", "cpu"), [(2, None, 600), (3, 1, 300)])
def test_job_parallelism(parallelism: int, completions: int | None, cpu: int) -> None:
    got, _, _ = qf.worst_case([_job("300m", parallelism, completions)], 2)
    assert got == cpu
