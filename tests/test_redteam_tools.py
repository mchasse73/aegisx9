import importlib.util
import json
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def _load(rel: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(rel.replace("/", "_"), ROOT / rel)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load("redteam/garak/gate.py")
rollout = _load("redteam/wait_for_rollout.py")


def test_gate_pass_rates_and_thresholds(tmp_path: Path) -> None:
    rows = [
        {"entry_type": "start_run setup"},
        {"entry_type": "eval", "probe": "dan.Dan_11_0", "passed": 9, "total": 10},
        {"entry_type": "eval", "probe": "dan.AutoDANCached", "passed": 10, "total": 10},
        {"entry_type": "eval", "probe": "encoding.InjectBase64", "passed": 5, "total": 10},
    ]
    report = tmp_path / "r.report.jsonl"
    report.write_text("\n".join(json.dumps(r) for r in rows) + "\n\n")
    rates = gate.pass_rates(report)
    assert rates == {"dan": 0.95, "encoding": 0.5}
    thresholds = json.loads((ROOT / "redteam/garak/thresholds.json").read_text())
    assert gate.evaluate(rates, thresholds) == ["encoding"]


def test_rollout_complete() -> None:
    digest = "sha256:" + "a" * 64
    deploy = {
        "metadata": {"generation": 2},
        "spec": {
            "replicas": 2,
            "template": {"spec": {"containers": [{"image": f"img@{digest}"}]}},
        },
        "status": {"observedGeneration": 2, "updatedReplicas": 2, "availableReplicas": 2},
    }
    assert rollout.rollout_complete(deploy, digest)
    deploy["status"]["availableReplicas"] = 1
    assert not rollout.rollout_complete(deploy, digest)
    assert rollout.DIGEST_RE.match(digest)
