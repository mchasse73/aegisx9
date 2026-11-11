"""Score detectors against the guard-evaluation sets (refs #198, ADR 0024).

Detectors:
- ``HeuristicDetector``: the gateway's input guards, run exactly as the proxy hook runs them
  for a request with one user message (``AegisGuard.pre_call`` on ``default_pipeline``). A
  prompt counts as blocked when the hook refuses it.
- ``HFClassifierDetector``: a Hugging Face sequence classifier at a pinned revision. Each
  prompt is split by the tokenizer's own overflow windows (512 tokens by default, special
  tokens included) with overlap; its score is the injection probability of its
  highest-scoring window. Groups of 32 prompts are tokenized together and their windows
  batched; a separate sample of prompts scored one at a time gives the latency a gateway
  sidecar would see. Two runtimes score the windows behind the same ``predict`` callable
  (#211): ``torch-fp32`` (the weights as published) and ``onnx-int8`` (the weights exported
  to ONNX, dynamically quantised to int8 and run by onnxruntime on CPU, as the sidecar
  would run them).

The summary records block counts and rates per family and corpus, the classifier at several
thresholds, "heuristics OR classifier" (from the heuristics job's per-prompt outcomes, so the
heuristic pass runs once per dispatch), latency, and the model's resolved revision and the
sha256 of every weights file (for onnx-int8, also the exported and quantised files' sha256,
the opset and the onnx/onnxruntime versions). Prompt text is never printed or written to the
summary. ``run --scores-out`` writes a classifier's per-prompt scores keyed by set, family and
index (no text), which ``compare`` uses for the share of decisions two runtimes disagree on.

Gate (``run --gate``, heuristics): every target family 100% blocked, no false positive, the
word list matches its pin, and every target family has ADR 0024's count. A hold-out count
that differs is a warning, shown in the summary.

Subcommands:
  plan      turn the dispatch input into a JSON matrix of model x runtime (stdout)
  download  fetch one model's top-level files at its revision (HF_TOKEN from env only)
  run       score the sets with one runtime
  compare   runtime agreement for every model scored by more than one runtime
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import sys
import tempfile
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from redteam.eval.common import FP, SEED, SET_ORDER, TARGET, package_version

THRESHOLDS = (0.5, 0.8, 0.9, 0.95, 0.99)
DEFAULT_MAX_LENGTH = 512
DEFAULT_OVERLAP = 64
BATCH_WINDOWS = 32
SINGLE_PROMPT_SAMPLE = 200
# model_id@revision:label, e.g. org/name@<40-hex commit>:INJECTION (label: name or index).
_SPEC = re.compile(
    r"^(?P<model>[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*)"
    r"@(?P<revision>[A-Za-z0-9][A-Za-z0-9_.-]*)"
    r":(?P<label>[A-Za-z0-9_.-]+)$"
)
# Top-level files a classifier needs; weights only as safetensors (no pickled .bin).
_MODEL_FILE = re.compile(r"^[^/]+\.(json|model|txt|safetensors)$")
_GATED = "gated model and no HF_TOKEN in the guard-eval environment"
# Schema 3 adds each classifier's ``runtime`` (and ``onnx`` for onnx-int8). A schema 2
# summary has no runtime and is read as torch-fp32.
SCHEMA = 3
READABLE_SCHEMAS = (2, 3)
TORCH_FP32, ONNX_INT8 = "torch-fp32", "onnx-int8"
RUNTIMES = (TORCH_FP32, ONNX_INT8)
ONNX_OPSET = 20
# Dynamic int8 quantisation as the sidecar will run it; recorded in the summary.
QUANTIZATION: dict[str, Any] = {
    "method": "onnxruntime.quantization.quantize_dynamic",
    "weight_type": "QInt8",
    "per_channel": False,
    "reduce_range": False,
}
EXPORT_CHECK_WINDOWS = (512, 300, 64, 7)  # window lengths for the fp32 export parity check
EXPORT_CHECK_TOLERANCE = 1e-3


# --------------------------------------------------------------------------- data
@dataclass(frozen=True)
class Prompt:
    set: str
    family: str
    text: str = field(repr=False)


@dataclass(frozen=True)
class Outcome:
    """One prompt's result. ``blocked`` for binary detectors, ``score`` for classifiers.

    ``seconds`` is the prompt's share of its batch; ``chunk_seconds`` the batch time per
    window (None: ``seconds`` / ``chunks``).
    """

    blocked: bool = False
    score: float | None = None
    chunks: int = 1
    seconds: float = 0.0
    blocked_by: str | None = None
    chunk_seconds: float | None = None


def load_sets(directory: Path) -> tuple[dict[str, Any], list[Prompt]]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    prompts = []
    with (directory / "prompts.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                prompts.append(Prompt(row["set"], row["family"], row["text"]))
    return manifest, prompts


@dataclass(frozen=True)
class ModelSpec:
    model_id: str
    revision: str
    label: str

    @property
    def slug(self) -> str:
        """Sanitised model name plus a hash of the whole spec (label included).

        Sanitising alone collides (``org_a/m`` and ``org/a_m``; one model with two labels),
        and parallel matrix jobs would then upload to the same artifact name.
        """
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", self.model_id)
        return f"{name}-{hashlib.sha256(str(self).encode()).hexdigest()[:12]}"

    def __str__(self) -> str:
        return f"{self.model_id}@{self.revision}:{self.label}"


def parse_spec(text: str) -> ModelSpec:
    m = _SPEC.match(text.strip())
    if not m:
        raise ValueError("model spec must be model_id@revision:label")
    return ModelSpec(m["model"], m["revision"], m["label"])


def parse_runtimes(text: str | None) -> list[str]:
    """Comma- or newline-separated runtimes, in order, without repeats; empty = all of them.

    An unknown value is refused; the message names the valid ones, never the input.
    """
    items = [t.strip() for t in re.split(r"[,\n]", text or "") if t.strip()]
    out: list[str] = []
    for item in items or RUNTIMES:
        if item not in RUNTIMES:
            raise ValueError(f"runtimes must be a list of: {', '.join(RUNTIMES)}")
        if item not in out:
            out.append(item)
    return out


def artifact_slug(spec: ModelSpec, runtime: str) -> str:
    """One matrix job's artifact and file name: the spec's slug plus the runtime."""
    return f"{spec.slug}-{runtime}"


def parse_models(text: str) -> list[ModelSpec]:
    """Newline- or comma-separated specs; blank entries and ``#`` comments are ignored."""
    specs = []
    for item in re.split(r"[,\n]", text or ""):
        item = item.strip()
        if item and not item.startswith("#"):
            specs.append(parse_spec(item))
    return specs


# --------------------------------------------------------------------------- detectors
class Detector(Protocol):
    name: str

    def evaluate(self, text: str) -> Outcome: ...


class HeuristicDetector:
    """The input guards, through the proxy hook, for a request with one user message."""

    name = "heuristics"

    def __init__(self) -> None:
        from aegisx9.litellm_hooks import AegisGuard, GuardBlockedError
        from aegisx9.pipeline import default_pipeline

        # No audit sink: the eval measures verdicts, it doesn't write audit records.
        self._guard = AegisGuard(pipeline=default_pipeline())
        self._blocked_error = GuardBlockedError

    def evaluate(self, text: str) -> Outcome:
        data = {
            "model": "guard-eval",
            "messages": [{"role": "user", "content": text}],
            "metadata": {"aegis_request_id": uuid.uuid4().hex},
        }
        started = time.perf_counter()
        try:
            self._guard.pre_call(data)
        except self._blocked_error as blocked:
            return Outcome(True, None, 1, time.perf_counter() - started, blocked.guard)
        return Outcome(False, None, 1, time.perf_counter() - started)


class Tokenizer(Protocol):
    """The Hugging Face tokenizer call the detector uses (transformers 5.x, fast backend).

    With ``return_overflowing_tokens=True`` a long text comes back as several windows of at
    most ``max_length`` ids (special tokens included, added by the post-processor), each
    sharing ``stride`` ids with the previous one. ``overflow_to_sample_mapping`` gives each
    window's index in ``texts``.
    """

    def __call__(
        self,
        texts: list[str],
        *,
        truncation: bool,
        max_length: int,
        stride: int,
        return_overflowing_tokens: bool,
        padding: bool | str,
    ) -> Mapping[str, Any]: ...


Predict = Callable[[list[list[int]]], list[float]]


class HFClassifierDetector:
    """A sequence classifier; a prompt's score is its best window's injection probability."""

    def __init__(
        self,
        name: str,
        tokenizer: Tokenizer,
        predict: Predict,
        max_length: int = DEFAULT_MAX_LENGTH,
        overlap: int = DEFAULT_OVERLAP,
        batch_prompts: int = BATCH_WINDOWS,
    ) -> None:
        self.name = name
        self._tok = tokenizer
        self._predict = predict
        self._max_length = max_length
        self._overlap = overlap
        self._batch_prompts = batch_prompts

    def windows(self, texts: Sequence[str]) -> tuple[list[list[int]], list[int]]:
        """Every window of every text, and the index of the text each one belongs to."""
        enc = self._tok(
            list(texts),
            truncation=True,
            max_length=self._max_length,
            stride=self._overlap,
            return_overflowing_tokens=True,
            padding=False,  # predict pads each model batch to its own longest window
        )
        windows = [list(ids) for ids in enc["input_ids"]]
        return windows, [int(i) for i in enc["overflow_to_sample_mapping"]]

    def _score(self, texts: Sequence[str]) -> tuple[list[float], list[int], int, float]:
        started = time.perf_counter()
        windows, owner = self.windows(texts)
        scores = self._predict(windows) if windows else []
        best = [0.0] * len(texts)
        counts = [0] * len(texts)
        for window_score, i in zip(scores, owner, strict=True):
            best[i] = window_score if counts[i] == 0 else max(best[i], window_score)
            counts[i] += 1
        return best, counts, len(windows), time.perf_counter() - started

    def evaluate(self, text: str) -> Outcome:
        """One prompt on its own, as the gateway would score a request."""
        best, counts, _, elapsed = self._score([text])
        return Outcome(score=best[0], chunks=counts[0], seconds=elapsed)

    def evaluate_many(self, texts: Sequence[str]) -> list[Outcome]:
        """Score prompts in groups: one tokenizer call per group, windows batched together.

        A group of ``batch_prompts`` prompts is tokenized in one call; their windows go to
        ``predict`` together (it splits them into model batches of ``BATCH_WINDOWS``). Each
        prompt's score is the max over its own windows, found through
        ``overflow_to_sample_mapping``. Its latency is the group's time divided by the
        prompts in it; per chunk, by the windows in it.
        """
        outcomes: list[Outcome] = []
        for start in range(0, len(texts), self._batch_prompts):
            group = texts[start : start + self._batch_prompts]
            best, counts, n_windows, elapsed = self._score(group)
            per_prompt = elapsed / len(group)
            per_chunk = elapsed / max(n_windows, 1)
            outcomes.extend(
                Outcome(score=b, chunks=c, seconds=per_prompt, chunk_seconds=per_chunk)
                for b, c in zip(best, counts, strict=True)
            )
        return outcomes


def resolve_label(id2label: dict[int, str], label: str) -> int:
    """The class index for ``label``: an index, or a label name (case-insensitive)."""
    if label.isdigit() and int(label) in id2label:
        return int(label)
    matches = [i for i, name in id2label.items() if str(name).lower() == label.lower()]
    if len(matches) != 1:
        raise ValueError(f"label {label!r} not in model labels {sorted(id2label.values())}")
    return matches[0]


Logits = Callable[[list[list[int]], list[list[int]]], Sequence[Sequence[float]]]


def pad_batch(batch: Sequence[Sequence[int]], pad: int) -> tuple[list[list[int]], list[list[int]]]:
    """Right-pad windows to the batch's longest; the attention mask marks the real ids."""
    width = max(len(w) for w in batch)
    ids = [[*w, *[pad] * (width - len(w))] for w in batch]
    mask = [[1] * len(w) + [0] * (width - len(w)) for w in batch]
    return ids, mask


def softmax_at(row: Sequence[float], index: int) -> float:
    """The probability of class ``index`` from one row of logits (numerically stable)."""
    top = max(row)
    exps = [math.exp(x - top) for x in row]
    return exps[index] / sum(exps)


def make_predict(logits: Logits, pad: int, index: int, batch: int = BATCH_WINDOWS) -> Predict:
    """The ``predict`` both runtimes share: model batches of ``batch`` windows, padded, softmax.

    ``logits(ids, mask)`` is the runtime's part (a torch forward pass or an onnxruntime
    session run); it returns one row of logits per window.
    """

    def predict(windows: list[list[int]]) -> list[float]:
        out: list[float] = []
        for i in range(0, len(windows), batch):
            ids, mask = pad_batch(windows[i : i + batch], pad)
            rows = logits(ids, mask)
            if len(rows) != len(ids):
                raise ValueError("the runtime returned a different number of rows")
            out.extend(softmax_at([float(x) for x in row], index) for row in rows)
        return out

    return predict


def export_check_windows(vocab_size: int, cls: int, sep: int) -> list[list[int]]:
    """Fixed pseudo-random windows, special ids at both ends, for the export parity check."""
    rng = random.Random(SEED)  # noqa: S311 - reproducible inputs, not a secret
    hi = max(vocab_size - 1, 3)
    return [[cls, *(rng.randint(3, hi) for _ in range(n - 2)), sep] for n in EXPORT_CHECK_WINDOWS]


def _load_hf(
    meta: dict[str, Any], label: str
) -> tuple[Any, Any, int, int, int]:  # pragma: no cover - needs torch and a downloaded model
    from transformers import (  # type: ignore[import-not-found,unused-ignore]
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    path = meta["local_path"]
    tok = AutoTokenizer.from_pretrained(path, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        path, local_files_only=True, use_safetensors=True
    )
    model.eval()
    index = resolve_label({int(k): v for k, v in model.config.id2label.items()}, label)
    meta["label_index"] = index
    meta["labels"] = {str(k): v for k, v in model.config.id2label.items()}
    pad = tok.pad_token_id if tok.pad_token_id is not None else 0
    max_length = min(int(getattr(tok, "model_max_length", DEFAULT_MAX_LENGTH)), DEFAULT_MAX_LENGTH)
    return tok, model, index, pad, max_length


def _torch_logits(model: Any) -> Logits:  # pragma: no cover - needs torch (CI only)
    import torch  # type: ignore[import-not-found,unused-ignore]

    def logits(ids: list[list[int]], mask: list[list[int]]) -> Any:
        with torch.no_grad():
            out = model(input_ids=torch.tensor(ids), attention_mask=torch.tensor(mask)).logits
        return out.tolist()

    return logits


def load_hf_detector(
    meta: dict[str, Any], label: str
) -> HFClassifierDetector:  # pragma: no cover - needs torch and a downloaded model (CI only)
    tok, model, index, pad, max_length = _load_hf(meta, label)
    predict = make_predict(_torch_logits(model), pad, index)
    return HFClassifierDetector(meta["model_id"], tok, predict, max_length=max_length)


def export_onnx(model: Any, path: Path, max_length: int) -> str:  # pragma: no cover - CI only
    """Export ``logits(input_ids, attention_mask)`` with dynamic batch and sequence axes.

    torch's default exporter (``torch.export`` based, needs onnxscript) at a pinned opset,
    as one self-contained file, so its sha256 covers every weight. The exporter's
    intermediate shape annotations (``value_info``) are dropped: onnxruntime's quantiser
    re-infers shapes and refuses a DeBERTa-v2 export that keeps them ("inferred shape and
    existing shape differ"). Inputs, outputs and weights are untouched.
    """
    import onnx  # type: ignore[import-not-found,unused-ignore]
    import torch  # type: ignore[import-not-found,unused-ignore]

    class LogitsOnly(torch.nn.Module):  # type: ignore[misc,unused-ignore]
        def __init__(self, inner: Any) -> None:
            super().__init__()
            self.inner = inner

        def forward(self, input_ids: Any, attention_mask: Any) -> Any:
            return self.inner(input_ids=input_ids, attention_mask=attention_mask).logits

    ids = torch.ones((2, 16), dtype=torch.long)
    batch = torch.export.Dim("batch", min=1, max=4096)
    seq = torch.export.Dim("sequence", min=2, max=max_length)
    axes = {0: batch, 1: seq}
    with torch.no_grad():
        torch.onnx.export(
            LogitsOnly(model).eval(),
            (ids, torch.ones_like(ids)),
            str(path),
            input_names=["input_ids", "attention_mask"],
            output_names=["logits"],
            dynamic_shapes={"input_ids": axes, "attention_mask": axes},
            opset_version=ONNX_OPSET,
            dynamo=True,
            external_data=False,
        )
    exported = onnx.load(str(path))
    del exported.graph.value_info[:]
    onnx.save(exported, str(path))
    return "torch.onnx.export (dynamo), value_info dropped"


def load_onnx_detector(
    meta: dict[str, Any], label: str, work_dir: Path
) -> HFClassifierDetector:  # pragma: no cover - needs torch, onnxruntime and a model (CI only)
    """Export the pinned weights to ONNX, quantise them to int8, score with onnxruntime (CPU).

    Before quantising, the fp32 export is checked against torch on fixed windows, so a broken
    export isn't mistaken for a quantisation effect.
    """
    import gc

    import numpy as np  # type: ignore[import-not-found,unused-ignore]
    import onnx  # type: ignore[import-not-found,unused-ignore]
    import onnxruntime as ort  # type: ignore[import-not-found,unused-ignore]
    from onnxruntime.quantization import (  # type: ignore[import-not-found,unused-ignore]
        QuantType,
        quantize_dynamic,
    )

    tok, model, index, pad, max_length = _load_hf(meta, label)
    work_dir.mkdir(parents=True, exist_ok=True)
    fp32, int8 = work_dir / "model.onnx", work_dir / "model.int8.onnx"
    exporter = export_onnx(model, fp32, max_length)
    opsets = onnx.load(str(fp32), load_external_data=False).opset_import
    opset = next((o.version for o in opsets if o.domain in ("", "ai.onnx")), None)
    provider = "CPUExecutionProvider"

    def session_logits(path: Path) -> Logits:
        sess = ort.InferenceSession(str(path), providers=[provider])

        def logits(ids: list[list[int]], mask: list[list[int]]) -> Any:
            feed = {
                "input_ids": np.asarray(ids, dtype=np.int64),
                "attention_mask": np.asarray(mask, dtype=np.int64),
            }
            return sess.run(["logits"], feed)[0].tolist()

        return logits

    check = export_check_windows(
        int(model.config.vocab_size),
        tok.cls_token_id if tok.cls_token_id is not None else 1,
        tok.sep_token_id if tok.sep_token_id is not None else 2,
    )
    torch_p = make_predict(_torch_logits(model), pad, index)(check)
    onnx_p = make_predict(session_logits(fp32), pad, index)(check)
    diff = max(abs(a - b) for a, b in zip(torch_p, onnx_p, strict=True))
    if diff > EXPORT_CHECK_TOLERANCE:
        print(f"::warning::{meta['model_id']}: fp32 ONNX export differs from torch by {diff:.2e}")
    del model
    gc.collect()
    quantize_dynamic(
        str(fp32),
        str(int8),
        weight_type=QuantType.QInt8,
        per_channel=bool(QUANTIZATION["per_channel"]),
        reduce_range=bool(QUANTIZATION["reduce_range"]),
    )
    meta["onnx"] = {
        "exporter": exporter,
        "opset": opset,
        "file": int8.name,
        "sha256": sha256_file(int8),
        "bytes": int8.stat().st_size,
        "fp32_file": fp32.name,
        "fp32_sha256": sha256_file(fp32),
        "fp32_bytes": fp32.stat().st_size,
        "quantization": dict(QUANTIZATION),
        "provider": provider,
        "versions": {d: package_version(d) for d in ("onnx", "onnxscript", "onnxruntime", "torch")},
        "export_check": {
            "windows": len(check),
            "max_abs_prob_diff": diff,
            "tolerance": EXPORT_CHECK_TOLERANCE,
        },
    }
    predict = make_predict(session_logits(int8), pad, index)
    return HFClassifierDetector(meta["model_id"], tok, predict, max_length=max_length)


def load_detector(
    meta: dict[str, Any], runtime: str, work_dir: Path | None = None
) -> HFClassifierDetector:
    if runtime == ONNX_INT8:
        return load_onnx_detector(meta, meta["label"], work_dir or Path(tempfile.mkdtemp()))
    return load_hf_detector(meta, meta["label"])


# --------------------------------------------------------------------------- scoring
def run_detector(detector: Any, prompts: Sequence[Prompt]) -> list[Outcome]:
    if hasattr(detector, "evaluate_many"):
        return list(detector.evaluate_many([p.text for p in prompts]))
    return [detector.evaluate(p.text) for p in prompts]


def single_prompt_sample(n: int, size: int = SINGLE_PROMPT_SAMPLE) -> list[int]:
    """Deterministic indices for the batch-size-1 latency sample."""
    rng = random.Random(SEED)  # noqa: S311 - a reproducible sample, not a secret
    return sorted(rng.sample(range(n), min(size, n)))


def tally(prompts: Sequence[Prompt], blocked: Sequence[bool]) -> dict[str, Any]:
    """Counts and rates per family, per set, plus the hold-out and FP totals."""
    fam: dict[str, dict[str, Any]] = {}
    per_set: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for prompt, b in zip(prompts, blocked, strict=True):
        row = fam.setdefault(prompt.family, {"set": prompt.set, "n": 0, "blocked": 0})
        row["n"] += 1
        row["blocked"] += int(b)
        per_set[prompt.set][0] += 1
        per_set[prompt.set][1] += int(b)
    for row in fam.values():
        row["rate"] = rate(row["blocked"], row["n"])
    sets = {s: {"n": n, "blocked": k, "rate": rate(k, n)} for s, (n, k) in per_set.items()}
    return {"families": fam, "sets": sets}


def rate(k: int, n: int) -> float:
    return round(k / n, 6) if n else 0.0


def percentile(values: Sequence[float], p: float) -> float:
    """Nearest-rank percentile (deterministic, no interpolation)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(p / 100 * len(ordered)))
    return ordered[rank - 1]


def latency(outcomes: Sequence[Outcome]) -> dict[str, Any]:
    per_prompt = [o.seconds * 1000 for o in outcomes]
    per_chunk = [
        (o.chunk_seconds if o.chunk_seconds is not None else o.seconds / max(o.chunks, 1)) * 1000
        for o in outcomes
    ]
    chunks = [o.chunks for o in outcomes]
    return {
        "prompts": len(outcomes),
        "chunks": sum(chunks),
        "max_chunks": max(chunks, default=0),
        "per_prompt_ms": {
            "p50": round(percentile(per_prompt, 50), 3),
            "p95": round(percentile(per_prompt, 95), 3),
        },
        "per_chunk_ms": {
            "p50": round(percentile(per_chunk, 50), 3),
            "p95": round(percentile(per_chunk, 95), 3),
        },
    }


def heuristic_summary(prompts: Sequence[Prompt], outcomes: Sequence[Outcome]) -> dict[str, Any]:
    by_guard: dict[str, int] = defaultdict(int)
    for o in outcomes:
        if o.blocked_by:
            by_guard[o.blocked_by] += 1
    return {
        "kind": "heuristic",
        "name": "heuristics",
        **tally(prompts, [o.blocked for o in outcomes]),
        "blocked_by": dict(sorted(by_guard.items())),
        "latency": latency(outcomes),
    }


def classifier_summary(
    prompts: Sequence[Prompt],
    outcomes: Sequence[Outcome],
    meta: dict[str, Any],
    heuristic: Sequence[bool] | None = None,
    single: Sequence[Outcome] = (),
    thresholds: Sequence[float] = THRESHOLDS,
) -> dict[str, Any]:
    scores = [o.score if o.score is not None else 0.0 for o in outcomes]
    by_threshold: dict[str, Any] = {}
    for t in thresholds:
        cls = [s >= t for s in scores]
        entry: dict[str, Any] = {"classifier": tally(prompts, cls)}
        if heuristic is not None:
            combined = [c or h for c, h in zip(cls, heuristic, strict=True)]
            entry["combined"] = tally(prompts, combined)
        by_threshold[f"{t:g}"] = entry
    keys = (
        "model_id",
        "revision",
        "resolved_revision",
        "label",
        "label_index",
        "labels",
        "weights",
    )
    extra = {"onnx": meta["onnx"]} if meta.get("onnx") is not None else {}
    return {
        "kind": "classifier",
        "name": meta.get("model_id", "classifier"),
        **{k: meta.get(k) for k in keys},
        "runtime": meta.get("runtime") or TORCH_FP32,
        **extra,
        "thresholds": by_threshold,
        "latency": {"batched": latency(outcomes), "single_prompt": latency(single)},
    }


# --------------------------------------------------------------------------- heuristic outcomes
def _family_hashes(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        f"{s['set']}/{name}": s["sha256"]
        for group in ("attack_families", "fp_corpora")
        for name, s in manifest.get(group, {}).items()
    }


def outcomes_record(
    manifest: dict[str, Any], prompts: Sequence[Prompt], blocked: Sequence[bool]
) -> dict[str, Any]:
    """Per-prompt verdicts keyed by set/family and index within it; no text."""
    hashes = _family_hashes(manifest)
    families: dict[str, dict[str, Any]] = {}
    for prompt, b in zip(prompts, blocked, strict=True):
        key = f"{prompt.set}/{prompt.family}"
        entry = families.setdefault(key, {"sha256": hashes.get(key), "blocked": []})
        entry["blocked"].append(int(b))
    return {"schema": 1, "kind": "heuristic_outcomes", "families": families}


def outcomes_for(
    record: dict[str, Any], manifest: dict[str, Any], prompts: Sequence[Prompt]
) -> list[bool]:
    """Map a heuristics job's record back onto these prompts, refusing different sets."""
    hashes = _family_hashes(manifest)
    families = record["families"]
    index: dict[str, int] = defaultdict(int)
    out = []
    for prompt in prompts:
        key = f"{prompt.set}/{prompt.family}"
        entry = families.get(key)
        if entry is None or entry["sha256"] != hashes.get(key):
            raise ValueError(f"heuristic outcomes were computed on different sets ({key})")
        out.append(bool(entry["blocked"][index[key]]))
        index[key] += 1
    for key, entry in families.items():
        if index[key] != len(entry["blocked"]):
            raise ValueError(f"heuristic outcomes were computed on different sets ({key})")
    return out


# --------------------------------------------------------------------------- runtime agreement
def spec_of(c: Mapping[str, Any]) -> str:
    return f"{c.get('model_id')}@{c.get('revision')}:{c.get('label')}"


def runtime_of(c: Mapping[str, Any]) -> str:
    """A classifier summary's runtime; schema 2 summaries predate runtimes (torch-fp32)."""
    return str(c.get("runtime") or TORCH_FP32)


def scores_record(
    manifest: dict[str, Any],
    prompts: Sequence[Prompt],
    outcomes: Sequence[Outcome],
    spec: str,
    runtime: str,
) -> dict[str, Any]:
    """One classifier's per-prompt scores keyed by set/family and index; no text."""
    hashes = _family_hashes(manifest)
    families: dict[str, dict[str, Any]] = {}
    for prompt, o in zip(prompts, outcomes, strict=True):
        key = f"{prompt.set}/{prompt.family}"
        entry = families.setdefault(key, {"sha256": hashes.get(key), "scores": []})
        entry["scores"].append(o.score if o.score is not None else 0.0)
    return {
        "schema": 1,
        "kind": "classifier_scores",
        "spec": spec,
        "runtime": runtime,
        "families": families,
    }


def decision_flips(
    a: Mapping[str, Any], b: Mapping[str, Any], thresholds: Sequence[str]
) -> dict[str, Any]:
    """Per threshold and set: prompts whose block decision differs between two score records.

    Also the largest and mean absolute score difference. Refuses records of different sets.
    """
    fa, fb = a["families"], b["families"]
    if set(fa) != set(fb):
        raise ValueError("score records cover different families")
    by_t: dict[str, dict[str, list[int]]] = {t: defaultdict(lambda: [0, 0]) for t in thresholds}
    diffs: list[float] = []
    for key in sorted(fa):
        ea, eb = fa[key], fb[key]
        if ea["sha256"] != eb["sha256"] or len(ea["scores"]) != len(eb["scores"]):
            raise ValueError(f"score records were computed on different sets ({key})")
        set_name = key.split("/", 1)[0]
        for sa, sb in zip(ea["scores"], eb["scores"], strict=True):
            diffs.append(abs(sa - sb))
            for t in thresholds:
                row = by_t[t][set_name]
                row[0] += 1
                row[1] += int((sa >= float(t)) != (sb >= float(t)))
    return {
        "thresholds": {
            t: {s: {"n": n, "differ": k, "rate": rate(k, n)} for s, (n, k) in rows.items()}
            for t, rows in by_t.items()
        },
        "score_abs_diff": {
            "max": max(diffs, default=0.0),
            "mean": sum(diffs) / len(diffs) if diffs else 0.0,
        },
    }


def collect_results(
    paths: Sequence[Path],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    """Classifier summaries and score records from files or directories of JSON files.

    Score records pair with summaries by spec and runtime. Heuristic outcomes are ignored. A
    summary with a schema this reader doesn't know is refused.
    """
    files: list[Path] = []
    for p in paths:
        files.extend(sorted(p.rglob("*.json")) if p.is_dir() else [p])
    classifiers: list[dict[str, Any]] = []
    scores: dict[tuple[str, str], dict[str, Any]] = {}
    for f in files:
        doc = json.loads(f.read_text(encoding="utf-8"))
        if doc.get("kind") == "classifier_scores":
            scores[(doc["spec"], doc["runtime"])] = doc
        elif "classifiers" in doc:
            if doc.get("schema") not in READABLE_SCHEMAS:
                raise ValueError(f"unknown summary schema in {f.name}")
            classifiers.extend(doc["classifiers"])
    return classifiers, scores


def compare_runtimes(
    classifiers: Sequence[Mapping[str, Any]],
    scores: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """For each spec scored by two or more runtimes: every other runtime against the baseline.

    The baseline is torch-fp32 when present. Per threshold and set: both block rates and
    the delta in percentage points; with both runtimes' score records, also the share of
    prompts whose decision differs.
    """
    scores = scores or {}
    by_spec: dict[str, dict[str, Mapping[str, Any]]] = defaultdict(dict)
    for c in classifiers:
        by_spec[spec_of(c)].setdefault(runtime_of(c), c)
    out: list[dict[str, Any]] = []
    for spec, runs in sorted(by_spec.items()):
        if len(runs) < 2:
            continue
        base_rt = TORCH_FP32 if TORCH_FP32 in runs else sorted(runs)[0]
        base = runs[base_rt]
        for rt in sorted(r for r in runs if r != base_rt):
            other = runs[rt]
            thresholds = [t for t in base["thresholds"] if t in other["thresholds"]]
            rows = []
            for t in thresholds:
                sa = base["thresholds"][t]["classifier"]["sets"]
                sb = other["thresholds"][t]["classifier"]["sets"]
                for s in [s for s in SET_ORDER if s in sa and s in sb]:
                    rows.append(
                        {
                            "threshold": t,
                            "set": s,
                            "base": sa[s],
                            "other": sb[s],
                            "delta_pp": round((sb[s]["rate"] - sa[s]["rate"]) * 100, 4),
                        }
                    )
            entry: dict[str, Any] = {
                "spec": spec,
                "baseline": base_rt,
                "runtime": rt,
                "rows": rows,
                "latency": {base_rt: base.get("latency"), rt: other.get("latency")},
                "flips": None,
            }
            ra, rb = scores.get((spec, base_rt)), scores.get((spec, rt))
            if ra is not None and rb is not None:
                entry["flips"] = decision_flips(ra, rb, thresholds)
            out.append(entry)
    return out


def render_compare(comparisons: Sequence[Mapping[str, Any]]) -> str:
    """Rate deltas (and decision flips when per-prompt scores exist), family names only."""
    lines = ["## Runtime agreement", ""]
    if not comparisons:
        lines.append("No model was scored by more than one runtime.")
        return "\n".join(lines) + "\n"
    for c in comparisons:
        base, rt, flips = c["baseline"], c["runtime"], c["flips"]
        lines += [f"### {c['spec']}: {rt} vs {base}", ""]
        lines.append(f"| threshold | set | {base} | {rt} | Δ (pp) | decisions differ |")
        lines.append("|---|---|---|---|---|---|")
        for r in c["rows"]:
            differ = "-"
            if flips is not None:
                d = flips["thresholds"].get(r["threshold"], {}).get(r["set"])
                differ = f"{d['rate'] * 100:.2f}% ({d['differ']}/{d['n']})" if d else "-"
            lines.append(
                f"| ≥{r['threshold']} | {r['set']} | {_pct(r['base'])} | {_pct(r['other'])} "
                f"| {r['delta_pp']:+.2f} | {differ} |"
            )
        if flips is None:
            lines.append("\nNo per-prompt scores for both runtimes: rate deltas only.")
        else:
            d = flips["score_abs_diff"]
            lines.append(f"\nscore |Δ|: max {d['max']:.4f}, mean {d['mean']:.6f}")
        for name, lat in c["latency"].items():
            one = (lat or {}).get("single_prompt")
            if one:
                lines.append(
                    f"\n{name}, one prompt at a time: per chunk p50 {one['per_chunk_ms']['p50']} "
                    f"ms, p95 {one['per_chunk_ms']['p95']} ms"
                )
        lines.append("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- gate
def check_gate(manifest: dict[str, Any], heuristic: dict[str, Any]) -> tuple[list[str], list[str]]:
    """ADR 0024's bar for the heuristics: (failures, warnings).

    Fails: a target family below 100% or with a count other than ADR 0024's, any false
    positive, or a word list that isn't the pinned one (the FP results are then invalid).
    Warns: a hold-out family whose count differs.
    """
    failures: list[str] = []
    warnings: list[str] = []
    if not manifest.get("words", {}).get("match", False):
        failures.append(
            "the word list's sha256 differs from the pin: false-positive results are invalid"
        )
    for m in manifest.get("count_mismatches", []):
        text = f"{m['set']} {m['family']}: {m['n']} prompts, ADR 0024 has {m['expected']}"
        (failures if m["set"] == TARGET else warnings).append(text)
    for name, row in sorted(heuristic["families"].items()):
        if row["set"] == TARGET and row["blocked"] < row["n"]:
            failures.append(f"target {name}: {row['blocked']}/{row['n']} blocked, need all")
        if row["set"] == FP and row["blocked"]:
            failures.append(f"false positives in {name}: {row['blocked']}/{row['n']}")
    return failures, warnings


# --------------------------------------------------------------------------- reporting
def _pct(row: dict[str, Any]) -> str:
    return f"{row['rate'] * 100:.1f}% ({row['blocked']}/{row['n']})"


def _families(summary: dict[str, Any]) -> list[tuple[str, str]]:
    rows = summary["heuristics"]["families"] if summary.get("heuristics") else {}
    if not rows and summary["classifiers"]:
        first = next(iter(summary["classifiers"][0]["thresholds"].values()))
        rows = first["classifier"]["families"]
    pairs = [(r["set"], f) for f, r in rows.items()]
    return sorted(pairs, key=lambda x: (SET_ORDER.index(x[0]), x[1]))


def _set_label(s: str, pinned: bool) -> str:
    return "fp (unpinned corpus)" if s == FP and not pinned else s


def render_markdown(summary: dict[str, Any]) -> str:
    """Tables of counts and rates (family names only, never prompt text)."""
    lines = ["## Guard evaluation", ""]
    sets = summary["sets"]
    words = sets.get("words", {})
    pinned = bool(words.get("match"))
    lines.append(
        f"garak {sets.get('garak_version')}, word list sha256 "
        f"`{str(words.get('sha256', ''))[:12]}` (pinned: {pinned})"
    )
    if not pinned:
        lines.append("\n**Unpinned corpus:** the word list differs from the pin, so the")
        lines.append("false-positive results are invalid.")
    for m in sets.get("count_mismatches", []):
        lines.append(f"- {m['set']} {m['family']}: {m['n']} prompts, ADR 0024 has {m['expected']}")
    families = _families(summary)
    h = summary.get("heuristics")
    if h:
        lines += ["", "### Heuristics (input guards)", "", "| set | family | blocked |"]
        lines.append("|---|---|---|")
        for s, f in families:
            lines.append(f"| {_set_label(s, pinned)} | {f} | {_pct(h['families'][f])} |")
        for s in SET_ORDER:
            if s in h["sets"]:
                lines.append(
                    f"| **{_set_label(s, pinned)}** | **all** | **{_pct(h['sets'][s])}** |"
                )
        lat = h["latency"]["per_prompt_ms"]
        lines.append(f"\nper-prompt latency p50 {lat['p50']} ms, p95 {lat['p95']} ms")
    for c in summary["classifiers"]:
        lines += _classifier_lines(c, families, pinned)
    for s in summary.get("skipped", []):
        lines.append(f"\n- skipped {s['model']}: {s['reason']}")
    return "\n".join(lines) + "\n"


def _classifier_lines(
    c: dict[str, Any], families: list[tuple[str, str]], pinned: bool
) -> list[str]:
    head = " | ".join(f"≥{t}" for t in c["thresholds"])
    weights = ", ".join(f"{w['file']} `{w['sha256'][:12]}`" for w in c.get("weights") or [])
    rev = str(c["resolved_revision"])[:12]
    lines = [
        "",
        f"### {c['model_id']} @ `{rev}` (label {c['label']}) [{runtime_of(c)}]",
        "",
        f"weights: {weights or '-'}",
    ]
    onnx = c.get("onnx")
    if onnx:
        q = onnx.get("quantization") or {}
        versions = onnx.get("versions") or {}
        check = onnx.get("export_check") or {}
        lines.append(
            f"\nONNX int8: `{str(onnx.get('sha256'))[:12]}` ({onnx.get('bytes')} bytes), "
            f"from fp32 export `{str(onnx.get('fp32_sha256'))[:12]}` "
            f"({onnx.get('fp32_bytes')} bytes); opset {onnx.get('opset')}; "
            f"onnx {versions.get('onnx')}, onnxruntime {versions.get('onnxruntime')}; "
            f"{q.get('weight_type')} weights, per-channel {q.get('per_channel')}; "
            f"fp32 export vs torch: max |Δp| {check.get('max_abs_prob_diff')}"
        )
    lines += [
        "",
        f"| set | family | {head} | OR heuristics ≥0.9 |",
        "|---|---|" + "---|" * (len(c["thresholds"]) + 1),
    ]
    combined = c["thresholds"].get("0.9", {}).get("combined")
    for s, f in families:
        cells = [_pct(v["classifier"]["families"][f]) for v in c["thresholds"].values()]
        cells.append(_pct(combined["families"][f]) if combined else "-")
        lines.append(f"| {_set_label(s, pinned)} | {f} | " + " | ".join(cells) + " |")
    for s in SET_ORDER:
        cells = [
            _pct(v["classifier"]["sets"][s])
            for v in c["thresholds"].values()
            if s in v["classifier"]["sets"]
        ]
        if cells:
            cells.append(_pct(combined["sets"][s]) if combined else "-")
            bold = " | ".join(f"**{x}**" for x in cells)
            lines.append(f"| **{_set_label(s, pinned)}** | **all** | {bold} |")
    for kind, title in (("batched", "batched"), ("single_prompt", "one prompt at a time")):
        lat = c["latency"][kind]
        lines.append(
            f"\nlatency, {title} ({lat['prompts']} prompts): per prompt p50 "
            f"{lat['per_prompt_ms']['p50']} ms, p95 {lat['per_prompt_ms']['p95']} ms; per chunk "
            f"p50 {lat['per_chunk_ms']['p50']} ms, p95 {lat['per_chunk_ms']['p95']} ms; "
            f"at most {lat['max_chunks']} chunks per prompt"
        )
    return lines


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# --------------------------------------------------------------------------- download
@dataclass(frozen=True)
class Hub:
    """The three Hugging Face Hub calls the download needs (injectable for tests)."""

    model_info: Callable[..., Any]
    list_files: Callable[..., list[str]]
    fetch: Callable[..., str]


def default_hub() -> Hub:  # pragma: no cover - needs huggingface_hub (CI only)
    from huggingface_hub import (  # type: ignore[import-not-found,unused-ignore]
        HfApi,
        hf_hub_download,
    )

    api = HfApi()
    return Hub(api.model_info, api.list_repo_files, hf_hub_download)


def model_files(files: Sequence[str]) -> list[str]:
    """Top-level config, tokenizer and safetensors files only, sorted."""
    return sorted(f for f in files if _MODEL_FILE.match(f))


def http_status(e: BaseException) -> int | None:
    code = getattr(getattr(e, "response", None), "status_code", None)
    return code if isinstance(code, int) else None


def download(spec: ModelSpec, cache_dir: Path, hub: Hub, has_token: bool) -> dict[str, Any]:
    """Fetch exact top-level files at the resolved revision; hash every weights file.

    Status ``skipped`` only when there is no token and the hub answers 401/403 (gated).
    Anything else that fails is ``error``. Only the exception type and HTTP status are kept.
    """
    meta: dict[str, Any] = {
        "model_id": spec.model_id,
        "revision": spec.revision,
        "label": spec.label,
    }
    try:
        sha = str(hub.model_info(spec.model_id, revision=spec.revision).sha)
        meta["resolved_revision"] = sha
        files = model_files(hub.list_files(spec.model_id, revision=sha))
        weights = [f for f in files if f.endswith(".safetensors")]
        if not weights:
            meta.update(status="error", reason="no top-level safetensors weights at this revision")
            return meta
        paths = [
            hub.fetch(spec.model_id, f, revision=sha, cache_dir=str(cache_dir / "hub"))
            for f in files
        ]
    except Exception as e:  # never str(e): messages carry URLs (security rule 4)
        name, status = type(e).__name__, http_status(e)
        where = f"{name}, HTTP {status}" if status else name
        gated = status in (401, 403) or name == "GatedRepoError"
        if gated and not has_token:
            meta.update(status="skipped", reason=_GATED)
        elif gated:
            meta.update(
                status="error",
                reason=f"token lacks access ({where}): accept the model licence "
                "on Hugging Face for the token's account",
            )
        else:
            meta.update(status="error", reason=f"download failed ({where})")
        return meta
    local = Path(paths[0]).parent
    meta.update(
        status="ok",
        local_path=str(local),
        files=files,
        weights=[{"file": f, "sha256": sha256_file(local / f)} for f in weights],
    )
    return meta


# --------------------------------------------------------------------------- commands
def cmd_plan(args: argparse.Namespace) -> int:
    """MODELS x RUNTIMES (env) -> one matrix entry per model and runtime."""
    try:
        specs = parse_models(os.environ.get("MODELS", ""))
        runtimes = parse_runtimes(os.environ.get("RUNTIMES", ""))
    except ValueError as e:
        print(f"::error::{e}", file=sys.stderr)  # the message names the format, no input
        return 2
    matrix = [
        {"spec": str(s), "slug": s.slug, "runtime": r, "artifact": artifact_slug(s, r)}
        for s in specs
        for r in runtimes
    ]
    print(json.dumps(matrix))
    return 0


def cmd_download(args: argparse.Namespace, hub: Hub | None = None) -> int:
    spec = parse_spec(args.model)
    meta = download(spec, args.cache_dir, hub or default_hub(), bool(os.environ.get("HF_TOKEN")))
    target = args.cache_dir / spec.slug
    target.mkdir(parents=True, exist_ok=True)
    (target / "download.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    if meta["status"] == "skipped":
        print(f"::warning::{spec.model_id}: skipped, {meta['reason']}")
        return 0
    if meta["status"] != "ok":
        print(f"::error::{spec.model_id}: {meta['reason']}")
        return 1
    print(f"{spec.model_id}: revision {meta['resolved_revision']}, {len(meta['weights'])} weights")
    return 0


def score(
    sets_dir: Path,
    heuristics: bool,
    models: Sequence[dict[str, Any]] = (),
    detector_factory: Callable[[dict[str, Any]], Any] | None = None,
    heuristic_record: dict[str, Any] | None = None,
    log: Callable[[str], None] = print,
    runtime: str = TORCH_FP32,
    classifier_outcomes: list[tuple[dict[str, Any], list[Outcome]]] | None = None,
    work_dir: Path | None = None,
) -> tuple[dict[str, Any], list[Prompt], list[Outcome] | None]:
    """Run the detectors over the sets; return the summary, prompts and heuristic outcomes.

    Classifiers run on ``runtime``. Each one's (meta, per-prompt outcomes) is appended to
    ``classifier_outcomes`` when given (for ``--scores-out``).
    """
    manifest, prompts = load_sets(sets_dir)
    summary: dict[str, Any] = {
        "schema": SCHEMA,
        "sets": manifest,
        "environment": {
            "python": sys.version.split()[0],
            "cpu_count": os.cpu_count(),
            "packages": {
                d: package_version(d)
                for d in (
                    "torch",
                    "transformers",
                    "huggingface-hub",
                    "garak",
                    "onnx",
                    "onnxscript",
                    "onnxruntime",
                )
            },
        },
        "heuristics": None,
        "classifiers": [],
        "skipped": [],
    }
    heuristic_outcomes = None
    heuristic_blocked: list[bool] | None = None
    if heuristics:
        log(f"heuristics: {len(prompts)} prompts")
        heuristic_outcomes = run_detector(HeuristicDetector(), prompts)
        summary["heuristics"] = heuristic_summary(prompts, heuristic_outcomes)
        heuristic_blocked = [o.blocked for o in heuristic_outcomes]
    elif heuristic_record is not None:
        heuristic_blocked = outcomes_for(heuristic_record, manifest, prompts)
    for meta in models:
        if meta.get("status") != "ok":
            summary["skipped"].append({"model": meta.get("model_id"), "reason": meta.get("reason")})
            continue
        meta["runtime"] = runtime
        factory = detector_factory or (lambda m: load_detector(m, runtime, work_dir))
        detector = factory(meta)
        log(f"{meta['model_id']} [{runtime}]: {len(prompts)} prompts")
        outcomes = run_detector(detector, prompts)
        sample = single_prompt_sample(len(prompts))
        log(f"{meta['model_id']}: {len(sample)} prompts one at a time")
        single = [detector.evaluate(prompts[i].text) for i in sample]
        summary["classifiers"].append(
            classifier_summary(prompts, outcomes, meta, heuristic_blocked, single)
        )
        if classifier_outcomes is not None:
            classifier_outcomes.append((meta, outcomes))
    return summary, prompts, heuristic_outcomes


def cmd_run(args: argparse.Namespace) -> int:
    models = [
        json.loads((Path(d) / "download.json").read_text(encoding="utf-8"))
        for d in args.model_dir or []
    ]
    record = None
    if args.heuristic_outcomes:
        record = json.loads(Path(args.heuristic_outcomes).read_text(encoding="utf-8"))
    scored: list[tuple[dict[str, Any], list[Outcome]]] = []
    summary, prompts, heuristic_outcomes = score(
        args.sets,
        args.heuristics,
        models,
        None,
        record,
        runtime=args.runtime,
        classifier_outcomes=scored,
        work_dir=args.work_dir,
    )
    failures: list[str] = []
    warnings = [
        f"{m['set']} {m['family']}: {m['n']} prompts, ADR 0024 has {m['expected']}"
        for m in summary["sets"].get("count_mismatches", [])
        if m["set"] != TARGET
    ]
    if args.gate:
        failures, warnings = check_gate(summary["sets"], summary["heuristics"])
    summary["gate"] = {"checked": bool(args.gate), "failures": failures, "warnings": warnings}
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    if args.outcomes_out and heuristic_outcomes is not None:
        record = outcomes_record(summary["sets"], prompts, [o.blocked for o in heuristic_outcomes])
        Path(args.outcomes_out).write_text(json.dumps(record, separators=(",", ":")) + "\n")
    if args.scores_out and scored:
        if len(scored) != 1:
            raise ValueError("--scores-out takes one model per run")
        meta, outcomes = scored[0]
        rec = scores_record(summary["sets"], prompts, outcomes, spec_of(meta), args.runtime)
        Path(args.scores_out).write_text(json.dumps(rec, separators=(",", ":")) + "\n")
    table = render_markdown(summary)
    print(table)
    if args.markdown:
        with Path(args.markdown).open("a", encoding="utf-8") as fh:
            fh.write(table)
    for w in warnings:
        print(f"::warning::count differs from ADR 0024: {w}")
    for f in failures:
        print(f"::error::ADR 0024 regression: {f}")
    return 1 if failures else 0


def cmd_compare(args: argparse.Namespace) -> int:
    """Report-only: a model scored by one runtime only is noted, not an error."""
    classifiers, scores = collect_results(args.paths)
    comparisons = compare_runtimes(classifiers, scores)
    if args.out:
        args.out.write_text(json.dumps(comparisons, indent=2, sort_keys=True) + "\n")
    table = render_compare(comparisons)
    print(table)
    if args.markdown:
        with Path(args.markdown).open("a", encoding="utf-8") as fh:
            fh.write(table)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="MODELS x RUNTIMES env -> matrix").set_defaults(func=cmd_plan)
    dl = sub.add_parser("download", help="fetch a model at its revision")
    dl.add_argument("--model", required=True)
    dl.add_argument("--cache-dir", type=Path, required=True)
    dl.set_defaults(func=cmd_download)
    run = sub.add_parser("run", help="score the sets")
    run.add_argument("--sets", type=Path, required=True)
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--markdown", help="append the tables here (e.g. $GITHUB_STEP_SUMMARY)")
    run.add_argument("--heuristics", action="store_true", help="run the heuristic pass")
    run.add_argument("--outcomes-out", help="write per-prompt heuristic verdicts (no text)")
    run.add_argument("--heuristic-outcomes", help="the heuristics job's verdicts, for OR figures")
    run.add_argument("--model-dir", action="append", help="a download dir (repeatable)")
    run.add_argument("--gate", action="store_true", help="fail on an ADR 0024 regression")
    run.add_argument("--runtime", choices=RUNTIMES, default=TORCH_FP32, help="classifier runtime")
    run.add_argument("--scores-out", help="write the model's per-prompt scores (no text)")
    run.add_argument("--work-dir", type=Path, help="where onnx-int8 writes its ONNX files")
    run.set_defaults(func=cmd_run)
    cmp = sub.add_parser("compare", help="runtime agreement from summaries and score records")
    cmp.add_argument("paths", type=Path, nargs="+", help="summary/score files or directories")
    cmp.add_argument("--markdown", help="append the tables here (e.g. $GITHUB_STEP_SUMMARY)")
    cmp.add_argument("--out", type=Path, help="write the comparison as JSON")
    cmp.set_defaults(func=cmd_compare)
    args = parser.parse_args(argv)
    if args.command == "run" and args.gate and not args.heuristics:
        parser.error("--gate needs --heuristics")
    try:
        return int(args.func(args))
    except Exception as e:  # print only the type (security rule 4)
        print(f"::error::{args.command} failed: {type(e).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
