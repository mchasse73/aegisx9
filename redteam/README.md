# Red-team suites

Run by `.github/workflows/redteam-staging.yml` against the **staging** gateway only, on
ephemeral in-cluster ARC runners: nightly, on manual dispatch, and on pushes to `main` that
change the staging overlay or these suites. Never on pull requests (see `SECURITY.md`).
It first waits until staging runs the image digest pinned in `deploy/overlays/staging/`
(`wait_for_rollout.py`, Kubernetes API with the runner pod's service-account token).

**Credential:** none is stored. `get_token.py` exchanges the job's own GitHub OIDC token for
an identity-provider machine-identity token of at most 15 minutes. The auth sidecar turns that
into a key that expires with it. Each suite gets a fresh token and is capped at 12 minutes.
Only a guard block counts as "blocked"; any other gateway error fails the test.
`redteam-freshness.yml` fails if no run has succeeded on `main` for 48 hours.

| Suite | What it checks | Gate |
|-------|----------------|------|
| `promptfoo/` | Curated baseline: direct and indirect injection, jailbreak personas, system-prompt leakage, secret/PII echo, and benign prompts that must not be blocked | Any failed assertion fails the job |
| `garak/` | Broad probe families (promptinject, DAN, encoding, latent injection, leak replay, markdown exfiltration) | `gate.py` fails if a family's pass rate drops below `thresholds.json` |

Planted secrets are generated at runtime (`promptfoo/generators/planted.js`); no
credential-shaped literal is stored in this repository.

## Guard evaluation (`eval/`, #198)

`.github/workflows/guard-eval.yml` scores the input guards, and optionally Hugging Face
prompt-injection classifiers, against ADR 0024's sets, on GitHub-hosted runners:

- the target families (promptinject goal hijacking, 525 prompts; LatentInjectionReportFull, 648);
- the hold-out (7,168 prompts: FactSnippet Eiffel and Legal, Translation Fr and Zh, Whois,
  WhoisSnippet, Resume, promptinject prompt-leaking, the promptfoo injection suite);
- the false-positive corpora (dictionary words, random sentences, order numbers, developer
  data, chat transcripts, Markdown, code, prompt-engineering requests, emails, the benign suite).

`build_sets.py` reads the attack prompts from garak 0.17.1's own probe classes, installed in a
tool venv inside the workflow only. It generates the false-positive corpora from fixed seeds and
the wamerican word list, whose sha256 is pinned. `score.py` writes a JSON summary (artifact) and
the tables (job summary). Neither prints prompt text. The family and corpus definitions live in
`eval/common.py`.

**On a pull request** that touches the guards, the proxy hook, the pipeline, the promptfoo
attack files or `eval/`: heuristics only, no environment, no secrets. The job fails if:

- a target family is blocked below 100%, or its prompt count differs from ADR 0024's;
- any false-positive corpus is hit;
- the word list's sha256 differs from the pin (the false-positive results are then invalid).

A hold-out family whose count differs is a warning, shown in the job summary; it doesn't fail.

**Manual dispatch** (Actions → guard-eval → Run workflow), input `models`: newline- or
comma-separated `model_id@revision:label`, where `label` is the injection class's name or
index. A malformed entry fails the plan job. Use a full commit sha as the revision. The summary
records the resolved sha and the sha256 of every top-level `.safetensors` file. Weights in
subfolders and pickled `.bin` files are never fetched. For example:

```
protectai/deberta-v3-base-prompt-injection-v2@90c9989b1a342275dd0d1a95aad283c04e075671:INJECTION
meta-llama/Llama-Prompt-Guard-2-86M@a8ded8e697ce7c355e395a0df51f94adb4a2fd27:1
meta-llama/Llama-Prompt-Guard-2-22M@11614a155199674a0a95e6602d6ab0417b790ed0:1
```

The heuristics run once per dispatch. Their job uploads per-prompt verdicts (keyed by
set/family/index, no text), and each model job reuses them for the "OR heuristics" figures.
Each model runs in its own job in the `guard-eval` environment (main only; Terraform in
`infra/modules/aegisx9-env`). Its `HF_TOKEN` environment secret reaches only the download step.

- With no token and a 401/403 answer (a gated model such as Prompt Guard), the model is skipped
  with a warning.
- Any other download failure fails the job, naming the exception type and HTTP status:
  - a bad revision;
  - a token without access (accept the model's licence for the token's account);
  - 429 or 5xx.

Latency is reported two ways:

- batched: groups of 32 prompts, tokenized in one call into the tokenizer's own overflow
  windows and scored together, with each group's time divided by its prompts;
- one prompt at a time: a fixed sample of 200 prompts, which is what a gateway sidecar would
  see.

Model results are report-only, and a word list that isn't pinned marks their false-positive rows
"unpinned corpus". Empty `models` runs the heuristics alone.

**Runtimes** (#211, #213), input `runtimes` (default `torch-fp32,onnx-fp32,onnx-int8`; an
unknown value fails the plan job). Each model × runtime is its own job, with up to 350 minutes:

- `torch-fp32`: the published weights in torch, as before.
- `onnx-fp32` and `onnx-int8` share one export path. They take a Hugging Face sequence
  classifier whose weights fit a single-file ONNX export. Protobuf limits that file to 2 GB, so
  the job fails with an error, before exporting, when the weights would take more than 1.8 GB in
  fp32 (counted from the safetensors headers). The job exports the downloaded weights offline to
  ONNX with torch's default exporter at opset 20, with dynamic batch and sequence axes and inputs
  `input_ids` and `attention_mask`. It then checks the fp32 export against torch on four fixed
  windows and fails if any probability differs by more than 0.001 or isn't finite. The check
  windows are no longer than the model's own maximum length. Chunking, batching, thresholds and
  latency are the same code as torch's.
  - `onnx-fp32` scores the export unquantised with an onnxruntime CPU session: the accuracy and
    latency baseline of ONNX itself. Its `onnx.quantization` says `{"method": "none", "applied":
    false}`, and `onnx.file`, `sha256` and `bytes` are the fp32 export's.
  - `onnx-int8` is the sidecar's candidate runtime (#198). It quantises the export with
    onnxruntime's `quantize_dynamic`, every setting explicit: QInt8 weights, per channel (each
    weight's output axis), `reduce_range` off, `op_types_to_quantize` `MatMul` and `Gemm`, and
    `MatMulConstBOnly` (only MatMuls with a constant weight; attention's activation × activation
    MatMuls stay fp32). The embedding Gather isn't quantised. In dynamic mode onnxruntime
    rewrites each Gemm as MatMul + Add first, so Gemm layers (pooler, classifier head) are
    quantised as MatMuls. A MatMul whose weight reaches it through a Transpose isn't
    constant-weight to the quantiser and stays fp32. The defaults (per-tensor, every supported op,
    Gather included) collapsed deberta-v3-base's scores (#213): at ≥0.9 they blocked no target
    prompt, where fp32 blocked 58%. `onnx.ops` counts the tracked node types before and after
    quantising, so the summary shows what changed. onnxruntime's docs say 7-bit weights
    (`reduce_range`) may help on CPUs without VNNI, especially per channel, so each summary also
    records `environment.cpu_vnni`.

  The summary records:
  - the scored and fp32 files' sha256 and sizes;
  - the opset and the onnx, onnxscript and onnxruntime versions;
  - the quantisation settings (or that none were applied);
  - the check's result and tolerance;
  - the source weights' sha256.

  The pinned versions are in the workflow's `env`. Without `--work-dir`, the ONNX files sit in a
  temporary directory that is removed when scoring ends. Each model gets its own subdirectory
  (its spec's slug and resolved revision).

Each model job also uploads its per-prompt scores, keyed by set, family and index, with no text.
A final report-only job (`score.py compare`) shows each model's runtimes side by side, with
torch-fp32 as the baseline for both ONNX runtimes:

- for each threshold and set: both block rates, the delta in percentage points, and the share
  of prompts whose block decision differs;
- the largest and mean score difference;
- the one-prompt-at-a-time latency.

Runs pair only when they scored the same source weights (resolved revision and every weights
sha256); otherwise the model shows "not comparable: weights differ". Several runs of one model
and runtime are ambiguous, so that model shows "not comparable: duplicate runs". A file or score record
that can't be used is skipped with a note naming the error type, and the rest of the report
still renders. Each summary records the runner's CPU model (`environment.cpu_model`), and the
latency rows carry a caveat when the two runs used different CPUs.

Summaries are schema 3: each classifier carries `runtime`, and a schema 2 summary is read as
torch-fp32. Schema 3 computes the softmax in float64 from torch's fp32 logits, where schema 2
used a float32 softmax. Scores can differ by about 1e-7, so a comparison against a schema 2
baseline can flip a prompt that sits exactly on a threshold.

Locally (no models): `python -m redteam.eval.build_sets --out /tmp/sets` needs garak 0.17.1 in
the interpreter; then `python -m redteam.eval.score run --sets /tmp/sets --heuristics --gate --out summary.json`.
