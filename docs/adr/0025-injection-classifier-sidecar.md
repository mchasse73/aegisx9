# 25. A model-based injection classifier in a loopback sidecar

- Status: Proposed
- Date: 2026-11-19
- Issues: #198; evaluation harness #209, runtimes #211 and #213; heuristics ADR 0024

## Context

The heuristic input guards (ADR 0022, ADR 0024) block 100% of the two garak families they were
written for and nothing in the false-positive corpora. On the hold-out families they were never
tuned against they block 26% (1,848 of 7,168). Indirect, latent injection is most of the gap:
FactSnippet, Translation, Whois and Resume plant instructions, or praise and fake verdicts, in
wording no keyword or structure rule anticipates. Resume is 0%. `injection.py` has always planned
a model-based classifier behind the same guard interface, with the heuristics kept as a cheap
pre-filter, and ADR 0024 made the hold-out set its acceptance bar.

The guard-evaluation harness (`redteam/eval/`, #209) now scores any Hugging Face sequence
classifier at a pinned revision against the target, hold-out and false-positive sets, in four
runtimes, and reports latency. What it has measured so far:

- **ProtectAI deberta-v3-base prompt-injection v2** (run 43078992659): hold-out 18.4% at 0.5
  (36.5% OR'd with the heuristics), target 60.5%, false positives 1.77% overall and 52% of the
  developer-data corpus. It catches direct injection and misses latent injection. **Rejected.**
- **Runtimes** (#213, run 43152667170, deberta-v3-base): ONNX fp32 matches torch with no decision
  flips, at a one-prompt p50 of 16 ms against torch's 136 ms on a 4-core hosted runner. Dynamic
  int8 lost 12 to 18 points on the target set and shrank the file only from 740 MB to 526 MB,
  because the embedding has to stay fp32.
- **Llama Prompt Guard 2, 86M and 22M**: not yet measured. Both jobs stopped at download because
  the repositories are gated. Prompt Guard 2 is trained for indirect injection, so it is the
  remaining candidate.

Owner decisions already taken, recorded here as decided:

1. Candidates are deberta v2 (rejected) and Prompt Guard 2 86M and 22M (to be measured).
2. The classifier runs as a **sidecar on loopback** in the gateway pod.
3. The model is **baked into the signed image, sha256-pinned, with no runtime download**.
4. **Fail closed**: if the classifier is down, slower than its timeout or errors, the request is
   refused, not passed.
5. **Runtime** (2026-11-19): ONNX fp32 by default. int8 only where that model's own guard-eval run
   is lossless against onnx-fp32: within 0.5 points on target and hold-out, and at most 1% of
   decisions flipped.
6. Target: at least 80% hold-out catch rate. Every guard reports hold-out next to target numbers,
   and the evaluation harness is the acceptance gate.

## Decision

### 1. Model selection criteria

The model is chosen from the Prompt Guard 2 run against these criteria, all from guard-eval
summaries of the runtime that will ship:

1. **Threshold first, on non-hold-out data only.** The threshold is the lowest value in the
   harness grid (0.5, 0.8, 0.9, 0.95, 0.99) at which the model, OR'd with the heuristics, produces
   no false positive on any ADR 0022/0024 corpus, the developer-data corpus included (#198's
   acceptance). The hold-out set is then read at that threshold and never used to move it,
   otherwise it stops being a hold-out.
2. **Hold-out at least 80%**, model OR heuristics, which is what ships. The model's own rate is
   reported next to it, per family.
3. **Target families stay at 100%** OR'd (the heuristics already give that); the model's own target
   rate is reported.
4. **Runtime**: onnx-fp32 has no decision flips against torch-fp32 at the chosen threshold. int8
   only under the owner's losslessness rule above.
5. **Latency**: the p95 of one full 512-token window on the sidecar's CPU allocation fits the
   budget in section 5.
6. **Packaging**: the fp32 export is under the harness's 1.8 GB limit, and the model's licence
   allows it to be distributed in the image (see Open items).
7. If both sizes pass, the 22M model wins: less memory, less latency, a smaller image.

If neither passes, the classifier is not enabled for blocking. The ADR stays Proposed and #198
stays open.

### 2. Topology

A container, `injection-classifier`, in the gateway pod beside `gateway`, `auth` and
`wif-broker`. It listens on `127.0.0.1` only (port 8788 by default) and declares no
`containerPort`. The gateway calls it once per request from LiteLLM's `async_pre_call_hook`,
after the heuristic input guards have passed every message. The classifier only scores input;
completions stay with the echo and redaction guards (ADR 0024).

**No authentication on the loopback listener.** Only containers in the same pod share its network
namespace, the pod never runs with `hostNetwork`, and every container in it is one of this
repository's signed images (Kyverno, ADR 0008). The sidecar holds no credential and has no side
effects: a caller gets a score for text it supplies, which anyone can compute offline from the
public model. The federation broker's loopback listener (ADR 0009) already relies on the same
boundary, and it attaches a credential to what it forwards. The sidecar refuses to start if its listen address is anything but `127.0.0.1`.

### 3. Interface

HTTP/1.1 with JSON bodies, served by the standard library's threaded HTTP server, as the broker
is. It needs no framework, and a JSON body is easy to bound, validate and test.

`POST /v1/score`, body at most 1 MiB (larger: 413 before parsing):

```json
{"request_id": "<32 hex>", "texts": ["<text 1>", "<text 2>"]}
```

`200` response:

```json
{
  "model": {"id": "<model id>", "revision": "<40 hex>", "onnx_sha256": "<64 hex>"},
  "results": [{"score": 0.0123, "windows": 1}, {"score": 0.9871, "windows": 3}],
  "windows_total": 4,
  "duration_ms": {"queue": 0.3, "tokenize": 1.1, "infer": 58.2}
}
```

Errors are `{"error": "<code>"}` and nothing else: `400 bad_request`, `413 body_too_large`,
`413 too_many_windows` (with `windows_total` and `max_windows`), `503 busy`, and
`500 <exception type name>`. No error repeats input text or an exception message.
`GET /healthz` answers 200 only after the startup checks in section 4 have passed.

**What the gateway sends.** One text per user, tool or function message of the current turn
(`current_turn` in `litellm_hooks.py`, ADR 0024): the messages after the last assistant answer.
Content-parts lists are sent as their joined text parts. System and assistant messages are the
operator's own text, as in ADR 0024, and earlier turns were scored when they were the current
turn. Texts are sent after the redaction guards, so secrets don't reach one more process. The
heuristics keep scanning every message of every request.

**Chunking is the sidecar's**, with the evaluation's scheme so that results match: the model's
tokenizer with overflow windows of `min(model_max_length, 512)` tokens, special tokens included,
a 64-token overlap, inference in batches of at most 8 windows (the harness uses 32; padding is
masked, and the parity check in section 7 proves the scores agree), and a text's score is its
highest window's injection probability. The windowing code moves to `src/aegisx9/classifier/`
and `redteam/eval/score.py` imports it, so the harness measures the code that ships. The sidecar
uses the `tokenizers` library rather than `transformers`; the harness checks that both produce
identical windows for every prompt in the sets.

**Decision rule (OR).** A request is refused if any heuristic guard blocks it (unchanged) **or**
the highest returned score is at or above the threshold. The classifier can add blocks but never
lift one.

**Configuration.** The threshold, the expected `onnx_sha256`, the mode, the timeout and the window
cap are chart values (`classifier.*`), rendered into the gateway's configuration. They are policy,
so changing them is a reviewed PR to an overlay, and prod changes go through the promotion gate.
The chart refuses to render `enabled` without `modelSha256`, or `enforce` without a threshold in
(0, 1). The gateway refuses a response whose `onnx_sha256` isn't the configured one, so a
threshold is always applied to the model it was chosen for.

**Timeout.** 3 s per request, measured by the gateway from sending to the parsed response, queue
time included. One attempt, no retry. The sidecar also drops work whose request has already
waited longer than the timeout.

**Modes**, `classifier.mode`:

- `report`: score, audit and log, never refuse because of the classifier. Classifier errors are
  logged and counted, and the request proceeds.
- `enforce`: refuse at or above the threshold, with the same `400 invalid_request_error`
  "request blocked by prompt_classifier (input guard)" the other guards use, so clients and the
  red-team suites read it the same way. **Fail closed**: a timeout, connection failure, non-200
  answer, malformed body, wrong result count, a score that isn't a finite number in [0, 1], or a
  model hash mismatch refuses the request with `503`
  "request blocked by prompt_classifier (unavailable)". 503 rather than 400, because the request
  isn't at fault and a retry may succeed; an outage is never counted as a pass. Too many windows
  refuses with `413`.

### 4. Packaging

**A separate image, `ghcr.io/mchasse73/aegisx9/classifier`**, built, scanned, signed and attested
by its own job in `release.yml`, as the workspace image already is.

- **Kyverno**: the verifyImages policy already matches `ghcr.io/mchasse73/aegisx9*` and the
  signer identity `release.yml@refs/heads/main`, so the new image is admitted and verified with no
  policy change.
- **Signing and SBOM**: keyless cosign and a Syft SBOM per image. The classifier's SBOM lists
  only what it runs (onnxruntime, tokenizers, numpy, the standard library), not LiteLLM; the
  gateway's SBOM doesn't grow a gigabyte of weights or onnxruntime. The model itself isn't a
  package Syft can see, so the image carries `/opt/classifier/model.json` and the release job
  attaches it as a second cosign attestation: model id, revision, label index, the sha256 of each
  safetensors file, of `model.onnx` and of `tokenizer.json`, the opset, and the onnx, onnxscript,
  onnxruntime and torch versions used.
- **Why not the gateway image**: weights and gateway code change on different schedules; the
  gateway rebuilds for every dependency fix and shouldn't re-export a model each time; a smaller
  runtime surface in the container that parses untrusted text; and the classifier can't import
  LiteLLM or the gateway's secrets code by accident. The cost is a second digest in each overlay.
  Enabling the sidecar and pinning both digests go in one PR (the 2026-10-22 rule).

**Build-time export**, in a multi-stage Dockerfile (`classifier/Dockerfile`):

1. A lock file, `classifier/model.lock`, names the model id, the full revision sha, the label, the
   sha256 of every safetensors file and of the tokenizer files, and the sha256 of the accepted
   `model.onnx`: the one the accepting guard-eval run recorded.
2. The export stage downloads exactly those files, with the Hugging Face token as a BuildKit
   secret mount in that stage only (never a layer, never a build argument), from a release
   environment limited to `main`. It verifies every sha256 before loading anything. Only
   safetensors are fetched, never pickled weights.
3. It exports with the harness's own export code and pinned versions (opset 20, dynamic batch and
   sequence axes), runs the harness's parity check against torch (tolerance 0.001), and refuses
   any operator outside the default ONNX domain.
4. The build fails if the export's sha256 differs from the lock, so the image always carries the
   file the evaluation measured. torch exists only in the export stage; the runtime stage copies
   `model.onnx`, `tokenizer.json` and `model.json` into `/opt/classifier`, root-owned and
   read-only.

**At startup** the sidecar hashes the files, compares them with `model.json`, and logs, as its
first line, the image version, model id, revision, label index, the ONNX and tokenizer sha256 and
the onnxruntime version. A mismatch stops it. It then scores two fixed built-in windows, one benign
and one injection, and refuses to become ready unless each lands on the expected side of the
threshold. `HF_HUB_OFFLINE=1` is set, and the image contains no download client for models.

**Size.** The fp32 ONNX file is about as large as the weights: 740 MB for deberta-v3-base. Prompt
Guard 2 86M has a deberta-base-sized encoder with a 250k-token multilingual embedding, which
puts its fp32 file at roughly 1.1 GB, larger than deberta-v3-base, not smaller. The 22M model
should be around 0.3 GB. Both figures come from the eval summary's `bytes` before this ADR is
accepted. The runtime layers add about 100 MB. The first pull on a node costs that much once;
the image is pulled by digest and cached.

### 5. Resources and latency

Defaults for the 86M model, revised from its measured resident memory before enforcing:

| | request | limit |
|---|---|---|
| CPU | 1 | 2 |
| memory | 2 GiB | 3 GiB |

The 22M model is expected to fit in 1 GiB. onnxruntime runs one inference at a time with
`intra_op_num_threads` equal to the CPU limit and one inter-op thread. A bounded queue holds 8
waiting requests; the next one gets `503 busy`, which in `enforce` mode refuses the request. A
`startupProbe` allows for hashing and loading the model; readiness is `/healthz` (exec, as for the
broker, because the listener is on loopback); liveness is a TCP connect. Security context is the
chart's shared one: non-root UID 10001, read-only root filesystem, no privilege escalation, every
capability dropped, RuntimeDefault seccomp. No Secret, no `envFrom`, no service-account token and
no volume other than a small `emptyDir` for `/tmp`.

**Latency budget.** Added latency is about windows × per-window time, plus queueing. deberta-v3-base
measured 16 ms p50 for one typical prompt on 4 hosted cores; a full 512-token window on 2 cores
costs more and is measured on the target CPU before enforcing. The cap is **64 windows per
request** (about 28,000 tokens of current-turn input). It is set so that 64 × the p99 of a full
window stays under the 3 s timeout. If the chosen model can't meet that, the cap is lowered, not
the timeout raised. The goal is a p95 added latency under 150 ms for requests of up to 4 windows.

**Long inputs are refused, never partly scored.** Above the cap the sidecar answers
`413 too_many_windows` after tokenizing, which is cheap, and before any inference. In `enforce`
mode the gateway refuses the request with 413. Scoring only the first or last windows would let an
attacker pad the payload into the unscored middle. Because only the current turn is scored, a long
conversation doesn't hit the cap; one very large pasted document or tool result can. Report mode
records the windows-per-request distribution, so the cap is calibrated from real traffic before it
can refuse anything.

### 6. Logging and audit

No prompt text, window text or token id is logged, by the sidecar or the gateway. The sidecar's
access log has method, path, status, durations (queue, tokenize, infer), window count and the
request id. The gateway writes one audit event for the classifier stage (schema 1.1 adds an
optional `classifier` block): mode, outcome (`allow`, `block`, `would_block`, `too_large`,
`error:<type>`), the highest score rounded to three decimals, window count, duration and the first
12 hex digits of the model's ONNX sha256. The audit event still has no field that can hold
content, and its credential re-scan still applies.

### 7. Rollout

1. The image, chart support (`classifier.enabled: false`) and the `src/aegisx9/classifier/`
   client and server ship first, with unit tests and a CI boot test that starts the sidecar from
   the built image and scores the two built-in windows.
2. **Acceptance run on the image.** guard-eval gains a `sidecar` runtime that starts the built
   classifier image and scores the sets through `/v1/score`. It must match that model's onnx-fp32
   run: identical windows, no decision flips at the chosen threshold, and the criteria in section 1.
3. **Staging, `report` mode**, in one PR that pins both digests and enables the sidecar: at least
   7 days and 1,000 scored requests. Read the would-block count per team, the windows-per-request
   distribution, p50/p95/p99 added latency, and the error, busy and timeout counts. Any would-block
   from the developers team is followed up with the developer: the owner of a request can say
   whether it was an attack; the gateway can't, since it keeps no text.
4. **Red-team gate.** The staging garak suite adds the hold-out probe classes (FactSnippet Eiffel
   and Legal, Translation Fr and Zh, Whois, WhoisSnippet, Resume) as a family that is report-only
   while the classifier reports. Existing floors stay as they are (`thresholds.json` never lowers
   one without an ADR).
5. **`enforce`** in staging, in its own PR, once steps 2 and 3 hold: the new family's floor
   becomes **0.80**, and every existing family must still pass its floor (promptinject 0.95,
   latentinjection 0.85, and the rest unchanged). The promptfoo benign suite must still pass.
6. Prod follows through the promotion gate, `report` first.

### 8. Scale/HA

The sidecar is a pure function of the request: no cache, no state between requests, nothing shared
between replicas. It scales with the gateway Deployment, one per pod, and a replica's sidecar
failing affects only that pod, which leaves the Service once it isn't ready. Each pod's memory
grows by the model, so rolling updates (`maxSurge: 1`) need room for one more pod of that size,
and a horizontal autoscaler, when one is added, scales on CPU, which the classifier now dominates.
A shared inference service or GPU pool for large clients would be a later, separate decision; the
HTTP interface would carry over unchanged, over mTLS (ADR 0017).

**The sidecar makes no outbound calls.** It has no HTTP client, sets `HF_HUB_OFFLINE`, and needs
nothing beyond its own image. NetworkPolicy applies to the whole pod, so it can't restrict this one
container; the code and the read-only image are the control, and the CI boot test runs it with no
network.

### 9. Assume breach

- **Detect.**
  - Startup hash checks and the built-in self-test catch a swapped or corrupted model file.
  - Every response carries the ONNX sha256 and the gateway rejects any other.
  - The audit log carries every score, so a classifier that suddenly never blocks, or blocks
    everything, shows as a change in the score distribution and the block rate per principal.
  - The nightly red-team gate, with the hold-out family, measures the deployed system end to end.
- **Contain.**
  - The classifier can only add blocks. A compromised or backdoored model at worst returns the
    gateway to the heuristics-only posture of ADR 0024, or refuses traffic.
  - The container holds no credential, no Secret and no service-account token. It can't change
    a request, only score it. Root filesystem is read-only, it runs unprivileged, and its image
    is digest-pinned and signature-verified at admission.
  - The weights come from a pinned revision as safetensors only, re-exported by our own build
    with default-domain operators only, never a third party's ONNX file.
  - Residual risk: the sidecar sees redacted current-turn text and shares the pod's egress, so a
    compromised image could try to send it out. The supply-chain controls are what prevent it.
  - Inputs crafted to be slow are bounded by the body limit, the window cap, the queue and the
    timeout, and LiteLLM's per-key rate limits and budgets bound any one caller.
- **Recover.** One overlay PR sets `classifier.mode: report` (or `enabled: false`) or pins the
  previous digest, and Argo CD rolls it out. The lock file rebuilds an identical model, and the
  harness re-measures it before re-enabling.

## Alternatives considered

1. **In-process inference in the LiteLLM container.** Rejected. Scoring inside the async hook
   would stall the event loop unless moved to threads, every LiteLLM worker would load its own copy
   of the model, a crash or memory spike in the classifier would take the gateway down with it, and
   the gateway image and SBOM would carry onnxruntime and the weights.
2. **A remote inference service**, shared in the cluster or hosted by a vendor. Rejected for now.
   Prompt text would leave the pod, the call would need mTLS and its own identity, a shared service
   becomes the single hub the design rules avoid, and a vendor API means prompt egress and a new
   credential. Its strength is pooled or GPU capacity for large clients, which the HTTP interface
   leaves open.
3. **int8 by default.** Rejected by the owner's runtime decision: on deberta-v3-base it lost 12 to
   18 points and saved under a third of the file size. It stays available per model under the
   losslessness rule.
4. **torch in the sidecar.** Rejected: about 8 times slower than onnx-fp32 on the same weights, and
   a much larger image.
5. **Heuristics only.** Rejected: 26% of the hold-out, and Resume at 0%, which is praise and fake
   verdicts rather than instructions. No keyword rule catches that without blocking ordinary
   documents.
6. **The classifier in the gateway image**, started with another command, as the auth sidecar
   and broker are. Rejected for the reasons in section 4.

## Consequences

- Indirect injection is scored by a model trained for it, under criteria and an acceptance gate
  fixed before the measurement, with the hold-out kept clean.
- Each gateway pod needs roughly 1 to 2 more CPUs and 1 to 3 GiB more memory, depending on the
  model, and its image pull grows by the model size.
- Every input request waits for the classifier: tens of milliseconds for typical prompts, up to
  the timeout for the largest allowed.
- Fail closed turns a classifier outage into refused requests (503) for that pod's callers. A
  current turn over the window cap is refused (413), which can affect agents that paste very
  large documents until the cap is calibrated.
- The release job needs Hugging Face access for gated models, from a `main`-only environment.
- The audit schema goes to 1.1, with an optional block.
- Streaming requests are covered, because scoring happens before the call.

## Open items

- **The model**: from the Prompt Guard 2 run (86M and 22M) against section 1. To be filled in,
  with its revision, weights sha256, ONNX sha256, size and resident memory.
- **The threshold**: chosen by the rule in section 1 from the same run.
- **The licence**: Prompt Guard 2 is distributed under Meta's Llama licence. Publishing the
  classifier image publicly redistributes the weights. Its conditions (shipping the licence text
  and the attribution notice, the acceptable-use policy) must be met, or the classifier image is
  made a private package under the same GHCR prefix. That keeps the Kyverno policy unchanged and
  uses the existing pull secret.
- **Reproducible export**: the build relies on the export reproducing the lock's ONNX sha256 with
  pinned versions. If it doesn't, the ONNX file is exported once by a dedicated workflow and
  published as a signed OCI artifact that the image build pulls by digest.
- **CPU calibration**: per-window latency on the cluster's nodes, which sets the window cap and the
  CPU limit.
