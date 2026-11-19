# 25. A model-based injection classifier in a loopback sidecar

- Status: Accepted
- Date: 2026-11-19 (owner decision)
- Revised 2026-11-19 after review (PR #223: 13 findings)
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
   refused, not passed. This applies in `enforce` mode. In `report` mode, which never blocks, an
   outage is logged and the request proceeds (owner decision, 2026-11-19).
5. **Runtime** (2026-11-19): ONNX fp32 by default. int8 only where that model's own guard-eval run
   is lossless against onnx-fp32: within 0.5 points on target and hold-out, and at most 1% of
   decisions flipped.
6. Target: at least 80% hold-out catch rate. Every guard reports hold-out next to target numbers,
   and the evaluation harness is the acceptance gate.

## Decision

### 1. Model selection criteria

The model is chosen from the Prompt Guard 2 run against these criteria, all from guard-eval
summaries of the runtime that will ship.

**Preprocessing parity.** Threshold selection and both acceptance runs (the guard-eval run and the
image's `sidecar` runtime, section 7) score exactly what the gateway would send: each prompt is
wrapped as a request and passed through `AegisGuard.pre_call` on `default_pipeline()` (ADR 0024).
A prompt the heuristics block counts as blocked, as today. Every other prompt is scored as its
post-redaction text, extracted by the same function the proxy hook uses,
`aegisx9.classifier.texts.request_texts()`, and windowed by `aegisx9.classifier.windows`. The
harness imports both; it never scores raw prompt text for these numbers.

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

If neither passes, the classifier is not enabled for blocking and #198 stays open.

### 2. Topology

A container, `injection-classifier`, in the gateway pod beside `gateway`, `auth` and
`wif-broker`. It listens on `127.0.0.1` only (port 8788 by default) and declares no
`containerPort`. The gateway calls it once per request from LiteLLM's `async_pre_call_hook`,
after the heuristic input guards have passed every message. The classifier only scores input;
completions stay with the echo and redaction guards (ADR 0024).

**No authentication on the classifier's loopback listener.** Only containers in the same pod share
its network namespace, the pod never runs with `hostNetwork`, and every container in it is one of
this repository's signed images (Kyverno, ADR 0008). The sidecar holds no credential and has no
side effects: a caller gets a score for text it supplies, which anyone can compute offline from the
public model. The sidecar refuses to start if its listen address is anything but `127.0.0.1`.

**The other loopback listeners authenticate their callers**, because the classifier, which parses
untrusted text, now shares their network namespace:

- LiteLLM on loopback requires the master key or a virtual key; the auth sidecar requires a JWT or
  passes the bearer on to LiteLLM's key checks (ADR 0010). Both stay as they are.
- **The federation broker (ADR 0009) must require a per-pod token**, because it attaches the
  provider credential to whatever it forwards. An init container writes a random token
  (`secrets.token_urlsafe(32)`) at pod start into an `emptyDir` with `medium: Memory`. Only the
  `gateway` and `wif-broker` containers mount it, never `injection-classifier`. The gateway sends it
  in a header on every call to the broker, and the broker refuses any request without the matching
  token (constant-time comparison; the token is never logged). `shareProcessNamespace` stays off,
  so the classifier can't read it from another container's process. This changes ADR 0009 and is a
  prerequisite (see below).

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
`413 too_many_windows` (with `windows_total` and `max_windows`), `503 busy`, `503 not_ready`, and
`500 <exception type name>`. No error repeats input text or an exception message.
`GET /healthz` answers 200 only after the startup checks in section 4 have passed.

**What the gateway sends.** Every untrusted message of the request, in every turn: one text per
user, tool or function message, whatever its position. The gateway keeps no session, so it can't
know that an earlier turn was scored before, and a caller can put anything in the history it sends.
Content-parts lists are sent as their joined text parts. System and assistant messages are the
operator's own text, as in ADR 0024, and aren't scored. Texts are taken after the redaction guards,
so secrets don't reach one more process. `request_texts()` (section 1) does the extraction, for the
hook and the harness alike.

**Verdict cache.** Scoring every turn of a long conversation on every request would rescore the
same messages again and again, so the gateway keeps a **per-pod, bounded LRU cache** of scores:

- key: (model ONNX sha256, threshold, sha256 of the redacted message text);
- value: that message's score and window count, never its text;
- bounded by `classifier.cache.maxEntries` (default 50,000, a few MB) and a TTL,
  `classifier.cache.ttlSeconds` (default 3,600);
- only successful scores are cached, never errors, `busy` or too-large answers.

Only the uncached messages go to the sidecar, and the window cap and timeout apply to that
remainder. The cache is purely an optimisation: an empty cache (a new pod, another replica, an
eviction) costs latency and never changes a verdict. A cached entry can only repeat the score that
message's own text produced, so it can't be used to whitelist different content.

**Chunking is the sidecar's**, with the evaluation's scheme so that results match: the model's
tokenizer with overflow windows of `min(model_max_length, 512)` tokens, special tokens included,
a 64-token overlap, inference in batches of at most 8 windows (the harness uses 32; padding is
masked, and the sidecar parity check in section 7 proves the scores agree), and a text's score is
its highest window's injection probability. That code is `aegisx9.classifier.windows`, which
`redteam/eval/score.py` imports, so the harness measures the code that ships. The sidecar uses the
`tokenizers` library rather than `transformers`; the harness checks that both produce identical
windows for every prompt in the sets.

**Decision rule (OR).** A request is refused if any heuristic guard blocks it (unchanged) **or**
the highest score over its messages, cached or fresh, is at or above the threshold. The classifier
can add blocks but never lift one.

**Configuration.** The threshold, the expected `onnx_sha256`, the mode, the timeout, the window cap
and the cache bounds are chart values (`classifier.*`). They are policy, so changing them is a
reviewed PR to an overlay, and prod changes go through the promotion gate.

- **The threshold is required whenever the classifier is enabled, in `report` mode too**: report
  mode logs would-blocks against it. The chart refuses to render `enabled` without `modelSha256`
  or without a threshold in (0, 1).
- The chart passes the same threshold value to both containers: the gateway applies it, and the
  sidecar uses it for its startup self-test (section 4).
- The gateway refuses a response whose `onnx_sha256` isn't the configured one, so a threshold is
  always applied to the model it was chosen for.

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
  model hash mismatch refuses the request with `503` "prompt_classifier unavailable". 503 rather
  than 400, because the request isn't at fault and a retry may succeed. The message deliberately
  **doesn't contain the `request blocked by` marker**, so no client or suite can read an outage as
  a block, and an outage is never counted as a pass. Both size limits, `body_too_large` and
  `too_many_windows`, refuse the request with `413` "prompt_classifier input too large", also
  without the marker.

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
  attaches it as a second cosign attestation: model id, revision, label index, the selected runtime
  and its quantisation settings, the sha256 of every locked source file and of the scored ONNX
  file, the opset, and the onnx, onnxscript, onnxruntime and torch versions used.
- **Why not the gateway image**: weights and gateway code change on different schedules; the
  gateway rebuilds for every dependency fix and shouldn't re-export a model each time; a smaller
  runtime surface in the container that parses untrusted text; and the classifier can't import
  LiteLLM or the gateway's secrets code by accident. The cost is a second digest in each overlay,
  which the rollout tooling must learn first (prerequisites). Enabling the sidecar and pinning
  both digests go in one PR (the 2026-10-22 rule).

**Build-time export**, in a multi-stage Dockerfile (`classifier/Dockerfile`):

1. A lock file, `classifier/model.lock`, names:
   - the model id, the full revision sha and the label;
   - the sha256 of every file `from_pretrained` reads for the model and its tokenizer:
     `config.json`, every safetensors file, `tokenizer.json`, `tokenizer_config.json`,
     `special_tokens_map.json` and any other tokenizer file the revision ships (the export fails
     if it would read a file the lock doesn't name);
   - the **selected runtime** (`onnx-fp32`, or `onnx-int8` / `onnx-int8-rr` only under the
     owner's rule) and, for int8, its quantisation settings exactly as the harness records them;
   - the sha256 of the fp32 export and of the **scored file**: the file the accepting guard-eval
     run scored (the fp32 export itself, or its int8 file).
2. The export stage downloads exactly the locked files, with the Hugging Face token as a BuildKit
   secret mount in that stage only (never a layer, never a build argument), from a release
   environment limited to `main`. It verifies every sha256 before loading anything. Only
   safetensors are fetched, never pickled weights.
3. It exports fp32 with the harness's own export code and pinned versions (opset 20, dynamic batch
   and sequence axes), runs the harness's parity check against torch (tolerance 0.001), and
   refuses any operator outside the default ONNX domain. It checks the fp32 export's sha256
   against the lock. If the lock selects int8, it then quantises with the locked settings through
   the harness's own quantisation code.
4. The build fails unless the sha256 of the file it will ship equals the lock's scored-file hash,
   so the image always carries the artifact the evaluation measured. torch exists only in the
   export stage; the runtime stage copies `model.onnx` (the scored file), the tokenizer files,
   `config.json` and `model.json` into `/opt/classifier`, root-owned and read-only.

**At startup** the sidecar hashes the files, compares them with `model.json`, and logs, as its
first line, the image version, model id, revision, label index, runtime, the ONNX and tokenizer
sha256 and the onnxruntime version. It then scores two fixed built-in windows, one benign and one
injection, which must land on the expected sides of the configured threshold. What a failed check
does depends on the mode (section 5). `HF_HUB_OFFLINE=1` is set, and the image contains no
download client for models.

**Size.** The fp32 ONNX file is about as large as the weights: 740 MB for deberta-v3-base. Prompt
Guard 2 86M has a deberta-base-sized encoder with a 250k-token multilingual embedding, which
puts its fp32 file at roughly 1.1 GB, larger than deberta-v3-base, not smaller. The 22M model
should be around 0.3 GB. Both figures are confirmed from the eval summary's `bytes`. The runtime
layers add about 100 MB. The first pull on a node costs that much once; the image is pulled by
digest and cached.

### 5. Resources and latency

Defaults for the 86M model, revised from its measured resident memory before enforcing:

| | request | limit |
|---|---|---|
| CPU | 1 | 2 |
| memory | 2 GiB | 3 GiB |

The 22M model is expected to fit in 1 CPU and 1 GiB (limits). onnxruntime runs one inference at a
time with `intra_op_num_threads` equal to the CPU limit and one inter-op thread. A bounded queue
holds 8 waiting requests; the next one gets `503 busy`, which in `enforce` mode refuses the
request. Security context is the chart's shared one: non-root UID 10001, read-only root
filesystem, no privilege escalation, every capability dropped, RuntimeDefault seccomp. No Secret,
no `envFrom`, no service-account token, not the broker's token volume, and no volume other than a
small `emptyDir` for `/tmp`.

**Namespace quota.** CI's quota-fit step (`.github/workflows/ci.yml`, `check_quota_fit.py`) holds
the rendered staging overlay to staging's quota of limits.cpu 3, limits.memory 3Gi and 5 pods at
the rollout peak (old pod, surge pod and the chart's jobs). Today's pod limits are 1.3 CPU and
1.25 GiB (gateway 800m/1Gi, auth 400m/128Mi, broker 100m/128Mi), and the peak is already 3.0 of
3 CPU and 2.75 of 3 GiB. With the classifier the pod's limits become:

| model | pod limits | rollout peak (2 pods + jobs) |
|---|---|---|
| 86M (2 CPU / 3 GiB) | 3.3 CPU / 4.25 GiB | 7.0 CPU / 8.75 GiB |
| 22M (1 CPU / 1 GiB) | 2.3 CPU / 2.25 GiB | 5.0 CPU / 4.75 GiB |

So even report mode needs a larger staging quota: at least limits.cpu 7 and limits.memory 9Gi for
the 86M model, or 5 and 5Gi for the 22M, from an ops-central `k3s-change` build job, with the
quota-fit step's arguments raised to match in the same PR that enables the sidecar.

**Probes and the modes.** The chart switches the classifier's probes on `classifier.mode`:

- **`report`**: no readiness probe, so the classifier never takes the pod out of the Service. It
  has a `startupProbe` (TCP connect, with room for hashing and loading the model) and a TCP
  liveness probe; a hung process is restarted. A failed startup check (hashes, self-test) doesn't
  exit the process: it logs the failure, and `/v1/score` answers `503 not_ready`, which the gateway
  logs as an error and ignores. Only an actual crash makes the container briefly not running,
  which Kubernetes counts against pod readiness during the restart.
- **`enforce`**: a readiness probe on `/healthz` (exec, as for the broker, because the listener is
  on loopback) gates the pod, and a failed startup check exits the process. A pod whose classifier
  can't score takes no traffic.

**Latency budget.** Added latency is about uncached windows × per-window time, plus queueing.
deberta-v3-base measured 16 ms p50 for one typical prompt on 4 hosted cores; a full 512-token
window on 2 cores costs more and is measured on the target CPU before enforcing. The cap is
**64 windows per sidecar call** (about 28,000 tokens of uncached input). It is set so that 64 × the
p99 of a full window stays under the 3 s timeout. If the chosen model can't meet that, the cap is
lowered, not the timeout raised. The goal is a p95 added latency under 150 ms for requests of up
to 4 uncached windows. On a warm cache, a conversation's later requests send only the new
messages. On a cold cache (a new pod, a rollout, or a request landing on another replica) the
whole history is uncached.

**Long inputs are refused, never partly scored.** Above the cap the sidecar answers
`413 too_many_windows` after tokenizing, which is cheap, and before any inference. In `enforce`
mode the gateway refuses the request with 413. Scoring only the first or last windows would let an
attacker pad the payload into the unscored middle. One very large pasted document or tool result
can hit the cap, and so can a long conversation on a cold cache. Report mode records the
windows-per-call distribution and the cache hit rate, so the cap and the cache bounds are
calibrated from real traffic before anything can be refused.

### 6. Logging and audit

No prompt text, window text or token id is logged, by the sidecar or the gateway. The sidecar's
access log has method, path, status, durations (queue, tokenize, infer), window count and the
request id. The gateway writes one audit event for the classifier stage (schema 1.1 adds an
optional `classifier` block): mode, outcome (`allow`, `block`, `would_block`, `too_large`,
`error:<type>`), the highest score rounded to three decimals, scored and cached message counts,
window count, duration and the first 12 hex digits of the model's ONNX sha256. The audit event
still has no field that can hold content, and its credential re-scan still applies.

### 7. Rollout

1. The image, chart support (`classifier.enabled: false`) and the `src/aegisx9/classifier/`
   client and server ship first, with unit tests and a CI boot test that starts the sidecar from
   the built image and scores the two built-in windows.
2. **Acceptance run on the image.** guard-eval gains a `sidecar` runtime that starts the built
   classifier image and scores the sets through `/v1/score`, with the preprocessing of section 1.
   It must match the guard-eval run of the **selected runtime** (the one the lock names) exactly:
   identical windows, no decision flips at the chosen threshold or any grid threshold, and no
   score differing by more than 1e-4. When int8 is selected, the owner's losslessness rule
   (int8 against onnx-fp32: within 0.5 points on target and hold-out, at most 1% of decisions
   flipped) applies separately, between those two guard-eval runs. The criteria in section 1 are
   read from the same runs.
3. **Staging, `report` mode**, once the prerequisites below are done, in one PR that pins both
   digests and enables the sidecar: at least 7 days and 1,000 scored requests. Read the
   would-block count per team, the windows-per-call distribution, the cache hit rate,
   p50/p95/p99 added latency, and the error, busy and timeout counts. Any would-block from the
   developers team is followed up with the developer: the owner of a request can say whether it
   was an attack; the gateway can't, since it keeps no text.
4. **Red-team gate.** The staging garak suite adds the hold-out probe classes (FactSnippet Eiffel
   and Legal, Translation Fr and Zh, Whois, WhoisSnippet, Resume) as their own family,
   `latentinjection_holdout`, report-only while the classifier reports. They live in garak's
   `latentinjection` module with the gated `LatentInjectionReport`, so the family comes from an
   explicit class-to-family map, not the module name (prerequisite 4). The existing
   `latentinjection` family (LatentInjectionReport) keeps its 0.85 floor, and no floor is lowered
   (`thresholds.json` never lowers one without an ADR).
5. **`enforce`** in staging, in its own PR, once steps 2 and 3 hold: `latentinjection_holdout`'s
   floor becomes **0.80**, independently of the other families, and every existing family must
   still pass its floor (promptinject 0.95, latentinjection 0.85, and the rest unchanged). The
   promptfoo benign suite must still pass.
6. Prod follows through the promotion gate, `report` first.

### Prerequisites before report mode

1. **Broker authentication.** The federation broker requires the per-pod token of section 2, the
   chart adds the init container and the memory-backed volume mounted only into `gateway` and
   `wif-broker`, and the gateway sends the header. A test proves the broker refuses a call without
   it, and the chart test proves `injection-classifier` doesn't mount the volume.
2. **Suites classify by HTTP status.** The promptfoo `transformResponse` and the garak block
   adapter (`redteam/garak/block_adapter.py`) count a response as a block only when it is HTTP 400
   and carries the `request blocked by` marker. A 503 or 413 is a gateway error, never a block,
   whatever its message says.
3. **Named image/digest pairs in the rollout tooling.** The staging rollout check
   (`redteam/wait_for_rollout.py`), its overlay digest parser and `promote-prod.yml` handle the
   gateway and classifier digests as named pairs, so each is waited for, verified and promoted on
   its own, and a promotion can't pin one image's digest under the other's name.
4. **Explicit garak family grouping.** `gate.py` groups by an explicit class-to-family map from
   `thresholds.json` (falling back to the module name for unlisted classes), so
   `latentinjection_holdout` is report-only and then floored at 0.80 on its own, and the existing
   `latentinjection` family is unchanged.
5. **Staging quota.** An ops-central `k3s-change` build job raises the staging quota to fit the
   chosen model (section 5), and the CI quota-fit arguments are raised to match.

### 8. Scale/HA

The sidecar is a pure function of the request, with no state between requests and nothing shared
between replicas. The gateway's verdict cache is per pod and purely an optimisation: an empty or
lost cache costs latency, never correctness, so replicas need nothing shared and no session
affinity. The sidecar scales with the gateway Deployment, one per pod, and a replica's classifier
failing affects only that pod: in `enforce` mode the pod leaves the Service once it isn't ready;
in `report` mode it keeps serving. Each pod's memory grows by the model, so rolling updates
(`maxSurge: 1`) need room for one more pod of that size (section 5), and a horizontal autoscaler,
when one is added, scales on CPU, which the classifier now dominates. More replicas mean lower
cache hit rates without affinity, which shows as latency in the report-mode numbers. A shared
inference service or GPU pool for large clients would be a later, separate decision; the HTTP
interface would carry over unchanged, over mTLS (ADR 0017).

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
  - The broker logs every refused call (reason code only), so a container probing it without the
    token shows up.
  - The nightly red-team gate, with the hold-out family, measures the deployed system end to end.
- **Contain.**
  - The classifier can only add blocks. A compromised or backdoored model at worst returns the
    gateway to the heuristics-only posture of ADR 0024, or refuses traffic.
  - The container holds no credential, no Secret and no service-account token. It can't change
    a request, only score it. Root filesystem is read-only, it runs unprivileged, and its image
    is digest-pinned and signature-verified at admission.
  - **Loopback neighbours.** A compromised classifier shares the pod's loopback. It can't use the
    federation broker, which requires the per-pod token the classifier never mounts. It can reach
    the other loopback ports, LiteLLM and the auth sidecar, but each requires its own credential
    (a key or a JWT), which the classifier doesn't have. Any future loopback listener in this pod
    must authenticate its callers too.
  - The weights come from a pinned revision as safetensors only, re-exported by our own build
    with default-domain operators only, never a third party's ONNX file.
  - The verdict cache holds scores keyed by content hashes; a poisoned entry would need a sha256
    collision.
  - Residual risk: the sidecar sees the redacted text of every untrusted message and shares the
    pod's egress, so a compromised image could try to send it out. The supply-chain controls are
    what prevent it.
  - Inputs crafted to be slow are bounded by the body limit, the window cap, the queue and the
    timeout, and LiteLLM's per-key rate limits and budgets bound any one caller.
- **Recover.** One overlay PR sets `classifier.mode: report` (or `enabled: false`) or pins the
  previous digest, and Argo CD rolls it out. The broker token is regenerated with every pod, so a
  restart revokes it. The lock file rebuilds an identical model, and the harness re-measures it
  before re-enabling.

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
7. **Scoring only the current turn.** Rejected in review: the gateway has no session state, so a
   caller could plant text in an earlier turn that was never scored. The verdict cache recovers
   most of the cost.

## Consequences

- Indirect injection is scored by a model trained for it, under criteria and an acceptance gate
  fixed before the measurement, with the hold-out kept clean and scored through the gateway's own
  preprocessing.
- Each gateway pod needs 1 to 2 more CPUs and 1 to 3 GiB more memory (limits), depending on the
  model, and its image pull grows by the model size. Staging's quota has to grow before report
  mode can start.
- Every input request waits for the classifier on its uncached messages: tens of milliseconds for
  typical prompts on a warm cache, up to the timeout for the largest allowed. A cold cache makes a
  long conversation's next request pay for its whole history.
- Fail closed turns a classifier outage into refused requests (503) for that pod's callers. An
  uncached remainder over the window cap is refused (413), which can affect agents that paste very
  large documents, or long conversations on a cold cache, until the cap is calibrated.
- The federation broker gains caller authentication, a change to ADR 0009.
- The release job needs Hugging Face access for gated models, from a `main`-only environment.
- The audit schema goes to 1.1, with an optional block.
- Streaming requests are covered, because scoring happens before the call.

## Open items

- **The model**: from the Prompt Guard 2 run (86M and 22M) against section 1. To be filled in,
  with its revision, the locked file hashes, the scored ONNX sha256, size and resident memory.
- **The threshold**: chosen by the rule in section 1 from the same run.
- **The licence**: Prompt Guard 2 is distributed under Meta's Llama licence. Publishing the
  classifier image publicly redistributes the weights. Its conditions (shipping the licence text
  and the attribution notice, the acceptable-use policy) must be met, or the classifier image is
  made a private package under the same GHCR prefix. That keeps the Kyverno policy unchanged and
  uses the existing pull secret.
- **Reproducible export**: the build relies on the export reproducing the lock's hashes with
  pinned versions. Evidence so far: in guard-eval run 43152667170 (#213), the separate
  onnx-fp32, onnx-int8 and onnx-int8-rr jobs exported deberta-v3-base to byte-identical fp32 files
  (one sha256), on hosted runners with different CPUs. That covers one architecture family and one
  set of pins, and says nothing yet about whether int8 quantisation is byte-reproducible, so the
  build check stays. If a build ever fails it, the ONNX file is exported once by a dedicated
  workflow and published as a signed OCI artifact that the image build pulls by digest.
- **CPU calibration**: per-window latency on the cluster's nodes, which sets the window cap and the
  CPU limit.
- **Needs the owner (changes from the review):**
  - The staging quota increase (section 5) is a capacity and cost change on shared infrastructure:
    the owner's yes, through ops-central's build job.
  - Broker caller authentication amends ADR 0009, an accepted decision.
  - Scoring every turn, with a per-pod cache, replaces the current-turn scope this ADR was
    accepted with. The cache is per-pod in-process state; it is argued above to be an
    optimisation only, not shared state, under the HA design rule.
  - Report mode's probes (section 5) mean a classifier that fails its startup checks keeps
    running and answering `not_ready`. That follows the owner's report-mode decision, but it is a
    second place where report mode doesn't fail closed.
