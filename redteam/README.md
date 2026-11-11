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
the wamerican word list (sha256 pinned and recorded). `score.py` writes a JSON summary
(artifact) and the tables (job summary). Neither prints prompt text.

**On a pull request** that touches the guards, the pipeline or `eval/`: heuristics only, no
secrets. The job fails if a target family drops below 100% or any false-positive corpus is hit.

**Manual dispatch** (Actions → guard-eval → Run workflow), input `models`: newline- or
comma-separated `model_id@revision:label`, where `label` is the injection class's name or
index. Use a full commit sha as the revision; the summary records the resolved sha and the
weights' sha256. For example:

```
protectai/deberta-v3-base-prompt-injection-v2@90c9989b1a342275dd0d1a95aad283c04e075671:INJECTION
meta-llama/Llama-Prompt-Guard-2-86M@a8ded8e697ce7c355e395a0df51f94adb4a2fd27:1
meta-llama/Llama-Prompt-Guard-2-22M@11614a155199674a0a95e6602d6ab0417b790ed0:1
```

Each model runs in its own job in the `guard-eval` environment (main only). Its `HF_TOKEN`
environment secret reaches only the download step. Without it, gated models (Prompt Guard) are
skipped with a message. Only safetensors weights are fetched. Model results are report-only.
Empty `models` runs the heuristics alone.

Locally (no models): `python -m redteam.eval.build_sets --out /tmp/sets` needs garak 0.17.1 in
the interpreter; then `python -m redteam.eval.score run --sets /tmp/sets --heuristics --gate --out summary.json`.
