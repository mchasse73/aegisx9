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
