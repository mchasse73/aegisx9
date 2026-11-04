# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-11-04

### Added
- Embedded-instruction input guard and instruction-echo output guard (#179, #195, ADR 0024). The input guard scans user and tool messages and blocks instructions planted in pasted data: requests to drop the rest of the data or everything except a bracketed string, fake end-of-session tags, and a quoted "just print"/"reply with only" literal placed on a fake `User:`/`System:` turn or after stacked separators. Weak signals on their own are allowed and logged as findings. The output guard blocks an answer that repeats, as whole words, a literal the current turn's data tried to force. The hook computes those literals once per request into a request-scoped `GuardContext.prompt_literals`, which is never logged or audited. The keyword guard also catches the shouted stop-and-print template, and the encoded-payload guard applies the strong signals to decoded spans. Offline, through the pipeline, with prompts rebuilt from garak 0.17.1: promptinject goal hijacking is blocked 525/525 (was 0.90 in the gate) and LatentInjectionReportFull 648/648 (was 0.30). There are no false positives on a 104k-word dictionary, 5,000 random sentences, 20,000 order numbers, the benign suite, developer data, or new corpora of chat transcripts, Markdown, code, prompt-engineering requests and emails. The new guard blocks none of the repository's 362 tracked files. Hold-out families it wasn't tuned on are blocked 26% (1,848/7,168); the Resume family's praise injections (0%) need the classifier (#198). Embedded guard p99 is 1.3 ms on a 32 KB prompt, linear up to 1 MB. Streamed completions aren't covered yet (#197). A pre-PR review found 10 evasions and false blocks in the first draft; all are fixed, each with a regression test. Copilot then found 7 more, all fixed with regression tests: two quadratic regexes (every pattern is now timed on 64 KB pathological input), a key split across content parts that reached the model unredacted (the text parts are now merged into one redacted part), session markers glued to a word, URLs with ports or queries not counted as links, stacks of three or more separators, and tool-call steps that cut the user's request out of the turn. The hold-out fell from 34% to 26% because strong signals now count only inside pasted data, not in the user's own words.
- ADR 0023: training-data replay (garak `leakreplay`) is reported, not gated (owner decision, #180). A gateway can't change what a model memorised, and the family sat near 0.30 against its 0.90 floor once scoring was fixed. It still runs and prints against its floor, marked report-only. It no longer fails the gate, the external scanner or the coverage check. Making a family report-only needs an ADR, and a test pins the list. The coverage message now also names answers cut off at `max_tokens`.

### Changed
- Staging runs v0.5.0 (digest `sha256:f6b1ffef…`, the signed index the 0.5.0 tag points at), so the encoded-payload guard is live there (#172).

### Fixed
- The proxy hook skipped OpenAI content-parts messages (`content` as a list of parts) for every input guard, including secret and PII redaction, so text sent that way reached the model unguarded. Each text part now goes through the whole input pipeline and is redacted in place; several parts are also checked joined. Image and other parts are left alone (#179, #195).
- The empty-answer fill (#191) also caught answers cut off at max_tokens: 47 of them in run 41772487413 had `finish_reason: length`, so a cut-off answer scored as a refusal. The adapter now fills only empty answers that stopped on their own; a `length` empty is rewritten to null content (an empty string would still be scored; caught by Copilot) so it stays unscored and the coverage check fails the family. garak's `max_tokens` goes from 256 to 1024 (#193).
- garak left an empty model answer (a refusal with no content) unscored, and the new coverage check then failed leakreplay (9 of 30 scored) and latentinjection (18 of 30) on run 41770191502, though the gateway returned no errors. The block adapter now fills an empty answer with `[EMPTY:<finish_reason>] I can't assist with that` and counts it by finish reason; an empty answer reproduces nothing. A null answer carrying tool calls is left alone (a tool call is an answer, and may be the jailbreak). The "garak log on failure" step no longer fails itself when its grep finds nothing (#191).
- The garak gate scored only the attacks the guards missed. A guard block answers 400 (#171), garak records a 4xx as a failed call with no output, and its detectors skip those, so in run 41765065198 base64 scored 2 of 30 attempts and hex 2 of 30, and every block was invisible. A loopback adapter in the garak step (`redteam/garak/block_adapter.py`) now turns a guard block into a `[BLOCKED] I can't assist with that: …` completion that scores as a pass (the refusal phrase keeps garak's MitigationBypass detector from reading a block as a jailbreak) and passes every other response through unchanged; it logs counts only and never follows a redirect (urllib would carry the Authorization header to another origin; caught by Copilot). `gate.py` also fails a family when under 90% of its attempts were scored, so gateway errors can't shrink the denominator. The external scanner's garak run has the same blind spot (#189) (#188).
- The red-team job could spend its whole hour in the install step: garak's torch dependency pulled about 2 GB of CUDA wheels from PyPI, and on a slow mirror that took more than 60 minutes (two runs cancelled on 2026-11-03). The step now installs the CPU build of torch first (about 200 MB, as the external scanner already did), has its own 15-minute timeout, and fails if any `nvidia-*` package slips back in (#184). Its timeout is 25 minutes: the first run with the CPU build still took 14 (#186).
- promptfoo counted an empty model answer (a refusal with no content) as an eval error and failed the gate with no finding; the response transform now scores it as `[EMPTY:<finish_reason>]`, which leaks nothing and the benign cases reject it explicitly, since `[EMPTY:content_filter]` is long enough to pass their length check (caught by Copilot) (#186).

## [0.5.0] - 2026-11-03

### Added
- Encoded-payload input guard (#172, ADR 0022). It decodes base64, base32 and hex in a prompt (hex plain, `0x`-prefixed, byte-separated, `\x` or `%` escaped) and blocks a span that hides an injection pattern or readable text. It runs after redaction, so base64 credentials are redacted rather than blocked. The first full garak run let 76% of base64 and 83% of hex attacks through. Offline, through the pipeline, garak's own payloads are now blocked 92% (base64) and 89% (hex), with no false positives on a 104k-word dictionary, 5,000 random sentences, 20,000 order numbers, the benign suite or common developer data. A pre-PR review found 9 fail-open and false-positive paths in the first draft (a span budget that padding could exhaust, `=`/`_`/`0x` prefixes, one junk byte, oversized spans, a JSON wrapper, 6-digit numbers, base64 credentials); all are fixed, each with a regression test. The promptfoo suite gains a hex-encoded attack.
- Secret redaction recognises `Authorization: Basic` credentials (`basic_auth`).

### Changed
- Staging runs v0.4.2 (digest `sha256:02c3355e…`, the signed index the 0.4.2 tag points at), so guard blocks there answer 400 (#171).

### Fixed
- garak 0.17 renamed the eval row's `total` to `total_evaluated`. The in-cluster gate raised on the missing key (failing closed). The external scanner read it as 0 and scored every probe family as passing, whatever garak found (failing open). Both parsers now read `total_evaluated`, score a zero total as 0, and accept a `probes.` prefix; the scanner fix takes effect on its next deploy (#177).
- garak ran out of its 12-minute step after 3 of 8 probes: at the default 256 prompts and 2 generations, the encoding probes alone made about 400 calls. The run is now capped at 30 prompts per probe, 1 generation and 6 in flight (about 300 calls, under Haiku's 120 rpm). Thresholds are unchanged; the sample per probe is smaller (#147).

## [0.4.2] - 2026-11-03

### Added
- ADR 0021, delivery spine and one-pane console (#107, #108): one hub id per change (the gate's
  request id) with every other id joined by `spine.link` events and kept as log fields, never
  labels; one source of truth per fact; production deploys only gate-signed release commits on
  `env/prod`, which Argo CD verifies against the gate's release key (outbound only, fails closed);
  the approval console grows into developer, manager and approver views (approver first, after
  #86); DORA, approval latency and a signed evidence export per release. Today's gaps are listed:
  production tracks `main`, and image admission fails open on webhook errors.
- Staging gateway accepts the red-team job's machine identity as a second token issuer (15-minute tokens, mapped to the staging-tests team), so the red-team gate no longer needs a stored gateway key (#147).
- Red-team freshness alert (#147): a scheduled workflow on GitHub-hosted runners fails, and so
  emails the owner, when `redteam-staging` hasn't succeeded on `main` for 48 hours.
- Approval console contract fixture (`tests/contracts/approval-console/`, #108, #109): one JSON
  file per console-to-gate endpoint with every success and refusal case, the action the
  console must take on each, and a stdlib schema checker. It is ported from customer zero's live
  console and gate, with placeholder credential ids, challenges recomputed from their statements,
  and the full browser registration response accepted. Both the future console and gate suites will assert against it, so neither side can
  drift alone. A test checks the fixture against itself, and the README lists the planned product
  differences.

### Changed
- `.gitignore` now ignores credential drop files (`.jira*`), so a vendor token placed in
  the repo directory can't be staged by accident (#143).
- ADR 0012 wording (#108, #109): keys that always report a signature counter of 0 are
  accepted as counter-less, a non-zero counter that does not increase is refused and alerts,
  and the counter is checked only after the signature verifies. The approver principal is
  bound by the credential-id registry, and the user handle is checked only when the
  authenticator sends one. Enrolment stays as written: only an existing hardware-signed
  approval can add a key (owner 2026-11-03).
- Staging: the developers team's 30-day cap rises from $50 to $75 (owner decision
  2026-10-29), so all three developers in the Coder quota can use their full $25 each.
  Allocated budgets now total $125 of the $180 gateway cap.

### Fixed
- Guard blocks now return HTTP 400 `invalid_request_error`, with the same `request blocked by <guard> (<direction> guard)` message, instead of 500 `internal_server_error`. Clients and SDKs retried every blocked prompt as a server fault, which also ran the red-team garak step out of time. The image smoke test now sends a known injection and requires the 400 (#171).
- garak asked the gateway for model `aegisx9-redteam`, which doesn't exist: garak sends the target name as the request's model and ignored the `model` generator option. The gateway refused every request, garak swallowed the errors and recorded no results, and the gate failed the run (correctly). The workflow now passes `--target_type`/`--target_name` (the gateway model), the deprecated config keys are gone, and a failure-only step prints the masked tail of garak's own log. The external scanner shares the config and had the same defect; it now passes the target name too (takes effect on its next deploy) (#147).
- garak's report directory is now created before the run; garak opens the file but never creates its directory (#147).
- garak never ran: the probe `xss.MarkdownImageExfil` moved to `web_injection` in garak 0.17, so garak rejected the spec and wrote no report. The probe and its threshold now use `web_injection` (same 0.95 floor). The garak gate now fails when a configured probe family is missing from the report, or when a family made no attempts (previously scored as 100%). A test ties the probe spec to the thresholds file (#147).
- promptfoo runs with `--no-table`, so generated planted values (fake, built at runtime) no longer appear in the public job log (#147).
- After minting, the red-team job reports the access token's claim names and group count, never a value, to triage the gateway's `no_team` refusal (#147).
- promptfoo data-leak cases now get their planted values from a `transformVars` hook declared in `defaultTest`. promptfoo inlines `file://` strings inside test files and doesn't support a `:function` suffix for variables, so neither earlier form loaded. Verified locally with promptfoo 0.124.1 and its echo provider: all 15 cases load, and the data-leak checks evaluate real generated values (#147).
- promptfoo data-leak cases pointed at `../generators/planted.js`, but promptfoo resolves `file://` paths from the config directory, so the suite stopped before sending a request. Paths fixed, plus a test that every `file://` reference resolves (#147).
- Red-team token errors now name the failing step (GitHub OIDC or identity provider) and the OAuth error code when it has the standard shape. When the identity provider refuses the federated assertion, the job prints the shape of its `sub` (key names, and whether each value matches the expected repository, ref and environment), never a value (#147).
- Staging rollouts were blocked by the namespace quota (#162): each gateway pod declared 1.6 CPU of limits, and a rolling update runs two pods, which with the jobs exceeds the 3-CPU quota, so the PR #152 rollout never started a pod (the old pod kept serving). Staging limits are now gateway 800m and auth 400m (1.3 CPU per pod). New CI step `scripts/ci/check_quota_fit.py` fails a PR whose rendered staging overlay can't roll out within the quota.
- Red-team gate: the in-cluster runner has no Node, so the install step failed with `npx: command not found`. The workflow now installs Node 22 with a pinned `actions/setup-node` (#150).
- The staging red-team gate never passed and hadn't run since 2026-10-21 (#147). This change
  fixes the pipeline; the gate goes green only once the machine identity it needs exists.
  - **Blocked queue (fixed):** a run from 2026-10-22 waited for an environment approval for 12
    days, so every later run queued behind it and was cancelled. The job now runs in a new
    `redteam` environment that allows exactly `main` and needs no reviewer, so the daily run
    starts on its own. It triggers on the schedule, on manual dispatch, and on pushes that
    change the staging overlay or the red-team suites.
  - **No `kubectl` (fixed):** the runner image doesn't have it, so the rollout wait exited at
    once. The wait now calls the Kubernetes API with the pod's service-account token, and
    retries transient API errors until its deadline.
  - **Wrong image (fixed):** it waited for each release's digest, which staging never runs. It
    now waits for the digest pinned in the staging overlay on `main`.
  - **No credential (pipeline ready, identity pending):** the job had no gateway credential at
    all. It now exchanges its own GitHub OIDC token for an identity-provider machine-identity
    token of 13 to 15 minutes, a fresh one per suite, with nothing stored. Each suite is
    capped at 12 minutes, and tools are installed before any token exists. The machine
    identity and the gateway's second issuer are still to come; until then the job stops at a
    clear "no red-team credential configured" step.
  - **False passes (fixed):** promptfoo scored *any* gateway error as "blocked", so an expired
    token, a 429 or a 5xx would have counted as a perfect defence. Only a guard block counts
    now, and any other error fails every test.
## [0.4.1] - 2026-10-29

### Added
- ADR 0019, assume breach: every control answers prevent, detect, contain and recover. It adds
  a WORM audit copy with an externally anchored chain head, misuse detection and honeytokens,
  a signed one-action kill switch, just-in-time privilege for automation, and recovery
  drills, plus an acceptance checklist.
- ADR 0020, geofencing for remote access: an edge country allow-list, per-user regions in the
  identity provider, revoke and alert on a disallowed region, impossible-travel detection, and
  a local GeoIP database updated by pull. Geography only removes access.
- ADR 0016, scalable by design: HA is designed for now and built after Phase 2. Every ADR
  carries a scalability check (0001-0015 checked), with rules for shared state (one
  sequencer with signed checkpoints, compare-and-set nonces and signature counters,
  server-side leases, endpoint lists, a disk-buffered audit, low-cardinality labels).
- ADR 0017, outbound only, never ingress (amends ADR 0014: no webhooks, SCIM push or inbound
  callbacks; hosts dial the control plane). The control plane runs only over WireGuard or
  mTLS, with peers identified by key, multiple hubs and fail-closed behaviour, plus an
  acceptance checklist.
- ADR 0018, directory adapters for identity sync (Authentik, Okta, Entra ID, SCIM pull),
  with machine identities kept out of per-seat directory licences.
- ADR 0015, brokered agent credentials and per-project identities (#128, amends ADR 0013).
  Agents hold only an opaque handle bound to their session, process and user, which is
  exchanged for a single-use broker token per request. The broker keeps the only real login
  (workload identity) and a single-use child credential that never leaves it. Handles use a
  scanner-detectable prefix (revoke and alert on sight), and every use is audited. Each project
  gets a service identity and group in the identity provider, synced to hosts. Onboarding
  beyond a template needs a signed approval, and there is one register, grant, log in, use,
  request-more workflow.
- `aegisx9-login`, a developer CLI that gets a short-lived gateway token (#122): OIDC
  authorization code with PKCE (S256) against a public client and a loopback redirect, an
  https-only discovery whose issuer must match exactly, single-use `state`, and the access
  token written to a 0600 file by atomic replace. It never prints the token, only its
  remaining lifetime, and reports errors by exception type only.

### Changed
- Staging runs v0.4.0 with the auth sidecar enabled (#86): callers present identity-provider
  access tokens of at most 15 minutes, which the sidecar exchanges for virtual keys that
  expire with them. The issuer, JWKS URL, audience and group-to-team mapping are read from
  the gateway Secret, so the public overlay holds no identity-provider details.

### Fixed
- Scanner root volume tags are now part of the launch request (`volume_tags`) instead of a
  CreateTags after launch, which the deploy role is not granted (#124); in-place volume tag
  changes are ignored and take effect on the next instance replacement.

## [0.4.0] - 2026-10-29

### Added
- Auth sidecar: an issuer's `audience` and its group-to-team mapping can now come from the
  gateway Secret (`audienceEnv`, and `groupTeamsEnv` holding ordered `group=team` pairs
  separated by `;`), like `issuerEnv` and `jwksUrlEnv`. This means no identity-provider
  details need to be committed to the public repository (refs #86).
- Product scope and build plan (#107): AegisX9 is the security gateway for AI-driven
  development: an LLM gateway, a build and action gate, and approval governance, with one
  view of what AI is building and changing. ADRs 0011 (scope, accepted), 0012 (approval
  governance: typed policy-as-code, signed statements with nonce, expiry and per-signer
  records, N-of-M and separation of duties, break-glass), 0013 (short-lived, single-use
  secrets and per-action credentials) and 0014 (integrations without inbound exposure,
  GitHub first, then Jira, then a connector framework with a trust bar). The roadmap is
  rebuilt into Phases 2 to 6 (epics #109 to #115). ADRs 0012-0014 fold in the detailed
  design and the owner's decisions of 2026-10-29. AegisX9 builds its own gate, and the
  homelab's build-request system is customer zero. Customer zero is a declared
  single-approver tenant, with a cooling-off delay and the second hardware key for T3/T4.
  Events are polled only, with no inbound exposure.

### Changed
- README: describes the new scope and roadmap; the status shows version 0.3.1 (it said 0.1.0).

### Security
- CI: ten new filelock 3.x advisories (#117) are assessed and listed in `.trivyignore` with
  their rationale. All need a second local user, or are Windows-only, and the gateway pod is
  a single non-root user on a read-only root filesystem. LiteLLM still caps `filelock<4`, so
  the fixed 4.x releases don't resolve. pip-audit --strict was failing every PR.

## [0.3.1] - 2026-10-28

### Fixed
- Scanner: the webhook URL parameter is now optional (#102). v0.3.0's boot-time fetcher
  required it, so the scan units could not start before an Event-Driven Ansible receiver
  existed; the redeploy for #96 stopped on the missing parameter. With no URL the webhook is
  off and alerts go by email only (the notifier already treated an empty URL that way); the
  webhook HMAC secret is required only when a URL is set. A non-https placeholder was not a
  safe workaround: it logs an error on every alert.

## [0.3.0] - 2026-10-28

### Added
- Short-lived JWT authentication (ADR 0010): `aegisx9.auth_proxy`, an auth sidecar in
  the gateway pod in front of LiteLLM (which then listens on loopback only). It validates
  tokens from configured issuers (JWKS signature with asymmetric algorithms only, `iss`,
  `aud`), requires `exp` and `iat`, refuses any token that lives longer than 15 minutes (a
  ceiling in code that configuration can only lower), maps groups to LiteLLM teams and
  exchanges the token for a virtual key scoped to that user and team that expires with the
  token, so model access, team and per-member budgets apply through LiteLLM's own checks.
  JWT callers are limited to inference routes; management routes answer 403.
  Every rejected token gets a generic 401; logs carry only a reason code. Other bearers
  (admin key, virtual keys) pass through unchanged. Chart: `gateway.oidc.issuers[]`
  replaces `jwksUrl`/`audience`/`userIdClaim`/`teamIdClaim`, and `gateway.oidc.enabled`
  defaults to false until an environment pins an image with the sidecar. CI image smoke
  boots LiteLLM and the sidecar with Postgres and runs `scripts/ci/auth_smoke.py` (refs #86).
- CI image boot smoke asserts that `/v1/models` without valid credentials returns 401:
  no header and an empty bearer with and without a database, and a random bearer with the
  database (the production setup), so an exception in the auth path can't ship as a 500
  again (closes #68).

### Fixed
- Workspace image: npm, npx and corepack are removed after Claude Code is installed, so
  the workspace has no package manager and none of npm's bundled dependencies. That
  clears two new undici advisories (certificate-validation bypass, TLS renegotiation DoS)
  that no Node 24 release fixes yet, and four older npm ignore entries. Claude Code's
  self-update is off (`DISABLE_AUTOUPDATER`), because the signed image pins its version.
  The Vault CLI moves to 2.2.1, which still bundles go-jose 4.1.5: its JWK-parsing DoS
  advisory has a documented ignore entry until the next Vault release. Developers no
  longer have `npm` in the workspace (owner decision, closes #99).
- The gateway image no longer contains `litellm-enterprise`, a proprietary package that
  `litellm[proxy]` pulls in (production use needs a BerriAI subscription; redistribution is
  not allowed). LiteLLM runs without it; the image job fails if it ever comes back
  (closes #91).
- The chart no longer enables LiteLLM's `enable_jwt_auth`, an Enterprise-only feature that
  answered every JWT with 403 and a message disclosing the edition and licence state
  (refs #86).
- CI: pip-audit and the gateway image Trivy scans read one documented ignore list
  (`.trivyignore`). It holds three filelock advisories that don't apply to the gateway
  and can't be fixed while LiteLLM requires filelock<4.0; removed once it allows 4.2.1.
  The workspace image ignores the undici advisory in Node.js 24.22.1's bundled copy until
  the next Node 24 LTS release (closes #88).
- External vantage scanner deploy defects found on an Ubuntu 24.04 rebuild: the bootstrap
  installs the AWS CLI v2 from the official zip with its PGP signature verified (the
  `awscli` package doesn't exist on noble and the snap can't run in the secrets fetcher's
  sandbox); the package installs with the PEP 508 `aegisx9[scanner] @ git+...` form, from a
  now-required `scanner_package_ref` (release tag or commit SHA), with CPU-only torch and no
  pip cache, on a 30 GiB root volume; the secrets fetcher fails, with an error naming the
  parameter and without leaving an empty file, when a required parameter can't be read; the
  daily unit drops `ProcSubset=pid` (nmap needs `/proc/net`) and sets
  `StateDirectoryMode`/`LogsDirectoryMode=0770` so the uptime and red-team units can write
  the shared state directory; the fetcher retries transient read errors and keeps the
  last good value, restarts itself on failure, and a failure no longer stops the timers
  from being enabled at bootstrap; the AWS CLI check also rejects expired or revoked keys;
  the role installs the package once per ref change (dependencies included) against a
  `+cpu` torch constraint, replaces a CUDA torch it finds, and re-runs the fetcher when it
  changes; uptime and red-team notify on a change of state (24-hour
  reminder, one recovery notice) instead of every run, registry entries that the
  never-target list covers are reported as intentionally not scanned (a never-target in
  targets.yml still alerts and fails `validate-config`), and the daily scan still sends
  its daily summary. Unit-file lint tests
  and a CI job that runs nmap under the daily unit's sandbox guard the units (refs #96).

## [0.2.0] - 2026-10-22

### Added
- Anthropic through Workload Identity Federation, with no static provider key (ADR 0009):
  `aegisx9.wif_broker` sidecar that logs in to Vault with the pod's service-account token,
  reads a fresh Vault-signed identity token for every exchange, keeps a short-lived
  Anthropic access token and serves a loopback-only proxy for LiteLLM (credential
  replacement, path allowlist, unbuffered SSE, `/healthz`); chart values `wif.*`. Staging
  activation (models `claude-haiku-5-5`, `claude-sonnet-5-5`, `claude-opus-5-5` via the
  broker) follows with the promotion of a signed image that contains it (refs #53).
- Spend caps: proxy-wide budget $180 per 30 days in staging and per-consumer LiteLLM teams
  (`public-chat` $20, `staging-tests` $30, `developers` $25 per member) kept in sync by a
  PostSync Job; spend-check CronJob (whenever a proxy budget is set, with or without teams)
  and Loki alerts at 50/80/100 %; broker no-token alert; hourly check of Vault's OIDC
  signing keys against the federation issuer. The jobs are behind
  `gateway.budgets.jobs.enabled` until that image is promoted (refs #53).
- Public-repository preparation: an `identifier check` CI job that fails on internal
  identifiers (generic patterns in the repo, organisation-specific ones only from a CI secret), and a log redaction filter used by
  the self-hosted workflows so Terraform plan bodies and internal URLs stay out of public
  Actions logs (refs #1).
- Developer tier: Coder workspace template as Terraform (`infra/workspaces/coder-template`):
  one restricted pod per developer running the signed workspace image by digest, persistent
  home, CPU/memory/team parameters, gateway and OTel environment, no provider key; the
  `signed-digest-images` Sentinel policy now also checks bare pods (refs #47).
- Break-glass local workspace (`workspace/breakglass`): hardened devcontainer on the same
  image, `breakglass-login` (OIDC Vault window with an HMAC-signed activation event),
  `handoff-sync` (gitleaks-gated, append-only union sync back to the central workspace with
  manifest verification, shred and token revoke), EDA rules and the `breakglass` role with
  ledger and window-expiry job templates (refs #52).
- External vantage scanner (`scanner/`, console script `aegisx9-scan`): daily port, TLS,
  exposure-file, nuclei and DNS checks from a cloud host outside every allow-list,
  diffed against the approved-exposure registry and the previous snapshot; five-minute
  uptime checks; weekly external red-team run; dated clean reports; HMAC-signed webhook
  to Event-Driven Ansible and SES email; a never-target deny list enforced before any
  scan. With hardened systemd units, Terraform for the host (`infra/scanner/`), an
  Ansible deploy role and an EDA rule that opens an incident on `exposure_change`
  (refs #42).
- Developer workspace image (`workspace/`): signed, digest-pinned devcontainer with the
  locked Claude Code baseline as root-owned managed settings (gateway-only routing,
  `apiKeyHelper`, model allowlist, bypass disabled, secret-path denies, Bash sandbox with
  a network allowlist, exclusive managed MCP list, fail-closed hooks, telemetry without
  prompt text); CI builds and self-tests it, the release pipeline publishes it to
  `ghcr.io/mchasse73/aegisx9/workspace` with SBOM, Trivy scan and keyless signature
  (refs #48).
- `gateway-token` apiKeyHelper: Vault OIDC login for role `aegisx9-developer` and a
  short-lived gateway JWT from Vault's identity OIDC provider, cached in 0600 files, no
  static key anywhere (refs #49).
- Session memory and daily handoff: `handoff` CLI, `/handoff` skill, a `SessionEnd`
  hook that writes a stub note, team-memory publish, and documented home/team-memory
  mounts; every note is scanned with the same secret patterns as prompts (refs #51).
- `.gitignore` refuses credential-shaped files in the working tree (refs #33).
- Project onboarded into the maintainer environment: repo remote, tracking issue, docs
  collection and memory (refs #33).
- Initial scaffold: guard pipeline interface with prompt-injection, secret and PII
  guards; audit-event schema with no content fields and a secret self-check; model
  allowlist, budget and rate-limit policy; LiteLLM proxy hook adapter.
- CI (ruff, mypy, pytest with an 85% coverage gate, gitleaks, Semgrep, pip-audit,
  Checkov, kube-linter, Docker build, Trivy), release pipeline (Syft SBOM, keyless cosign
  signing, GHCR push) and a staging red-team workflow restricted to ARC runners on `main`.
- Helm chart, Kustomize overlays for staging and prod, Argo CD applications and a Kyverno
  image-verification policy.
- promptfoo and garak red-team suites, ADRs 0001-0007, contribution and security policies.
- `AuditSigner` interface with a Vault transit implementation and a local test double;
  signed audit envelopes.
- Terraform roots for staging and prod (Terraform Enterprise, organization `x9`) covering
  Kubernetes namespaces/quotas, Vault KV/transit/PKI, the identity-provider app, GitHub
  environments and branch protection, the ARC runner scale set and Route 53.
- Sentinel policy set (6 policies) with mock-based tests.
- Ansible collection `x9.aegisx9`, AAP playbooks and an Event-Driven Ansible rulebook.
- CI jobs for Terraform (fmt, validate, tflint, Checkov), Sentinel tests and ansible-lint;
  `infra-apply` workflow for TFE runs on ARC runners.

### Changed
- infra-apply runs only when the repository variable `INFRA_APPLY_ENABLED` is `true`, until the
  Terraform Enterprise workspaces and token exist (refs #17).
- Staging runs on Workload Identity Federation: new signed image with the broker, models
  `claude-sonnet-5-5`, `claude-haiku-5-5`, `claude-opus-5-5`, budget jobs and the signing-key
  check enabled (refs #53).
- Release signs and attests in cosign's legacy layout so the cluster's keyless image
  verifier finds the signature; overlays no longer render a NetworkPolicy (platform-owned);
  the Argo CD AppProject file mirrors the live, namespace-whitelisted project (refs #8).
- Branch protection no longer requires an approving review (single maintainer); required
  checks, linear history, conversation resolution and admin enforcement remain (refs #1).
- Staging overlay pinned to the first release digest signed in the legacy cosign layout; overlays no longer carry the
  Namespace object, which the platform team owns (refs #8).

### Fixed
- Day-2 jobs retry connection failures for up to 60 seconds (a new pod can be refused for its
  first seconds while network policy catches up) and can set a priority class (refs #53).
- Dependency bumps: hatchling 1.32.4, pytest 9.1.1, pytest-cov 7.1.0, ruff 0.17.1, mypy 2.4.0,
  checkov-action 12.3134.0 (supersedes Dependabot PRs #34 to #39).
- The gateway image starts with a database: the Prisma client (`prisma==0.11.0`, the version
  LiteLLM 1.106.2 ships), its CLI, query and schema engines and a digest-pinned Node.js are
  baked in at build time, the client is generated from LiteLLM's schema, and LiteLLM's
  migrations run from `/tmp` (`LITELLM_MIGRATION_DIR`), so nothing is downloaded at runtime and
  the read-only root filesystem holds. CI now also boots the image read-only against Postgres 17
  and checks that the migrations were applied, and that the Prisma CLI runs with no network.
- The signing-key check no longer alerts every day: it compared a digest of every key Vault
  publishes, including a built-in key that rotates daily. The broker now checks the `kid` of
  each identity token against `wif.uploadedKids` (`wif_kid_not_uploaded`), and the hourly job
  checks that every uploaded kid is still published (`missing_uploaded_kids`). The
  `wif.jwksCheck.expectedSha256` value and its alerts are removed; ADR 0009 describes key
  rotation.
- The guard callback subclasses LiteLLM's CustomLogger so the proxy loads it; CI boots the proxy
  with the real config as a smoke test; ExternalSecret defaults are explicit to avoid Argo CD
  drift (refs #8).
- First CI run: Checkov runs one framework per step, the rollout-wait script selects the
  namespace literal by comparison (no tainted argv for SAST), and GitHub provenance
  attestation is skipped while the repository is private; the gitleaks job can read PR
  commits (refs #2).

