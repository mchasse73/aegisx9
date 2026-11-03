# 21. Delivery spine: one id per change, gate-signed releases and a one-pane console

- Status: Accepted (owner decisions 2026-11-03)
- Date: 2026-11-03

## Context

A change touches many systems: the work tracker, the code host, CI, the approval gate
(ADR 0012), the GitOps controller (ADR 0003) and the log store. Each mints its own ids, and
today nothing joins them. Nobody can follow a change from the work item that asked for it to
the running system and to the evidence that it was authorized, and the DORA and approval
metrics a manager needs can't be computed. Developers, managers and approvers also look in
different tools, none of which knows whether a change was authorized.

## Decision

**One hub id per change.** Every change has one hub id: the gate's request (job) id, minted at
submit. Every other id is joined to it by the gate, at the moment the gate learns it:

- the work key (the human handle) and the pull request, head and base commits, carried inside
  the spec hash, so a signed request can't be re-pointed;
- CI runs, read by the gate's code-host connector by polling;
- the approval statement hash and the signers, when the threshold is reached;
- per-job credential ids (certificate serial, broker token accessor, never the credential);
- the release commit and image digest, then the GitOps sync revision;
- request ids and alerts, for how the change behaves in production.

Each join is a `spine.link` event, appended to the gate's hash-chained audit log (so the
write-once copy holds the joins) and written to the log store. Links are append-only and
idempotent. Only the gate joins ids; a tracker sync service may log an incident-to-release
link but never writes gate state.

**Ids are fields, never labels.** Log labels stay fixed and low-cardinality (project, host,
job, unit, env, level). Every spine id is a JSON field with one spelling in every component,
promoted to structured metadata by the collector so it filters without being indexed
(ADR 0016, rule 3). Tokens, statements, signatures, spec bodies and full nonces are never
logged.

**Sources of truth.** Every fact has exactly one source that writes it. Every other system holds
a mirror that links back, never feeds a decision, and is rewritten from the source when they
disagree (the disagreement is logged and alerted).

| Fact | The one source |
|---|---|
| What work exists, priority, incident lifecycle | the tracker |
| Code and its history | git on the code host |
| Whether tests passed for a commit | CI |
| The approval policy | the policy repository (signed bundle) |
| Whether a change is authorized; who may approve | the gate, with its credential registry bound to identity-provider groups |
| Who a person is | the identity provider |
| What an environment should run | the release commit at the head of `env/<env>` |
| What is actually running | the cluster, read through the GitOps controller |
| Image provenance | the registry signature (keyless, transparency log) |
| Secrets | the secret broker |
| Tamper-evident audit | the write-once store, anchored by the gate's chain head (ADR 0019) |

A tracker "Approved" status or a code-host approval review is a mirror or a workflow signal,
never an authorization (ADR 0012, ADR 0014).

**Application changes (GitHub and Argo CD).**

1. A pull request gets a gate request of type `vcs-change`, created by the gate's GitHub App
   connector polling with a short-lived installation token. A required status check from that
   App (bypass list empty) holds the merge until the statement is signed. The spec binds the
   head, base and target branch: a new push, a moved base or a retargeted PR is a new spec
   hash and a new request. The branch must be up to date with its base before merge (strict
   status checks), or the gate signs the exact merge-queue result, so a signed head can't be
   merged against a base the signature never covered.
2. Merge, then the release workflow builds once, scans, writes an SBOM and signs keylessly
   (ADR 0002). Staging may track the default branch with automated sync at a low tier.
3. Promotion to production is its own gate request of type `deploy` (environment, digest,
   source commit, staging evidence, parent request), signed separately.
4. After re-checking the deploy approval (spec hash, expiry, threshold), the gate writes a
   **release commit** on `env/prod`: the approved tree plus a release record (request id,
   statement hash, spec hash, digest, source commit, work keys), signed with the gate's
   release key, through the code host's API with a 1-hour repo-scoped token.
5. Argo CD's production Application tracks `env/prod` with automated sync, and its project's
   signature keys list **only** the gate's release key. Production gets its own Argo CD
   project for this, because signature keys apply to every Application in a project and
   staging keeps tracking the default branch. Admission re-verifies the image signature and
   fails closed in production.

This is outbound only (ADR 0017): the gate pushes to the code host and Argo CD pulls; nothing
calls in. It fails closed: no gate means no release commit, so production is unchanged; an
unsigned or foreign-signed head is a sync error; a manual sync to another revision is refused.
Layers: a code-host ruleset on `env/*` (only the gate's App may push; no force push or
deletion), Argo CD signature verification, an optional PreSync authorization hook, and image
signature admission. A signed tag per release is the fallback; gate-toggled sync windows and
branch protection alone were rejected (the first needs write access to Argo CD and fails open,
the second makes a review the authority). Rollback is a new gated change from a low-tier
"roll back to a released digest" template. To be proven in a test repository first: Argo CD
accepts a commit signed through the code host's API and refuses unsigned revisions.
Signature verification proves who signed a revision, not that it is the current `env/prod`
head: an older gate-signed release still verifies. So routine identities get no production
sync, override or Application-update permission, and a test proves they can't deploy an older
signed release; a rollback is always a new gated change.

**Infrastructure changes** go through the executor: a request carrying the work key inside
its spec hash, policy evaluation and a read-only pre-flight review, approval (a standard
change without a signature only where policy allows it), an executor re-check and lease, and
per-job credentials (an SSH certificate with a TTL no longer than the job, at most 2 hours,
and one broker token from a fixed policy catalogue; ADR 0013). Commits carry both ids.

**Emergency changes** follow ADR 0012's break-glass rules: hardware-signed with a smaller
quorum, an incident id, an expiry of at most 1 hour, security paged, and a retrospective
signature from security within 72 hours. Policy, signer-registry and detection-rule changes
are never allowed on this path. A change found with no request at all is a detection and
must get a record after the fact.

**One-pane console (owner, 2026-11-03).** The approval console (#108) grows into the one
console for developers, managers and approvers, the first modules of the admin console (#93).
Every widget is a query keyed by spine ids.

| View | Shows |
|---|---|
| Developer | my work; my PRs with CI and gate state; what waits for approval and for how long; per environment, desired release vs synced revision vs health; my service's logs, pre-filtered to the current release; incidents on my services |
| Manager | sprint and epic progress; the approval queue and approval latency; DORA; incidents and SLOs; the evidence export per release; policy exceptions (time-boxed relaxations, emergency changes, overdue retrospectives) |
| Approver | the existing signing flow (ADR 0012): inbox, review page, statement shown verbatim with a client-side spec-hash recompute, WebAuthn with user verification |

The approver view is built first, and the build order is unchanged: after #86. The backend
reads every source outbound with a read-only identity through one plugin interface per source,
and the browser never holds a vendor token. **The only write is the gate's signing endpoint**
(and credential enrolment): the console never moves an issue, merges a PR or syncs an app.
When a source is down its widgets show "stale since"; the approver view depends only on the
gate.

**Metrics from the spine**, computed by the console backend because they need joins:

- deployment frequency: distinct gate releases that reached production per environment,
  counted once each (repeat and self-heal syncs of the same release are excluded);
- lead time for changes: first commit of the PR to the production sync of the release that
  contains it;
- change failure rate: production releases followed within 7 days by an incident linked
  "caused by" that release, or by a rollback release, divided by production releases;
- time to restore: incident opened to mitigated, for incidents linked to a release;
- approval latency: request submitted to approved, and challenge issued to consumed, by tier
  and approver;
- **evidence export per release**, signed by the gate: the release record, both gate requests
  with their specs, statement hashes, signer records, audit entries with a chain proof to the
  write-once anchor, CI runs, image digest and transparency-log entry, sync history, linked
  work items and incidents (#111).

**Capability checklist** for a deployment:

- the work key in branch, PR, commit and the gate request spec;
- a required check from the gate's App with an empty bypass list (#110);
- gate-signed release commits on `env/<env>`, protected by a code-host ruleset;
- GitOps signature verification limited to the gate's release key;
- image signature verification, fail closed in production;
- `spine.link` events and structured metadata in the log collector;
- GitOps controller logs and events in the log store;
- incident-to-release links from the tracker sync (#114);
- write-once anchoring of the gate's chain head.

## Scalability

The gate runs N replicas on a shared database with server-side claims and one sequencer with
signed checkpoints for the audit chain (ADR 0016). Hub ids come from a database sequence or a
tenant-prefixed ULID, never a per-process counter. `spine.link` consumers dedupe on request
id, field and value. The console backend is stateless (per-replica caches with TTLs), and
pollers are leader-elected per tenant and resume from shared, fenced cursors. Each tenant has
its own log tenant, code-host installation, tracker site, GitOps project, release key and
reader credentials, so no query joins across tenants. Acceptance once HA is built: killing a
gate replica during a signature and release write leaves exactly one release commit; killing
the tracker sync leader during a burst loses and duplicates no change issue; blocking
code-host egress for an hour deploys nothing and the backlog then clears.

## Assume breach

No mirror can approve. A compromised tracker can move a status but nothing reads it for
authority. A compromised code host can push to `env/prod` but can't sign as the gate's release
key, which it never holds. A compromised Argo CD admin is an enforcement bypass,
not only a detection: replacing the trusted signature keys with their own lets them deploy
manifests they signed (still referencing an approved image while changing its command or
configuration), and a manual sync can select an older signed release. Prevention is
therefore no standing Argo CD admin in production (just-in-time, hardware-approved access,
ADR 0019); detection is the project drift and non-automated sync alerts below; containment
is revoking the admin session and restoring the declared project from git. A compromised
console shows misleading content but holds no key, and the gate notifies approvers from its
own record. A stolen release key can sign a commit but can't create the matching request,
approvals and audit entry. Detections (added to #113), each with a known-positive test and a
shadow period before it alerts or contains: an `env/*` head not signed by the release key or
not pushed by the gate's App; a production sync not started by the automated controller; GitOps
project or Application drift from declared state; production revision differing from the
gate's latest release for more than 15 minutes, or a running digest in no release record; a
release record naming a request or statement with no audit entry; an infrastructure change
with no request and no emergency record; a change to a gate-owned mirrored tracker field (authorization status, release links)
made outside the sync identity. Ordinary tracker edits (priority, incident lifecycle) are the
tracker's own facts and raise nothing.
Containment is one step per component (revoke the token or App key, disable the approver
role, rotate the release key and replace the controller's signature keys), and recovery
re-applies declared state from git and reconciles mirrors from the gate.

## Consequences

- The gate gains a release-writer role and a release key, which become high-value assets with
  their own rotation and detection (#109, #110).
- Every component logs spine ids under the same field names; a component that labels by id
  fails review.
- #108 widens from the approver view to the one-pane console, but only the approver view is
  in scope until #86 ships.
- Change management (#114) consumes the spine; the tracker stays workflow, never authority.

**Gaps in the reference deployment today**, both planned fixes pending the owner's decision:

- production tracks `main` with automated sync, so a merge deploys and code review is the
  authority today; the `env/prod` release commit replaces this;
- image admission currently fails open on webhook errors; the target is fail closed in
  production.

Umbrella: #107.
