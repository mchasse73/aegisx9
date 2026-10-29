# 16. Scalable by design: every decision is HA-ready, HA is built later

- Status: Accepted (owner decisions 2026-10-29)
- Date: 2026-10-29

## Context

AegisX9 is designed for large organisations as well as small ones. The owner's requirements:
"systems need to be robust and redundant in the end", and "while we don't need to implement
HA now we need to validate all decisions to make sure they are scalable". The reference
deployment runs single instances today. The risk is a decision that quietly assumes one
process, one node or one store, and becomes a rewrite later.

## Decision

1. **HA is designed for, not built, in Phases 1 and 2.** Code and schemas must not assume a
   single instance. Building redundancy (replicas across failure domains, store failover)
   is planned work after Phase 2.
2. **Every ADR has a scalability check.** From this ADR on, each ADR ends with a
   "Scalability" section. It answers three questions: what state does the decision create,
   where does that state live, and what happens with N instances and with a failed instance?
   The checks for ADRs 0001-0015 are recorded below.
3. **Rules for state:**
   - gateway, gate, broker and host-agent replicas are stateless; shared state lives in a
     store built for HA, never in process memory;
   - the approval log's hash chain has one logical sequencer (with failover once HA exists)
     and signed checkpoints, so verification walks from the last checkpoint, not the whole
     chain;
   - nonce and replay stores are shared, and a single-use check is a compare-and-set in the
     shared store;
   - hardware-key signature counters (signCount) live in the shared approvals store and
     advance by compare-and-set;
   - worker claims and locks are server-side leases with heartbeats, never worker-local. A
     holder can pause past its lease, so every write under a lease carries a fencing token the
     store checks, and the work it guards is idempotent (a duplicate poll or claim has no
     second effect);
   - the identity provider and secret store are configured as endpoint lists, not one URL;
   - audit events are buffered on local disk when the sink is unavailable, so a sink outage
     never drops evidence;
   - log index labels stay low-cardinality; session, handle, request and path ids are event
     fields.
4. **Acceptance criteria once HA is built:** failover tests that kill a replica, then a node,
   and prove the service keeps working with no lost audit event, no double-consumed nonce and
   no chain fork.

## Scalability check of ADRs 0001-0015

| ADR | State it creates | N instances / failure |
|---|---|---|
| 0001 records | none | n/a |
| 0002 GHCR, keyless signing | registry, transparency log (external) | no in-house state |
| 0003 Argo CD | desired state in Git | Argo CD can run HA; Git is the source of truth |
| 0004 ARC runners | ephemeral runners | scale horizontally; no shared state |
| 0005 TFE and Sentinel | Terraform state in TFE | TFE's own HA; runs are serialised per workspace |
| 0006 Vault | secrets, transit keys, PKI | Vault HA cluster; clients take an endpoint list (rule 3) |
| 0007 AAP / EDA | job history in AAP | AAP clustering; responders are idempotent |
| 0008 Fulcio chain pin | policy in Git | none |
| 0009 WIF broker, spend caps | per-pod access-token cache; proxy, team and member spend in the gateway DB | each replica federates on its own; the budget DB is shared state that replicas must agree on to enforce a global cap, so it needs HA later |
| 0010 auth sidecar | per-pod key cache; keys and teams in the gateway DB | each replica mints its own keys; the DB is the shared store and needs HA later |
| 0011 scope | n/a | n/a |
| 0012 approvals | statements, nonces, signCounts, approval log | shared store, compare-and-set, one sequencer with checkpoints (rule 3) |
| 0013 per-action credentials | leases in Vault | Vault HA; revocation is idempotent |
| 0014 connectors | poll cursors and ETags | leases (rule 3); a paused poller can outlive its lease, so cursor updates are fenced and event handling is idempotent |
| 0015 brokered credentials | handles, broker nonces, directory sync bundles | shared nonce store, stateless brokers, signed bundles that hosts can fetch from any replica |

## Scalability

This ADR is the scalability rule. Its own state is limited to the checks above.

## Consequences

- Reviews of new ADRs and PRs fail when there's no Scalability section, or when state is held
  in process memory without a stated reason.
- The gateway database (ADR 0010) and the approvals store (ADR 0012) are the first HA work
  items once Phase 2 ships.
