# Break-glass local workspace

The normal developer workspace is a pod on the platform cluster (see
`infra/workspaces/`). **Break-glass** runs the *same signed image* on a managed laptop
when the central platform cannot serve it, with the same guardrails, for a declared
window, with an audit trail. When the window ends the work is synced back and the local
copy is wiped.

This is not a convenience mode. It exists so that an outage of the platform never turns
into developers running unmanaged tooling with real credentials.

## When break-glass may be used

All of the following must be true:

1. A platform incident is open (status page or incident channel) that stops the central
   workspace from starting or from reaching the gateway.
2. The laptop is **managed**: full-disk encryption on, screen lock on, EDR/MDM enrolled,
   Docker Desktop or Podman installed by the device-management profile. Personal devices
   are never allowed; the transcripts the agent writes are company data.
3. The developer can sign in to Vault with OIDC (identity provider + MFA).
4. The developer runs `breakglass-login` **before** starting work and `handoff-sync`
   **before** the declared window ends.

Break-glass is **not** for working offline, for bypassing a budget or a guard, or for
anything the central workspace refuses. The gateway still mediates every model call;
there is no provider key on the laptop in any mode.

## What works in which outage

| Scenario | Central workspace | Model calls (gateway) | Vault | Break-glass gives you |
|----------|-------------------|-----------------------|-------|-----------------------|
| **Cluster down** (control plane, nodes or storage) | no | no, if the gateway runs on the same cluster | depends | the image and your home volume locally; model calls only once the gateway is back or fails over; `breakglass-login` spools its activation event until the event stream is reachable |
| **Gateway down** (cluster up) | yes, but the agent cannot call models | no | yes | nothing extra: stay in the central workspace; a local copy has the same gateway dependency. Do not point `ANTHROPIC_BASE_URL` anywhere else |
| **Vault down** | yes (running pods keep their leases) | yes while the gateway's leases last | no | nothing: `breakglass-login` needs Vault to issue the window token. Wait for Vault, or work without agent tooling in the central workspace |
| **Coder control plane down** (cluster and gateway up) | cannot start or connect | yes | yes | the full local workspace with model calls through the gateway: this is the main case |
| **Laptop cannot reach the office network** | no | only if the gateway is reachable through the VPN | via VPN | nothing: fix connectivity first; break-glass never bypasses the egress allowlist |

The container's `HTTPS_PROXY` points at the egress allowlist proxy
(`AEGISX9_EGRESS_PROXY`), so the laptop container can reach only what the central
workspace can reach.

## Setup (once per laptop, by the developer)

```bash
# Values come from the platform team's break-glass page; none of them is a secret except
# the HMAC key file, which must be 0600 and is read by the tools, never pasted.
export AEGISX9_WORKSPACE_IMAGE='ghcr.io/mchasse73/aegisx9/workspace@sha256:<digest>'
export AEGISX9_EGRESS_PROXY='http://<egress proxy>:3128'
export AEGISX9_NO_PROXY='<internal suffixes that bypass the proxy>'
export AEGISX9_GATEWAY_URL='https://<gateway host>'
export AEGISX9_OTEL_ENDPOINT='https://<otel collector>'
export AEGISX9_VAULT_ADDR='https://<vault host>'
export AEGISX9_EVENT_URL='https://<eda event stream url>'
export AEGISX9_EVENT_HMAC_FILE="$HOME/.aegisx9/breakglass-event.hmac"   # 0600
export AEGISX9_SYNC_TARGET='coder:<your workspace name>'

cosign verify --certificate-identity-regexp '^https://github.com/mchasse73/aegisx9/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$AEGISX9_WORKSPACE_IMAGE"       # same check Kyverno makes in the cluster
devcontainer up --workspace-folder workspace/breakglass   # or "Reopen in Container"
```

`devcontainer.json` runs the image with `--cap-drop=ALL`, `--security-opt=no-new-privileges`,
a read-only root filesystem with a tmpfs `/tmp`, a user-defined Docker network
(`aegisx9-breakglass`, created on first start), user `dev`, and a named volume
`aegisx9-breakglass-home` at `/home/dev`. The repository folder is mounted read-only at
`/workspaces/breakglass` only to put `bin/` on the `PATH`.

## During the window

```bash
breakglass-login --hours 8      # OIDC login (browser), records the activation
# ... work; every model call goes through ANTHROPIC_BASE_URL (the gateway)
handoff-sync --dry-run          # see what would be synced
handoff-sync                    # sync, verify, wipe local sessions, revoke the token
```

`breakglass-login` signs in to Vault with role `aegisx9-breakglass` (token TTL equals
the maximum window), records **who** (Vault entity name), **when** and the **declared
window**, and delivers the record HMAC-signed to the Event-Driven Ansible event stream.
EDA opens a ledger entry and starts the "Break-glass window" job, which revokes the token
when the window ends whether or not the developer remembered. If the event stream is
unreachable the record is spooled and delivered by `handoff-sync`.

`handoff-sync` bundles `~/.claude/projects`, `~/.aegisx9/handoff` and `~/.aegisx9/memory`,
scans the bundle with gitleaks (any finding stops the upload; only file names and counts
are shown), uploads with rsync over `coder ssh` (session `.jsonl` files are never
overwritten centrally: append-only union; notes and memory use newer-wins), verifies a
size/sha256 manifest before and after, shreds the bundle and the local session files,
revokes the Vault token and records a `breakglass_sync` event. `--keep-local` skips the
shredding; `--dry-run` stops before any upload. It needs `coder config-ssh` to have been
run once (the `coder.<workspace>` SSH alias) or `--to ssh:<host>`.

| `handoff-sync` exit | Meaning |
|---|---|
| 0 | synced, verified, wiped (unless `--keep-local`), token revoked, event recorded |
| 1 | unexpected failure (only the exception type is printed) |
| 2 | usage or configuration error, or a tool (gitleaks, rsync, ssh) is missing |
| 3 | gitleaks findings: nothing uploaded, nothing wiped, token kept |
| 4 | manifest verification failed: local copies and token kept |
| 5 | sync succeeded but the `breakglass_sync` event could not be recorded |

## Data handling

- **Transcripts are local until synced.** Everything the agent writes during the window
  lives in the `aegisx9-breakglass-home` volume on the laptop: that is why the laptop must
  be managed and encrypted, and why the window is short.
- After a successful `handoff-sync`, remove the volume: `docker volume rm aegisx9-breakglass-home`.
  The sync shreds the session files, but the volume may still hold caches and clones.
- The HMAC key file authenticates events to the audit stream; it is not a credential for
  anything else. The Vault token lives in the vault CLI's own 0600 token file inside the
  volume and is revoked by `handoff-sync` or by the EDA expiry job.
- Never set `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` in a break-glass container. The
  gateway authenticates the developer's identity; a provider key on a laptop is an
  incident.
