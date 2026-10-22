---
name: handoff
description: End-of-session routine for AegisX9 workspaces. Writes today's handoff note (what changed, open items, first thing tomorrow) with the managed `handoff` CLI and publishes it to team memory. Use when the user says "/handoff", "wrap up", "end of day", or before the session ends.
---

# Handoff: end-of-session routine

Every session ends with a note the next person (or tomorrow's you) can pick up from.
The note lives on the home volume (`~/.aegisx9/handoff/YYYY-MM-DD.md`) and is written
only through `/opt/aegisx9/bin/handoff`, which scans every bullet with the workspace's
secret detectors before saving it. The SessionEnd hook creates a stub if you skip this.

## Steps

1. **Collect** from this session: what changed (commits, files, decisions, issue
   numbers), what is still open (failing checks, questions for the owner, blocked
   items), and the first concrete action for tomorrow.
2. **Write** each bullet. Keep them factual and short; reference issues (`refs #48`).
   ```bash
   handoff add changed "Workspace image builds; CI self-test green (refs #48)"
   handoff add open "Coder template still needs the sandbox userns setting"
   handoff add tomorrow "Run gateway-token end to end against staging Vault"
   ```
   Several bullets at once: `printf '%s\n' "a" "b" | handoff add open --stdin`.
3. **Review**: `handoff show`. Nothing in the note may be a secret, a token, an internal
   hostname or a personal remark; the CLI refuses credential-shaped text, but the rest
   is on you.
4. **Publish** to team memory when the volume is mounted: `handoff publish` (copies
   the note to `$AEGISX9_TEAM_MEMORY_DIR/<user>/`). Skip silently if it reports
   `FileNotFoundError`: the volume is optional.
5. Tell the user in one line where the note is and the first thing tomorrow.

## Rules

- Never paste command output that could carry a secret into a bullet.
- Do not edit the note file by hand; the CLI keeps the format the hook understands.
- If `handoff` exits non-zero it prints only an error type; fix the input and retry.
